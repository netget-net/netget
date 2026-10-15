//! BLE File Transfer Service
pub mod actions;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct BluetoothBleFileTransfer;
impl BluetoothBleFileTransfer {
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
            {
                // The user's instruction leads and the profile sentence is appended to it; an empty
                // instruction gets the sentence alone. This was `format!("{}. Configure as ...",
                // inst)`, which put a stray leading period in front of the sentence when the
                // instruction was empty and a doubled one after it when the instruction already
                // ended in a full stop — in the prompt the model actually reads.
                let inst = inst.trim().trim_end_matches('.').trim();
                if inst.is_empty() {
                    "Configure as a BLE file transfer service.".to_string()
                } else {
                    format!("{inst}. Configure as a BLE file transfer service.")
                }
            },
        )
        .await
    }
}
#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleFileTransfer {
    pub async fn spawn_with_llm_actions(
        _: String,
        _: crate::llm::ollama_client::OllamaClient,
        _: Arc<crate::state::app_state::AppState>,
        _: mpsc::UnboundedSender<String>,
        _: crate::state::ServerId,
        _: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!("BLE file_transfer not enabled")
    }
}
