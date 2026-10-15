//! BLE Proximity Service
pub mod actions;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct BluetoothBleProximity;
impl BluetoothBleProximity {
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
            format!("{}. Configure as BLE Proximity.", inst),
        )
        .await
    }
}
#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBleProximity {
    pub async fn spawn_with_llm_actions(
        _: String,
        _: crate::llm::ollama_client::OllamaClient,
        _: Arc<crate::state::app_state::AppState>,
        _: mpsc::UnboundedSender<String>,
        _: crate::state::ServerId,
        _: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!("BLE proximity not enabled")
    }
}
