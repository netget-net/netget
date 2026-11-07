//! Bluetooth Low Energy (BLE) client implementation
pub mod actions;

pub use actions::BluetoothClientProtocol;

use anyhow::{Context, Result};
use btleplug::api::{Central, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::future::BoxFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::client::bluetooth::actions::{
    BLUETOOTH_CONNECTED_EVENT, BLUETOOTH_DATA_READ_EVENT, BLUETOOTH_NOTIFICATION_RECEIVED_EVENT,
    BLUETOOTH_SCAN_COMPLETE_EVENT, BLUETOOTH_SERVICES_DISCOVERED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-client data for LLM handling
struct ClientData {
    #[allow(dead_code)]
    state: ConnectionState,
    memory: String,
    peripheral: Option<Peripheral>,
    #[allow(dead_code)]
    manager: Manager,
    adapter: Adapter,
}

/// What applying one action to the BLE adapter/peripheral actually did.
///
/// `Sent` is reported only for a completed GATT write — those bytes really went
/// out on the radio. Every other verb reads, scans or subscribes, so it reports
/// `Executed` with what it found.
pub enum BluetoothApplied {
    /// This many bytes were written to a characteristic.
    Sent(usize),
    /// The action ran but wrote nothing; the string says what it did.
    Executed(String),
    /// The peripheral was disconnected.
    Disconnected,
}

/// Bluetooth Low Energy client that connects to BLE devices
pub struct BluetoothClient;

impl BluetoothClient {
    /// Connect to a BLE device with integrated LLM actions
    ///
    /// Note: For BLE, the "remote_addr" parameter is actually the device name or address to connect to.
    /// If empty or "scan", the client will scan for devices and wait for LLM to select one.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("Bluetooth client {} initializing", client_id);

        // Initialize BLE manager and adapter
        let manager = Manager::new()
            .await
            .context("Failed to create BLE manager")?;

        let adapters = manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .context("No Bluetooth adapters found")?;

        info!(
            "Bluetooth client {} using adapter: {:?}",
            client_id,
            adapter.adapter_info().await?
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Bluetooth client {} initialized",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            memory: String::new(),
            peripheral: None,
            manager: manager.clone(),
            adapter: adapter.clone(),
        }));

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the scan/connect task below, whose very first step is an
        // LLM call that a `*` -> manual rule can park for minutes: the operator must
        // be able to drive the adapter while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn({
            let client_data = client_data.clone();
            let app_state = app_state.clone();
            let status_tx = status_tx.clone();
            let llm_client = llm_client.clone();
            async move {
                Self::command_loop(
                    command_rx,
                    client_data,
                    app_state,
                    status_tx,
                    llm_client,
                    client_id,
                )
                .await;
            }
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn LLM integration task
        let client_data_clone = client_data.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let llm_client_clone = llm_client.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            // Initial scan if requested
            if remote_addr.is_empty() || remote_addr == "scan" {
                if let Err(e) = Self::perform_scan(
                    &client_data_clone,
                    &app_state_clone,
                    &status_tx_clone,
                    &llm_client_clone,
                    client_id,
                    5,
                )
                .await
                {
                    error!("Bluetooth scan error: {}", e);
                }
            } else {
                // Try to connect to specified device
                if let Err(e) = Self::connect_to_device(
                    &client_data_clone,
                    &app_state_clone,
                    &status_tx_clone,
                    &llm_client_clone,
                    client_id,
                    Some(remote_addr.clone()),
                    None,
                )
                .await
                {
                    error!("Bluetooth connection error: {}", e);
                    app_state_clone
                        .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                        .await;
                    let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                }
            }

            // Main event loop - wait for LLM actions
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Check if client is still active
                if let Some(client) = app_state_clone.get_client(client_id).await {
                    if matches!(
                        client.status,
                        ClientStatus::Disconnected | ClientStatus::Error(_)
                    ) {
                        break;
                    }
                } else {
                    break;
                }
            }

            info!("Bluetooth client {} event loop ended", client_id);
            // The scan/connect task is what tracks liveness; when it gives up, the
            // command handle must go with it so the dashboard stops offering [ send ].
            app_state_clone.remove_client_handle(client_id).await;
            let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return a dummy socket address (BLE doesn't use IP sockets)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (the client was removed,
    /// which drops the handle) or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this
    /// client: it owns no socket, and every BLE verb yields a
    /// `ClientActionResult::Custom` that only btleplug can carry out. So the action
    /// goes through [`Self::execute_llm_action`] — the exact function the LLM path
    /// uses, including its follow-up events — and the outcome is recorded and replied
    /// the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client_data: Arc<Mutex<ClientData>>,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
        client_id: ClientId,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = BluetoothClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            // `execute_llm_action` returns Err both for a rejected action (unknown
            // verb / bad params) and for a BLE failure. They are not distinguishable
            // from here without duplicating `execute_action`, so run the decode first
            // and let only its error be a rejection.
            let decoded = {
                use crate::llm::actions::client_trait::Client;
                protocol.execute_action(action.clone())
            };
            let outcome = match decoded {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(_) => Self::execute_llm_action(
                    action.clone(),
                    &client_data,
                    &app_state,
                    &status_tx,
                    &llm_client,
                    client_id,
                )
                .await
                .map(|applied| match applied {
                    BluetoothApplied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                    BluetoothApplied::Executed(detail) => ClientSendOutcome::Executed { detail },
                    BluetoothApplied::Disconnected => ClientSendOutcome::Disconnected,
                }),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "Bluetooth client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Perform a BLE scan for nearby devices
    async fn perform_scan(
        client_data: &Arc<Mutex<ClientData>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        llm_client: &OllamaClient,
        client_id: ClientId,
        duration_secs: u64,
    ) -> Result<usize> {
        let adapter = {
            let data = client_data.lock().await;
            data.adapter.clone()
        };

        info!(
            "Bluetooth client {} starting scan for {} seconds",
            client_id, duration_secs
        );
        let _ = status_tx.send(format!("[CLIENT] Scanning for BLE devices..."));

        adapter.start_scan(ScanFilter::default()).await?;
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
        adapter.stop_scan().await?;

        // Get discovered devices
        let peripherals = adapter.peripherals().await?;

        let mut devices = Vec::new();
        for peripheral in peripherals {
            if let Ok(Some(props)) = peripheral.properties().await {
                let device_info = serde_json::json!({
                    "address": props.address.to_string(),
                    "name": props.local_name.unwrap_or_else(|| "Unknown".to_string()),
                    "rssi": props.rssi,
                });
                devices.push(device_info);
            }
        }

        info!(
            "Bluetooth client {} found {} devices",
            client_id,
            devices.len()
        );
        let _ = status_tx.send(format!("[CLIENT] Found {} BLE devices", devices.len()));
        let device_count = devices.len();

        // Call LLM with scan results
        let protocol = Arc::new(BluetoothClientProtocol::new());
        let event = Event::new(
            &BLUETOOTH_SCAN_COMPLETE_EVENT,
            serde_json::json!({
                "devices": devices,
            }),
        );

        // Copy the memory out before the call: the command loop shares this
        // mutex, and a guard held across an LLM round-trip (which a `*` manual
        // rule can park for minutes) would stall every injected command.
        let memory_snapshot = client_data.lock().await.memory.clone();
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            match call_llm_for_client(
                llm_client,
                app_state,
                client_id.to_string(),
                &instruction,
                &memory_snapshot,
                Some(&event),
                protocol.as_ref(),
                status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        client_data.lock().await.memory = mem;
                    }

                    // Execute actions
                    for action in actions {
                        if let Err(e) = Self::execute_llm_action(
                            action,
                            client_data,
                            app_state,
                            status_tx,
                            llm_client,
                            client_id,
                        )
                        .await
                        {
                            error!("Error executing Bluetooth action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for Bluetooth client {}: {}", client_id, e);
                }
            }
        }

        Ok(device_count)
    }

    /// Connect to a specific BLE device
    fn connect_to_device<'a>(
        client_data: &'a Arc<Mutex<ClientData>>,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        llm_client: &'a OllamaClient,
        client_id: ClientId,
        device_address: Option<String>,
        device_name: Option<String>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let adapter = {
                let data = client_data.lock().await;
                data.adapter.clone()
            };

            // Scan for devices if we need to find by name
            if device_name.is_some() {
                info!("Bluetooth client {} scanning for device by name", client_id);
                adapter.start_scan(ScanFilter::default()).await?;
                tokio::time::sleep(Duration::from_secs(5)).await;
                adapter.stop_scan().await?;
            }

            let peripherals = adapter.peripherals().await?;

            // Find the target device
            let mut target_peripheral: Option<Peripheral> = None;
            for peripheral in peripherals {
                if let Ok(Some(props)) = peripheral.properties().await {
                    let matches = if let Some(ref addr) = device_address {
                        props.address.to_string().eq_ignore_ascii_case(addr)
                    } else if let Some(ref name) = device_name {
                        props
                            .local_name
                            .as_ref()
                            .map_or(false, |n| n.contains(name))
                    } else {
                        false
                    };

                    if matches {
                        target_peripheral = Some(peripheral);
                        break;
                    }
                }
            }

            let peripheral = target_peripheral.context("Device not found")?;

            // Connect to the device
            info!("Bluetooth client {} connecting to device", client_id);
            let _ = status_tx.send(format!("[CLIENT] Connecting to BLE device..."));

            peripheral.connect().await?;
            peripheral.discover_services().await?;

            let device_props = peripheral
                .properties()
                .await?
                .context("No device properties")?;
            let device_addr = device_props.address.to_string();
            let device_name_str = device_props
                .local_name
                .unwrap_or_else(|| "Unknown".to_string());

            info!(
                "Bluetooth client {} connected to {} ({})",
                client_id, device_name_str, device_addr
            );
            let _ = status_tx.send(format!("[CLIENT] Connected to {}", device_name_str));

            // Store peripheral
            {
                let mut data = client_data.lock().await;
                data.peripheral = Some(peripheral.clone());
            }

            // Set up notification handler using stream-based API
            let client_data_clone = client_data.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();
            let llm_client_clone = llm_client.clone();
            let peripheral_clone = peripheral.clone();

            // Spawn task to handle notification stream
            // Tracked, not detached: stop_client must abort this task too.
            let task_owner = app_state.clone();
            task_owner
                .spawn_client_task(client_id, async move {
                    match peripheral_clone.notifications().await {
                        Ok(mut notification_stream) => {
                            use futures::StreamExt;
                            while let Some(notification) = notification_stream.next().await {
                                let client_data = client_data_clone.clone();
                                let app_state = app_state_clone.clone();
                                let status_tx = status_tx_clone.clone();
                                let llm_client = llm_client_clone.clone();

                                trace!(
                                    "Bluetooth notification received from {:?}",
                                    notification.uuid
                                );

                                // Call LLM with notification
                                let protocol = Arc::new(BluetoothClientProtocol::new());
                                let event = Event::new(
                                    &BLUETOOTH_NOTIFICATION_RECEIVED_EVENT,
                                    serde_json::json!({
                                        "service_uuid": "unknown", // btleplug doesn't provide service UUID in notification
                                        "characteristic_uuid": notification.uuid.to_string(),
                                        "value_hex": hex::encode(&notification.value),
                                    }),
                                );

                                // Copy the memory out before the call: the command loop shares this
                                // mutex, and a guard held across an LLM round-trip (which a `*` manual
                                // rule can park for minutes) would stall every injected command.
                                let memory_snapshot = client_data.lock().await.memory.clone();
                                if let Some(instruction) =
                                    app_state.get_instruction_for_client(client_id).await
                                {
                                    match call_llm_for_client(
                                        &llm_client,
                                        &app_state,
                                        client_id.to_string(),
                                        &instruction,
                                        &memory_snapshot,
                                        Some(&event),
                                        protocol.as_ref(),
                                        &status_tx,
                                    )
                                    .await
                                    {
                                        Ok(ClientLlmResult {
                                            actions,
                                            memory_updates,
                                        }) => {
                                            // Update memory
                                            if let Some(mem) = memory_updates {
                                                client_data.lock().await.memory = mem;
                                            }

                                            // Execute actions
                                            for action in actions {
                                                if let Err(e) = Self::execute_llm_action(
                                                    action,
                                                    &client_data,
                                                    &app_state,
                                                    &status_tx,
                                                    &llm_client,
                                                    client_id,
                                                )
                                                .await
                                                {
                                                    error!(
                                                        "Error executing Bluetooth action: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("LLM error for Bluetooth notification: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get notification stream: {}", e);
                        }
                    }
                })
                .await;

            // Call LLM with connected event
            let protocol = Arc::new(BluetoothClientProtocol::new());
            let event = Event::new(
                &BLUETOOTH_CONNECTED_EVENT,
                serde_json::json!({
                    "device_address": device_addr,
                    "device_name": device_name_str,
                }),
            );

            // Copy the memory out before the call: the command loop shares this
            // mutex, and a guard held across an LLM round-trip (which a `*` manual
            // rule can park for minutes) would stall every injected command.
            let memory_snapshot = client_data.lock().await.memory.clone();
            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                match call_llm_for_client(
                    llm_client,
                    app_state,
                    client_id.to_string(),
                    &instruction,
                    &memory_snapshot,
                    Some(&event),
                    protocol.as_ref(),
                    status_tx,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates,
                    }) => {
                        // Update memory
                        if let Some(mem) = memory_updates {
                            client_data.lock().await.memory = mem;
                        }

                        // Execute actions
                        for action in actions {
                            if let Err(e) = Self::execute_llm_action(
                                action,
                                client_data,
                                app_state,
                                status_tx,
                                llm_client,
                                client_id,
                            )
                            .await
                            {
                                error!("Error executing Bluetooth action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for Bluetooth client {}: {}", client_id, e);
                    }
                }
            }

            Ok(())
        })
    }

    /// Execute an action returned by the LLM
    fn execute_llm_action<'a>(
        action: serde_json::Value,
        client_data: &'a Arc<Mutex<ClientData>>,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        llm_client: &'a OllamaClient,
        client_id: ClientId,
    ) -> BoxFuture<'a, Result<BluetoothApplied>> {
        Box::pin(async move {
            use crate::llm::actions::client_trait::Client;
            let protocol = BluetoothClientProtocol::new();

            match protocol.execute_action(action)? {
                crate::llm::actions::client_trait::ClientActionResult::Custom { name, data } => {
                    match name.as_str() {
                        "scan_devices" => {
                            let duration_secs = data["duration_secs"].as_u64().unwrap_or(5);
                            let found = Box::pin(Self::perform_scan(
                                client_data,
                                app_state,
                                status_tx,
                                llm_client,
                                client_id,
                                duration_secs,
                            ))
                            .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "scan_devices ({duration_secs}s): {found} devices found"
                            )))
                        }
                        "connect_device" => {
                            let device_address =
                                data["device_address"].as_str().map(|s| s.to_string());
                            let device_name = data["device_name"].as_str().map(|s| s.to_string());
                            let target = device_address
                                .clone()
                                .or_else(|| device_name.clone())
                                .unwrap_or_else(|| "<unspecified>".to_string());
                            Self::connect_to_device(
                                client_data,
                                app_state,
                                status_tx,
                                llm_client,
                                client_id,
                                device_address,
                                device_name,
                            )
                            .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "connect_device {target}: connected"
                            )))
                        }
                        "discover_services" => {
                            let count = Self::discover_services(
                                client_data,
                                app_state,
                                status_tx,
                                llm_client,
                                client_id,
                            )
                            .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "discover_services: {count} services"
                            )))
                        }
                        "read_characteristic" => {
                            let service_uuid = Uuid::parse_str(
                                data["service_uuid"]
                                    .as_str()
                                    .context("Missing service_uuid")?,
                            )?;
                            let char_uuid = Uuid::parse_str(
                                data["characteristic_uuid"]
                                    .as_str()
                                    .context("Missing characteristic_uuid")?,
                            )?;
                            let read = Self::read_characteristic(
                                client_data,
                                app_state,
                                status_tx,
                                llm_client,
                                client_id,
                                service_uuid,
                                char_uuid,
                            )
                            .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "read_characteristic {char_uuid}: {read} bytes read"
                            )))
                        }
                        "write_characteristic" => {
                            let service_uuid = Uuid::parse_str(
                                data["service_uuid"]
                                    .as_str()
                                    .context("Missing service_uuid")?,
                            )?;
                            let char_uuid = Uuid::parse_str(
                                data["characteristic_uuid"]
                                    .as_str()
                                    .context("Missing characteristic_uuid")?,
                            )?;
                            let value_bytes = crate::client::wire_values::bytes(
                                data["value_bytes"]
                                    .as_array()
                                    .context("Missing value_bytes")?,
                            )?;
                            let with_response = data["with_response"].as_bool().unwrap_or(true);
                            let written = value_bytes.len();
                            Self::write_characteristic(
                                client_data,
                                service_uuid,
                                char_uuid,
                                value_bytes,
                                with_response,
                            )
                            .await?;
                            // A completed GATT write really put these bytes on the
                            // radio, so this is the one BLE verb that can report Sent.
                            Ok(BluetoothApplied::Sent(written))
                        }
                        "subscribe_notifications" => {
                            let service_uuid = Uuid::parse_str(
                                data["service_uuid"]
                                    .as_str()
                                    .context("Missing service_uuid")?,
                            )?;
                            let char_uuid = Uuid::parse_str(
                                data["characteristic_uuid"]
                                    .as_str()
                                    .context("Missing characteristic_uuid")?,
                            )?;
                            Self::subscribe_notifications(client_data, service_uuid, char_uuid)
                                .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "subscribe_notifications {char_uuid}: subscribed"
                            )))
                        }
                        "unsubscribe_notifications" => {
                            let service_uuid = Uuid::parse_str(
                                data["service_uuid"]
                                    .as_str()
                                    .context("Missing service_uuid")?,
                            )?;
                            let char_uuid = Uuid::parse_str(
                                data["characteristic_uuid"]
                                    .as_str()
                                    .context("Missing characteristic_uuid")?,
                            )?;
                            Self::unsubscribe_notifications(client_data, service_uuid, char_uuid)
                                .await?;
                            Ok(BluetoothApplied::Executed(format!(
                                "unsubscribe_notifications {char_uuid}: unsubscribed"
                            )))
                        }
                        _ => {
                            warn!("Unknown custom action: {}", name);
                            Ok(BluetoothApplied::Executed(format!(
                                "custom result '{name}' has no Bluetooth handler"
                            )))
                        }
                    }
                }
                crate::llm::actions::client_trait::ClientActionResult::Disconnect => {
                    Self::disconnect(client_data, app_state, client_id).await?;
                    // Drop the command handle here rather than only in the command
                    // loop: the LLM can disconnect too, and a handle left behind
                    // would offer [ send ] into a closed peripheral.
                    app_state.remove_client_handle(client_id).await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    Ok(BluetoothApplied::Disconnected)
                }
                other => {
                    debug!("Unhandled action result type");
                    Ok(BluetoothApplied::Executed(format!(
                        "unhandled action result {other:?}"
                    )))
                }
            }
        })
    }

    /// Discover GATT services and characteristics
    async fn discover_services(
        client_data: &Arc<Mutex<ClientData>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        llm_client: &OllamaClient,
        client_id: ClientId,
    ) -> Result<usize> {
        let peripheral = {
            let data = client_data.lock().await;
            data.peripheral.clone().context("Not connected to device")?
        };

        info!("Bluetooth client {} discovering services", client_id);

        let services = peripheral.services();
        let mut services_data = Vec::new();

        for service in services {
            let mut characteristics_data = Vec::new();

            for char in service.characteristics {
                let mut properties = Vec::new();
                if char.properties.contains(CharPropFlags::READ) {
                    properties.push("read".to_string());
                }
                if char.properties.contains(CharPropFlags::WRITE) {
                    properties.push("write".to_string());
                }
                if char
                    .properties
                    .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
                {
                    properties.push("write_without_response".to_string());
                }
                if char.properties.contains(CharPropFlags::NOTIFY) {
                    properties.push("notify".to_string());
                }
                if char.properties.contains(CharPropFlags::INDICATE) {
                    properties.push("indicate".to_string());
                }

                characteristics_data.push(serde_json::json!({
                    "uuid": char.uuid.to_string(),
                    "properties": properties,
                }));
            }

            services_data.push(serde_json::json!({
                "uuid": service.uuid.to_string(),
                "primary": service.primary,
                "characteristics": characteristics_data,
            }));
        }

        info!(
            "Bluetooth client {} discovered {} services",
            client_id,
            services_data.len()
        );
        let service_count = services_data.len();

        // Call LLM with services discovered event
        let protocol = Arc::new(BluetoothClientProtocol::new());
        let event = Event::new(
            &BLUETOOTH_SERVICES_DISCOVERED_EVENT,
            serde_json::json!({
                "services": services_data,
            }),
        );

        // Copy the memory out before the call: the command loop shares this
        // mutex, and a guard held across an LLM round-trip (which a `*` manual
        // rule can park for minutes) would stall every injected command.
        let memory_snapshot = client_data.lock().await.memory.clone();
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            match call_llm_for_client(
                llm_client,
                app_state,
                client_id.to_string(),
                &instruction,
                &memory_snapshot,
                Some(&event),
                protocol.as_ref(),
                status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        client_data.lock().await.memory = mem;
                    }

                    // Execute actions
                    for action in actions {
                        if let Err(e) = Self::execute_llm_action(
                            action,
                            client_data,
                            app_state,
                            status_tx,
                            llm_client,
                            client_id,
                        )
                        .await
                        {
                            error!("Error executing Bluetooth action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for Bluetooth client {}: {}", client_id, e);
                }
            }
        }

        Ok(service_count)
    }

    /// Read a characteristic value
    async fn read_characteristic(
        client_data: &Arc<Mutex<ClientData>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        llm_client: &OllamaClient,
        client_id: ClientId,
        service_uuid: Uuid,
        char_uuid: Uuid,
    ) -> Result<usize> {
        let peripheral = {
            let data = client_data.lock().await;
            data.peripheral.clone().context("Not connected to device")?
        };

        debug!(
            "Reading characteristic {} from service {}",
            char_uuid, service_uuid
        );

        // Find the characteristic
        let services = peripheral.services();
        let characteristic = services
            .iter()
            .find(|s| s.uuid == service_uuid)
            .and_then(|s| s.characteristics.iter().find(|c| c.uuid == char_uuid))
            .context("Characteristic not found")?;

        let value = peripheral.read(characteristic).await?;

        info!(
            "Read {} bytes from characteristic {}",
            value.len(),
            char_uuid
        );

        // Call LLM with read data
        let protocol = Arc::new(BluetoothClientProtocol::new());
        let event = Event::new(
            &BLUETOOTH_DATA_READ_EVENT,
            serde_json::json!({
                "service_uuid": service_uuid.to_string(),
                "characteristic_uuid": char_uuid.to_string(),
                "value_hex": hex::encode(&value),
            }),
        );

        // Copy the memory out before the call: the command loop shares this
        // mutex, and a guard held across an LLM round-trip (which a `*` manual
        // rule can park for minutes) would stall every injected command.
        let memory_snapshot = client_data.lock().await.memory.clone();
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            match call_llm_for_client(
                llm_client,
                app_state,
                client_id.to_string(),
                &instruction,
                &memory_snapshot,
                Some(&event),
                protocol.as_ref(),
                status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        client_data.lock().await.memory = mem;
                    }

                    // Execute actions
                    for action in actions {
                        if let Err(e) = Self::execute_llm_action(
                            action,
                            client_data,
                            app_state,
                            status_tx,
                            llm_client,
                            client_id,
                        )
                        .await
                        {
                            error!("Error executing Bluetooth action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for Bluetooth client {}: {}", client_id, e);
                }
            }
        }

        Ok(value.len())
    }

    /// Write a characteristic value
    async fn write_characteristic(
        client_data: &Arc<Mutex<ClientData>>,
        service_uuid: Uuid,
        char_uuid: Uuid,
        value: Vec<u8>,
        with_response: bool,
    ) -> Result<()> {
        let peripheral = {
            let data = client_data.lock().await;
            data.peripheral.clone().context("Not connected to device")?
        };

        debug!(
            "Writing {} bytes to characteristic {} from service {}",
            value.len(),
            char_uuid,
            service_uuid
        );

        // Find the characteristic
        let services = peripheral.services();
        let characteristic = services
            .iter()
            .find(|s| s.uuid == service_uuid)
            .and_then(|s| s.characteristics.iter().find(|c| c.uuid == char_uuid))
            .context("Characteristic not found")?;

        let write_type = if with_response {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };

        peripheral.write(characteristic, &value, write_type).await?;

        info!(
            "Wrote {} bytes to characteristic {}",
            value.len(),
            char_uuid
        );

        Ok(())
    }

    /// Subscribe to notifications from a characteristic
    async fn subscribe_notifications(
        client_data: &Arc<Mutex<ClientData>>,
        service_uuid: Uuid,
        char_uuid: Uuid,
    ) -> Result<()> {
        let peripheral = {
            let data = client_data.lock().await;
            data.peripheral.clone().context("Not connected to device")?
        };

        debug!(
            "Subscribing to characteristic {} from service {}",
            char_uuid, service_uuid
        );

        // Find the characteristic
        let services = peripheral.services();
        let characteristic = services
            .iter()
            .find(|s| s.uuid == service_uuid)
            .and_then(|s| s.characteristics.iter().find(|c| c.uuid == char_uuid))
            .context("Characteristic not found")?;

        peripheral.subscribe(characteristic).await?;

        info!(
            "Subscribed to notifications from characteristic {}",
            char_uuid
        );

        Ok(())
    }

    /// Unsubscribe from notifications from a characteristic
    async fn unsubscribe_notifications(
        client_data: &Arc<Mutex<ClientData>>,
        service_uuid: Uuid,
        char_uuid: Uuid,
    ) -> Result<()> {
        let peripheral = {
            let data = client_data.lock().await;
            data.peripheral.clone().context("Not connected to device")?
        };

        debug!(
            "Unsubscribing from characteristic {} from service {}",
            char_uuid, service_uuid
        );

        // Find the characteristic
        let services = peripheral.services();
        let characteristic = services
            .iter()
            .find(|s| s.uuid == service_uuid)
            .and_then(|s| s.characteristics.iter().find(|c| c.uuid == char_uuid))
            .context("Characteristic not found")?;

        peripheral.unsubscribe(characteristic).await?;

        info!(
            "Unsubscribed from notifications from characteristic {}",
            char_uuid
        );

        Ok(())
    }

    /// Disconnect from the BLE device
    async fn disconnect(
        client_data: &Arc<Mutex<ClientData>>,
        app_state: &Arc<AppState>,
        client_id: ClientId,
    ) -> Result<()> {
        let peripheral = {
            let mut data = client_data.lock().await;
            data.peripheral.take()
        };

        if let Some(peripheral) = peripheral {
            peripheral.disconnect().await?;
            info!("Bluetooth client {} disconnected", client_id);
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
        }

        Ok(())
    }
}
