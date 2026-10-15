//! Bluetooth Low Energy (BLE) GATT server implementation
//!
//! Cross-platform peripheral/server mode using ble-peripheral-rust
//! Platforms: Windows (WinRT), macOS (CoreBluetooth), Linux (BlueZ)

pub mod actions;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::{console_error, console_info, console_trace};
use actions::{
    BluetoothBleProtocol, BLUETOOTH_BLE_STARTED_EVENT, BLUETOOTH_READ_REQUEST_EVENT,
    BLUETOOTH_STATE_CHANGED_EVENT, BLUETOOTH_SUBSCRIBE_EVENT, BLUETOOTH_WRITE_REQUEST_EVENT,
};

#[cfg(all(unix, feature = "bluetooth"))]
use ble_peripheral_rust::gatt::characteristic::Characteristic;
#[cfg(all(unix, feature = "bluetooth"))]
use ble_peripheral_rust::gatt::peripheral_event::{
    PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
};
#[cfg(all(unix, feature = "bluetooth"))]
use ble_peripheral_rust::gatt::properties::{AttributePermission, CharacteristicProperty};
#[cfg(all(unix, feature = "bluetooth"))]
use ble_peripheral_rust::gatt::service::Service;
#[cfg(all(unix, feature = "bluetooth"))]
use ble_peripheral_rust::{Peripheral, PeripheralImpl};
#[cfg(all(unix, feature = "bluetooth"))]
use uuid::Uuid;

/// The longest LocalName that fits an AD structure inside a 31-octet legacy advertisement,
/// after its length and type bytes. A name past this is refused by the radio rather than
/// shortened, so NetGet shortens it first.
const MAX_LOCAL_NAME_CHARS: usize = 29;

/// Per-characteristic data for tracking pending requests
#[derive(Debug)]
struct CharacteristicData {
    #[allow(dead_code)]
    uuid: String,
    #[allow(dead_code)]
    properties: Vec<String>,
    #[allow(dead_code)]
    permissions: Vec<String>,
    current_value: Vec<u8>,
}

/// Server data for BLE peripheral
struct ServerData {
    /// The process-wide shared radio, or `None` in the radio-free test loop.
    hub: Option<Arc<BleHub>>,
    /// This server's own slice of the shared event stream, used to register characteristic
    /// routes with the hub as services are added. `None` in the radio-free test loop.
    event_tx: Option<mpsc::Sender<PeripheralEvent>>,
    memory: String,
    characteristics: HashMap<String, CharacteristicData>,
}

/// Parse a BLE UUID, expanding the 16- and 32-bit shorthands.
///
/// Bluetooth assigns short UUIDs (`180D` for Heart Rate, `2A37` for its
/// measurement characteristic) that stand for the full 128-bit value
/// `0000XXXX-0000-1000-8000-00805F9B34FB`. Every example in this protocol's
/// actions and CLAUDE.md uses that shorthand, and the docs stated it was
/// "expanded to" the long form — but nothing expanded it, and
/// `Uuid::parse_str("180D")` fails, so a model copying the protocol's own
/// documented example got `Invalid service UUID`.
///
/// Accepts a 4-hex-digit (16-bit) or 8-hex-digit (32-bit) shorthand, or any
/// form `Uuid::parse_str` already understands.
///
/// `pub` so `tests/` can exercise it directly — CLAUDE.md forbids unit-test
/// modules in `src/`, so an internal helper has to be reachable to be tested.
/// The ATT Write Response a `respond_to_write` action asks for.
///
/// `respond_to_write` has always declared a `status` of `'success'` or `'error'`, and nothing
/// anywhere read it — both consumption sites skip the action as "handled inline" and the
/// inline handler answered `Success` unconditionally. So a model rejecting a write (value out
/// of range, wrong length, characteristic not writable in this state) had its decision
/// discarded and the central was told the write had been accepted. The ATT Write Response is
/// the only signal the central gets.
///
/// Silence still means success: most writes are accepted, and a handler that answers a
/// `bluetooth_write_request` without naming a status has consented to it. Only an explicit
/// `'error'` refuses. An LLM *failure* is handled separately by the caller and stays
/// distinct — that path logs `the handler failed` where this one logs `model_reject`.
///
/// `pub` so `tests/` can exercise it without a Bluetooth adapter.
#[cfg(all(unix, feature = "bluetooth"))]
pub fn write_response_status(raw_actions: &[serde_json::Value]) -> RequestResponse {
    let refused = raw_actions.iter().any(|action| {
        matches!(
            action.get("type").and_then(|v| v.as_str()),
            Some("respond_to_write") | Some("send_write_response")
        ) && action
            .get("status")
            .and_then(|v| v.as_str())
            .is_some_and(|status| status.eq_ignore_ascii_case("error"))
    });

    if refused {
        RequestResponse::UnlikelyError
    } else {
        RequestResponse::Success
    }
}

/// What a successful handler round-trip decided about a `bluetooth_read_request`.
///
/// Kept separate from the event loop so the decision is testable without a Bluetooth adapter,
/// and so the three outcomes cannot silently collapse into one another.
#[cfg(all(unix, feature = "bluetooth"))]
#[derive(Debug, PartialEq, Eq)]
pub enum ReadDecision {
    /// The handler named a value: serve exactly it. `decision=model_value`.
    Value(Vec<u8>),
    /// The handler answered without naming a value. `decision=model_silent` — the stored
    /// characteristic value is served *if there is one*; there is nothing to invent if not.
    UseStored,
    /// The handler produced a `respond_to_read` whose value cannot be used (not hex, or no
    /// `value` field at all). `decision=fail_closed_bad_value` — an answer that cannot be
    /// decoded is not an answer, and must not silently become the stored value.
    Unusable(String),
}

/// Classify the handler's answer to a read request.
///
/// The dangerous case this exists to keep out is an unparseable `respond_to_read` degrading into
/// the stored-value fallback: the model *tried* to say what the characteristic holds, we could
/// not decode it, and the central would otherwise be handed a different value under
/// `RequestResponse::Success` with nothing on the wire to say so.
///
/// `pub` so `tests/` can exercise it without a Bluetooth adapter.
#[cfg(all(unix, feature = "bluetooth"))]
pub fn read_decision(raw_actions: &[serde_json::Value]) -> ReadDecision {
    let Some(action) = raw_actions.iter().find(|a| {
        matches!(
            a.get("type").and_then(|v| v.as_str()),
            Some("respond_to_read") | Some("send_read_response")
        )
    }) else {
        return ReadDecision::UseStored;
    };

    let Some(value) = action.get("value").and_then(|v| v.as_str()) else {
        return ReadDecision::Unusable(
            "respond_to_read carried no 'value' field (hex-encoded bytes)".to_string(),
        );
    };

    match hex::decode(value.trim_start_matches("0x")) {
        Ok(bytes) => ReadDecision::Value(bytes),
        Err(e) => ReadDecision::Unusable(format!(
            "respond_to_read 'value' is not hex-encoded ({e}); \
             expected something like \"0048\" or \"0x0048\""
        )),
    }
}

#[cfg(all(unix, feature = "bluetooth"))]
pub fn parse_ble_uuid(s: &str) -> Result<Uuid> {
    let t = s.trim();
    let is_hex = |v: &str| v.chars().all(|c| c.is_ascii_hexdigit());

    if (t.len() == 4 || t.len() == 8) && is_hex(t) {
        // Left-pad the 16-bit form to 32 bits, then splice into the BLE base UUID.
        let short = format!("{:0>8}", t.to_ascii_lowercase());
        let full = format!("{short}-0000-1000-8000-00805f9b34fb");
        return Uuid::parse_str(&full)
            .with_context(|| format!("Invalid BLE short UUID {t:?} (expanded to {full})"));
    }

    Uuid::parse_str(t).with_context(|| {
        format!(
            "Invalid UUID {t:?}. Use a 16-bit shorthand like \"180D\", a 32-bit one, \
             or a full 128-bit UUID."
        )
    })
}

/// The single key a characteristic is filed and looked up under.
///
/// Always the canonical lowercase-hyphenated 128-bit form, which is exactly what
/// `request.characteristic.to_string()` yields on the radio's read/write/subscribe events. So
/// every spelling of the same characteristic — the `"2A37"` shorthand every documented example
/// in this protocol uses, the 32-bit form, and the full 128-bit UUID — lands on one entry.
///
/// Three different spellings were in play before, and none of the tests noticed because every
/// one of them used the full form:
///
/// * `add_service` filed the stored value under **the model's own spelling**
///   (`characteristics.insert(char_uuid_str, ..)`), while the read and write paths looked it up
///   under **the radio's canonical form**. So a service added with the protocol's own
///   documented `"uuid": "2A37"` was unreachable: a read the handler declined to answer fell
///   through to `decision=fail_closed_model_silent_no_value` and replied ATT Unlikely Error
///   although `initial_value` had supplied one, and a write never updated the stored value.
/// * `send_notification` used the model's spelling again, a third variant that agreed with
///   `add_service` only when both happened to be written the same way.
/// * [`BleRouter::register_characteristic`] lowercased without expanding, so a route registered
///   as `"2a37"` was never found by a lookup for `"00002a37-0000-1000-8000-00805f9b34fb"`. That
///   one failed quietly into the "newest live server" fallback, which is why it survived: with
///   a single BLE server the fallback is the right answer anyway. With two — a base server and
///   any of the fifteen profiles that delegate to this event loop — the second server captured
///   the first server's characteristic traffic.
///
/// An unparseable UUID falls back to the trimmed lowercase input rather than panicking.
/// `add_service` rejects those before they can be filed, so this is only reachable from a
/// lookup for a characteristic that was never added, where a miss is the correct outcome.
#[cfg(all(unix, feature = "bluetooth"))]
pub fn characteristic_key(uuid: &str) -> String {
    match parse_ble_uuid(uuid) {
        Ok(parsed) => parsed.to_string(),
        Err(_) => uuid.trim().to_lowercase(),
    }
}

/// Process-wide shared BLE radio.
///
/// `ble-peripheral-rust`'s CoreBluetooth backend funnels *every* `Peripheral` through a single
/// process-global manager thread guarded by its own `static PERIPHERAL_THREAD: OnceCell<()>`
/// (`peripheral_manager.rs:50`). Only the **first** `Peripheral::new()` in a process actually
/// spawns that thread and wires up its command channel; every later `Peripheral::new()` builds a
/// fresh `manager_tx` whose receiver is dropped on the spot, so all of its commands — including
/// `is_powered()` — fail silently. The second BLE server start therefore saw `is_powered()`
/// return `false` forever and bailed after the 20×500ms wait with a bogus "adapter failed to
/// power on after 10 seconds", while the adapter was fine (IMPROVEMENTS item 2).
///
/// CoreBluetooth is genuinely one-manager-per-process anyway (one GATT database, one advertising
/// state, one radio), so the correct model is a single shared `Peripheral` reused across every
/// BLE server start. That is what `BleHub` is. It is created exactly once, on the first start,
/// via [`BLE_HUB`]; the adapter power-on wait happens once there, so subsequent starts reuse the
/// live radio with no wait and no hang.
///
/// The single shared radio also means a single shared event stream: `Peripheral::new` takes one
/// `PeripheralEvent` sender for the whole process. The hub owns that stream and a dispatcher task
/// hands each event to its [`BleRouter`], which fans it out to the owning server by characteristic
/// UUID, falling back to the most-recently-started live server, and broadcasts adapter
/// `StateUpdate`s to all of them.
#[cfg(all(unix, feature = "bluetooth"))]
struct BleHub {
    /// The one real radio. Its mutating methods take `&mut self`, so calls are serialised here.
    peripheral: Mutex<Peripheral>,
    /// Where the single event stream is fanned out to per-server channels.
    router: BleRouter,
}

/// Routes one shared radio's events to the right per-server channel.
///
/// Split out of [`BleHub`] so it is exercisable without a Bluetooth adapter: it holds no
/// `Peripheral`, only channels, so a test can register stub servers, dispatch events, and assert
/// which server received what. It is `pub` for the same reason `run_event_loop_without_radio` and
/// `parse_ble_uuid` are — the project forbids `#[cfg(test)]` modules in `src/`.
#[cfg(all(unix, feature = "bluetooth"))]
#[derive(Default)]
pub struct BleRouter {
    /// characteristic UUID (lowercased) -> the event channel of the server that added it.
    routes: std::sync::Mutex<HashMap<String, mpsc::Sender<PeripheralEvent>>>,
    /// Every started server's event channel, for events with no characteristic (StateUpdate)
    /// and as the routing fallback.
    servers: std::sync::Mutex<Vec<mpsc::Sender<PeripheralEvent>>>,
}

#[cfg(all(unix, feature = "bluetooth"))]
static BLE_HUB: tokio::sync::OnceCell<Arc<BleHub>> = tokio::sync::OnceCell::const_new();

#[cfg(all(unix, feature = "bluetooth"))]
impl BleRouter {
    /// A router with no registered servers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly started server so adapter-level events and unrouted requests can reach
    /// it.
    pub fn register_server(&self, tx: mpsc::Sender<PeripheralEvent>) {
        self.servers.lock().unwrap().push(tx);
    }

    /// Point a characteristic's future read/write/subscribe events at the server that owns it.
    ///
    /// Keyed through [`characteristic_key`], so a route registered from the `"2A37"` shorthand
    /// is found by a lookup for the canonical form the radio reports. Lowercasing alone was not
    /// enough and failed silently — see [`characteristic_key`].
    pub fn register_characteristic(&self, char_uuid: &str, tx: mpsc::Sender<PeripheralEvent>) {
        self.routes
            .lock()
            .unwrap()
            .insert(characteristic_key(char_uuid), tx);
    }

    /// Choose where a characteristic event goes: its registered owner, else the newest live
    /// server. Closed channels (stopped servers) are skipped so a dead server never captures
    /// traffic.
    fn route_target(&self, char_uuid_lc: &str) -> Option<mpsc::Sender<PeripheralEvent>> {
        if let Some(tx) = self.routes.lock().unwrap().get(char_uuid_lc) {
            if !tx.is_closed() {
                return Some(tx.clone());
            }
        }
        self.servers
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|tx| !tx.is_closed())
            .cloned()
    }

    /// Every still-open server channel.
    fn live_servers(&self) -> Vec<mpsc::Sender<PeripheralEvent>> {
        self.servers
            .lock()
            .unwrap()
            .iter()
            .filter(|tx| !tx.is_closed())
            .cloned()
            .collect()
    }

    /// Fan one radio event out to the owning server(s). Never holds a std lock across an await —
    /// senders are cloned out first.
    pub async fn dispatch(&self, event: PeripheralEvent) {
        match event {
            // No characteristic: an adapter state change concerns every server on the radio.
            // `PeripheralEvent` is not `Clone` (read/write carry a `oneshot` responder), but
            // `StateUpdate` is trivially rebuildable, so it can be fanned out.
            PeripheralEvent::StateUpdate { is_powered } => {
                for tx in self.live_servers() {
                    let _ = tx.send(PeripheralEvent::StateUpdate { is_powered }).await;
                }
            }
            // Everything else names a characteristic and carries at most one responder, so it
            // goes to exactly one server.
            ev => {
                let char_uuid_lc = match &ev {
                    PeripheralEvent::ReadRequest { request, .. }
                    | PeripheralEvent::WriteRequest { request, .. }
                    | PeripheralEvent::CharacteristicSubscriptionUpdate { request, .. } => {
                        characteristic_key(&request.characteristic.to_string())
                    }
                    PeripheralEvent::StateUpdate { .. } => unreachable!(),
                };
                match self.route_target(&char_uuid_lc) {
                    Some(tx) => {
                        let _ = tx.send(ev).await;
                    }
                    None => {
                        // No live server owns this characteristic. A read/write responder is
                        // dropped here, which the central surfaces as a failed operation — the
                        // honest outcome when nothing is behind the GATT entry.
                        warn!(
                            "BLE event for characteristic {} has no live server to handle it; \
                             dropping",
                            char_uuid_lc
                        );
                    }
                }
            }
        }
    }
}

/// Bluetooth Low Energy GATT server
pub struct BluetoothBle;

impl BluetoothBle {
    /// Spawn the BLE GATT server with integrated LLM actions
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        instruction: String,
    ) -> Result<std::net::SocketAddr> {
        // Acquire the process-wide shared radio. It is created (and the adapter powered on)
        // exactly once, on the first BLE server start; every later start reuses it with no
        // wait. Creating a fresh `Peripheral` per start is what IMPROVEMENTS item 2 describes:
        // the crate's global manager singleton leaves the second peripheral's command channel
        // dead, so `is_powered()` never returns true and the start falsely times out. See
        // [`BleHub`].
        let hub = Self::shared_hub(&status_tx)
            .await
            .context("Failed to bring up the shared BLE radio")?;

        info!("Bluetooth server created on shared radio, adapter powered on");
        Log::new(Some(&status_tx)).info(format!(
            "Bluetooth server created for device '{}'",
            device_name
        ));

        // This server's slice of the shared event stream. The hub's dispatcher forwards this
        // server's characteristic events here; adapter state changes are broadcast here too.
        let (event_tx, event_rx) = mpsc::channel::<PeripheralEvent>(256);
        hub.router.register_server(event_tx.clone());

        // Create server data
        let server_data = Arc::new(Mutex::new(ServerData {
            hub: Some(hub.clone()),
            event_tx: Some(event_tx.clone()),
            memory: String::new(),
            characteristics: HashMap::new(),
        }));

        let protocol = Arc::new(BluetoothBleProtocol::new());

        // Call LLM with server started event to get initial configuration
        let started_event = Event::new(
            &BLUETOOTH_BLE_STARTED_EVENT,
            serde_json::json!({
                "device_name": device_name,
                "instruction": instruction,
            }),
        );

        info!("Calling LLM for initial Bluetooth server configuration");

        // Bringing the adapter up must not require the model to be reachable: the LLM answers
        // traffic, it does not open the radio. This call used to propagate with `?`, so an
        // Ollama outage made `spawn()` return `Err` and the server never started.
        //
        // Unlike NFC and the USB smart card reader there is no useful default here — the
        // configuration *is* the services and the advertisement — so a failure leaves a
        // powered adapter advertising nothing. That is a much better outcome than a server
        // that will not start, but it is not a working one, so it is logged at ERROR on both
        // channels saying exactly that. The individual actions are non-fatal for the same
        // reason `executor::execute_actions` does not abort a batch on one bad action:
        // dropping the rest would suppress the services that were fine.
        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            None, // No connection_id for server-level actions
            &started_event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(llm_result) => {
                // Execute initial actions (add services, start advertising, etc.)
                let mut failed = 0usize;
                let mut attempted = 0usize;
                for action in llm_result.raw_actions {
                    attempted += 1;
                    debug!(
                        "Executing initial Bluetooth action: {:?}",
                        action.get("type")
                    );
                    if let Err(e) =
                        Self::execute_action(&server_data, &device_name, action, &status_tx).await
                    {
                        failed += 1;
                        Log::new(Some(&status_tx)).error(format!(
                            "Bluetooth startup for '{device_name}' \
                             decision=fail_closed_bad_action: initial action failed: {e}"
                        ));
                    }
                }

                // Startup is the one BLE outcome no per-event tag can reach, and it is the
                // one that leaves the server looking healthy while it is not: a powered
                // adapter with no services and no advertisement, reported as `Running`.
                // Tagging it is what lets `grep decision=` find that state at all.
                let log = Log::new(Some(&status_tx));
                if attempted == 0 {
                    log.warn(format!(
                        "Bluetooth startup for '{device_name}' decision=model_silent: the \
                         model configured nothing, so the adapter is powered with no services \
                         and is NOT advertising"
                    ));
                } else if failed == attempted {
                    log.error(format!(
                        "Bluetooth startup for '{device_name}' \
                         decision=fail_closed_no_action: every initial action failed; the \
                         adapter is powered with no services and is NOT advertising"
                    ));
                } else {
                    log.info(format!(
                        "Bluetooth startup for '{device_name}' decision=model_answer: \
                         {} of {attempted} initial action(s) applied",
                        attempted - failed
                    ));
                }
            }
            Err(e) => {
                // Deliberately not fatal — the adapter is up and the event loop below can
                // still answer reads — but the server reports `Running` with nothing on air,
                // so this must be greppable as a backend failure rather than as a decision
                // anybody took.
                let decision = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "Bluetooth startup configuration failed for '{}' decision={}: {}; the \
                     adapter is powered but has no services and is NOT advertising",
                    device_name, decision, e
                );
                Log::new(Some(&status_tx)).error(format!(
                    "Bluetooth startup for '{device_name}' decision={decision}: the adapter \
                     is up but no services were added and it is not advertising."
                ));
            }
        }

        // Spawn event processing loop
        let llm_client_clone = llm_client.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let server_data_clone = server_data.clone();
        let protocol_clone = protocol.clone();

        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                Self::event_loop(
                    event_rx,
                    server_id,
                    llm_client_clone,
                    app_state_clone,
                    status_tx_clone,
                    server_data_clone,
                    protocol_clone,
                )
                .await;
            })
            .await;

        // BLE speaks to a radio, not a socket, so there is no endpoint to report.
        //
        // This used to return `127.0.0.1:{5900 + server_id % 100}` "for display purposes".
        // `server_startup::is_bound_addr` only rejects port 0, so that address was recorded as
        // `local_addr` and the TUI, `server_status` and every log reader were told the BLE
        // server was listening on a loopback port that nothing had bound — and on 5900, which
        // is VNC's port, so it could also collide with a real server in the display. Port 0 is
        // this codebase's "binds no listening socket" placeholder and is recognised as such.
        Ok(std::net::SocketAddr::from((
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )))
    }

    /// Get (creating once) the process-wide shared BLE radio.
    ///
    /// The first call builds the single `Peripheral`, waits for the adapter to power on, and
    /// spawns the dispatcher task that fans radio events out to per-server channels. Every later
    /// call returns the same `Arc<BleHub>` immediately. On failure the `OnceCell` stays empty so
    /// a subsequent start retries rather than caching the failure.
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn shared_hub(status_tx: &mpsc::UnboundedSender<String>) -> Result<Arc<BleHub>> {
        let status_tx = status_tx.clone();
        BLE_HUB
            .get_or_try_init(move || async move {
                info!("Creating shared BLE peripheral (first BLE server in this process)");

                // The single process-wide event stream. `Peripheral::new` bakes this sender into
                // the crate's global manager; the hub dispatcher owns the receiver.
                let (event_tx, mut event_rx) = mpsc::channel::<PeripheralEvent>(256);
                let mut peripheral = Peripheral::new(event_tx)
                    .await
                    .context("Failed to create BLE peripheral")?;

                // Wait for the adapter to power on — once, here, not per server start.
                let mut retries = 0;
                while !peripheral.is_powered().await.unwrap_or(false) {
                    if retries == 0 {
                        Log::new(Some(&status_tx))
                            .warn("Bluetooth adapter is not powered on, waiting...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    retries += 1;
                    if retries > 20 {
                        anyhow::bail!("Bluetooth adapter failed to power on after 10 seconds");
                    }
                }

                info!("Bluetooth adapter powered on (shared radio)");
                Log::new(Some(&status_tx)).info("Bluetooth adapter powered on");

                let hub = Arc::new(BleHub {
                    peripheral: Mutex::new(peripheral),
                    router: BleRouter::new(),
                });

                // Single dispatcher for the whole process: route each radio event to the server
                // that owns the characteristic (or broadcast, for adapter state).
                let dispatch_hub = hub.clone();
                tokio::spawn(async move {
                    while let Some(event) = event_rx.recv().await {
                        dispatch_hub.router.dispatch(event).await;
                    }
                    warn!("BLE shared radio event stream ended; no further events will be routed");
                });

                Ok::<Arc<BleHub>, anyhow::Error>(hub)
            })
            .await
            .cloned()
    }

    /// Execute a single LLM action
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn execute_action(
        server_data: &Arc<Mutex<ServerData>>,
        device_name: &str,
        action: serde_json::Value,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let action_type = action["type"]
            .as_str()
            .context("Action must have 'type' field")?;

        match action_type {
            "add_service" => Self::execute_add_service(server_data, action, status_tx).await,
            "start_advertising" => {
                Self::execute_start_advertising(server_data, device_name, action, status_tx).await
            }
            "stop_advertising" => Self::execute_stop_advertising(server_data, status_tx).await,
            "send_notification" => {
                Self::execute_send_notification(server_data, action, status_tx).await
            }
            "respond_to_read" | "send_read_response" => {
                // Read responses are handled inline in event loop
                Ok(())
            }
            "respond_to_write" | "send_write_response" => {
                // Write responses are handled inline in event loop
                Ok(())
            }
            _ => {
                // Not `Ok(())`. An unrecognised action did nothing, and reporting success for it
                // made a misspelled or invented action name indistinguishable from one that ran:
                // the only trace was a `warn!` in `netget.log`, nothing on the status channel.
                // The callers log the error and continue with the rest of the batch, so this
                // stays non-fatal — it is now merely honest about what happened.
                Err(anyhow::anyhow!(
                    "Unknown Bluetooth action type {action_type:?}; nothing was done. Known \
                     actions: add_service, start_advertising, stop_advertising, \
                     send_notification, respond_to_read, respond_to_write."
                ))
            }
        }
    }

    /// Add a GATT service
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn execute_add_service(
        server_data: &Arc<Mutex<ServerData>>,
        action: serde_json::Value,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let uuid_str = action["uuid"]
            .as_str()
            .context("add_service requires 'uuid' field")?;
        let primary = action["primary"].as_bool().unwrap_or(true);

        let uuid = parse_ble_uuid(uuid_str).context("Invalid service UUID")?;

        let chars_json = action["characteristics"]
            .as_array()
            .context("add_service requires 'characteristics' array")?;

        let mut characteristics = Vec::new();
        let mut char_uuids: Vec<String> = Vec::new();
        let mut server_data_guard = server_data.lock().await;

        for char_json in chars_json {
            let char_uuid_str = char_json["uuid"]
                .as_str()
                .context("characteristic requires 'uuid' field")?;
            let char_uuid = parse_ble_uuid(char_uuid_str).context("Invalid characteristic UUID")?;

            // Parse properties
            let props_json = char_json["properties"]
                .as_array()
                .context("characteristic requires 'properties' array")?;
            let mut properties = Vec::new();
            for prop in props_json {
                let prop_str = prop.as_str().context("property must be string")?;
                properties.push(match prop_str.to_lowercase().as_str() {
                    "read" => CharacteristicProperty::Read,
                    "write" => CharacteristicProperty::Write,
                    "notify" => CharacteristicProperty::Notify,
                    "indicate" => CharacteristicProperty::Indicate,
                    "write_without_response" => CharacteristicProperty::WriteWithoutResponse,
                    _ => {
                        warn!("Unknown property: {}, defaulting to Read", prop_str);
                        CharacteristicProperty::Read
                    }
                });
            }

            // Parse permissions
            let empty_perms = Vec::new();
            let perms_json = char_json["permissions"].as_array().unwrap_or(&empty_perms);
            let mut permissions = Vec::new();
            for perm in perms_json {
                let perm_str = perm.as_str().context("permission must be string")?;
                permissions.push(match perm_str.to_lowercase().as_str() {
                    "readable" => AttributePermission::Readable,
                    "writeable" => AttributePermission::Writeable,
                    _ => {
                        warn!("Unknown permission: {}", perm_str);
                        continue;
                    }
                });
            }

            // Parse initial value (hex-encoded).
            //
            // A value that will not decode is refused, not silently dropped. `unwrap_or_default()`
            // turned a malformed `initial_value` into *zero bytes stored for that
            // characteristic*, and the read path then served exactly those zero bytes under
            // `RequestResponse::Success` on `decision=model_silent` — telling the central "this
            // characteristic holds nothing" on the strength of a value nobody could read. That is
            // the same defect `ReadDecision::Unusable` exists to prevent one layer up: an answer
            // that cannot be decoded is not an answer. Failing here surfaces the typo to the
            // model instead of baking it into the GATT database.
            let initial_value = parse_initial_value(&char_uuid_str, &char_json["initial_value"])?;

            // Store characteristic data for tracking, keyed canonically so the read, write and
            // notification paths can find it whatever spelling the model used here.
            server_data_guard.characteristics.insert(
                characteristic_key(char_uuid_str),
                CharacteristicData {
                    // The model's own spelling, kept for diagnostics.
                    uuid: char_uuid_str.to_string(),
                    properties: props_json
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    permissions: perms_json
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    current_value: initial_value.clone(),
                },
            );

            // `mut` is only used by the Apple-specific guard below.
            #[allow(unused_mut)]
            let mut cached_value = if initial_value.is_empty() {
                None
            } else {
                Some(initial_value)
            };

            // CoreBluetooth (macOS/iOS) raises NSInvalidArgumentException from
            // -[CBMutableCharacteristic initWithType:properties:value:permissions:] when a
            // cached value is combined with anything other than read-only properties and
            // permissions. That Objective-C exception crosses the FFI boundary and aborts the
            // whole process ("fatal runtime error: Rust cannot catch foreign exceptions"), so it
            // cannot be caught or reported - it must be avoided. ble-peripheral-rust documents
            // the same constraint in its CoreBluetooth backend (peripheral_manager.rs:205).
            //
            // Dropping the cached value costs nothing: reads are served through the
            // bluetooth_read_request -> respond_to_read event path, never from this cache.
            #[cfg(target_vendor = "apple")]
            if cached_value.is_some() {
                let read_only = properties
                    .iter()
                    .all(|p| matches!(p, CharacteristicProperty::Read))
                    && permissions
                        .iter()
                        .all(|p| matches!(p, AttributePermission::Readable));
                if !read_only {
                    warn!(
                        "CoreBluetooth: ignoring initial_value on characteristic {} - a cached \
                         value is only legal on a read-only characteristic. Reads are answered \
                         via bluetooth_read_request instead.",
                        char_uuid_str
                    );
                    Log::new(Some(&status_tx)).warn(format!(
                        "BLE {}: initial_value ignored (macOS allows a cached value only \
                         on read-only characteristics); reads are answered by the LLM",
                        char_uuid_str
                    ));
                    cached_value = None;
                }
            }

            characteristics.push(Characteristic {
                uuid: char_uuid,
                properties,
                permissions,
                value: cached_value,
                descriptors: Vec::new(), // TODO: support descriptors if needed
            });
            char_uuids.push(char_uuid_str.to_string());
        }

        // Capture the shared radio and this server's event channel, then drop the ServerData
        // guard: the radio call below awaits I/O and must not be made holding that lock (and
        // never with the two locks nested, to keep a consistent order).
        let hub = server_data_guard.hub.clone();
        let event_tx = server_data_guard.event_tx.clone();
        drop(server_data_guard);

        // Point this characteristic's future read/write/subscribe events at this server.
        if let (Some(hub), Some(tx)) = (hub.as_ref(), event_tx.as_ref()) {
            for cu in &char_uuids {
                hub.router.register_characteristic(cu, tx.clone());
            }
        }

        let service = Service {
            uuid,
            primary,
            characteristics,
        };

        if let Some(hub) = hub.as_ref() {
            hub.peripheral
                .lock()
                .await
                .add_service(&service)
                .await
                .context("Failed to add service to peripheral")?;

            Log::new(Some(&status_tx)).info(format!(
                "Added BLE service {} with {} characteristics",
                uuid_str,
                chars_json.len()
            ));
        }

        Ok(())
    }

    /// Start BLE advertising
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn execute_start_advertising(
        server_data: &Arc<Mutex<ServerData>>,
        device_name: &str,
        action: serde_json::Value,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // The advertised LocalName is model-supplied and goes straight onto the air, into the
        // status channel, and into whatever scanner UI displays it. A control character there
        // is a forged line in someone else's log or a forged screen in someone else's
        // terminal, so it is stripped here rather than trusted. 29 characters is what fits an
        // AD structure in a 31-octet legacy advertisement once its length and type bytes are
        // accounted for; a longer name would be refused by the radio, not truncated politely.
        let name = crate::utils::sanitize::token(
            action["device_name"].as_str().unwrap_or(device_name),
            MAX_LOCAL_NAME_CHARS,
        );
        let name = name.as_str();

        // Parse service UUIDs if provided
        let service_uuids: Vec<Uuid> = action["service_uuids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| parse_ble_uuid(s).ok())
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        let hub = server_data.lock().await.hub.clone();
        if let Some(hub) = hub.as_ref() {
            hub.peripheral
                .lock()
                .await
                .start_advertising(name, &service_uuids)
                .await
                .context("Failed to start advertising")?;

            console_info!(
                status_tx,
                "Started BLE advertising as '{}' with {} service(s)",
                name,
                service_uuids.len()
            );
        } else {
            // No radio attached (the radio-free event loop used by tests). Nothing is being
            // advertised, and previously nothing said so — the action reported success and the
            // device was simply undiscoverable.
            Log::new(Some(status_tx)).warn(format!(
                "start_advertising as '{name}' had no BLE radio attached; the device is NOT \
                 discoverable"
            ));
        }

        Ok(())
    }

    /// Stop BLE advertising
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn execute_stop_advertising(
        server_data: &Arc<Mutex<ServerData>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let hub = server_data.lock().await.hub.clone();
        if let Some(hub) = hub.as_ref() {
            hub.peripheral
                .lock()
                .await
                .stop_advertising()
                .await
                .context("Failed to stop advertising")?;

            Log::new(Some(&status_tx)).info("Stopped BLE advertising");
        }

        Ok(())
    }

    /// Send notification to subscribed clients
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn execute_send_notification(
        server_data: &Arc<Mutex<ServerData>>,
        action: serde_json::Value,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let char_uuid_str = action["characteristic_uuid"]
            .as_str()
            .context("send_notification requires 'characteristic_uuid' field")?;
        let value_str = action["value"]
            .as_str()
            .context("send_notification requires 'value' field (hex-encoded)")?;

        let char_uuid = parse_ble_uuid(char_uuid_str).context("Invalid characteristic UUID")?;
        let value_str = value_str.trim_start_matches("0x");
        let value = hex::decode(value_str).context("Value must be hex-encoded")?;

        // Update stored value and capture the shared radio, then drop the guard before I/O.
        let hub = {
            let mut server_data_guard = server_data.lock().await;
            if let Some(char_data) = server_data_guard
                .characteristics
                .get_mut(&characteristic_key(char_uuid_str))
            {
                char_data.current_value = value.clone();
            }
            server_data_guard.hub.clone()
        };

        if let Some(hub) = hub.as_ref() {
            hub.peripheral
                .lock()
                .await
                .update_characteristic(char_uuid, value.clone())
                .await
                .context("Failed to send notification")?;

            Log::new(Some(&status_tx)).debug(format!(
                "Sent BLE notification on {} ({} bytes)",
                char_uuid_str,
                value.len()
            ));
        }

        Ok(())
    }

    /// Run the GATT event loop over an externally supplied event stream, with no radio.
    ///
    /// This is the same [`Self::event_loop`] `spawn_with_llm_actions` runs; the only difference
    /// is that the `ServerData` it builds holds no `Peripheral`, so the actions that would
    /// transmit are no-ops while the request/response paths are byte-for-byte the ones a real
    /// central drives.
    ///
    /// It exists so `tests/` can exercise the ATT error paths. The project forbids
    /// `#[cfg(test)]` modules in `src/`, and the alternative — a Bluetooth adapter plus a second
    /// radio acting as a central — is why every test in `tests/server/bluetooth_ble/e2e_test.rs`
    /// is `#[ignore]`d. `parse_ble_uuid` above is `pub` for the same reason.
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn run_event_loop_without_radio(
        event_rx: mpsc::Receiver<PeripheralEvent>,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        seed_characteristics: Vec<(String, Vec<u8>)>,
    ) {
        // `seed_characteristics` gives a test a GATT table that already exists, as `(uuid,
        // stored value)` pairs.
        //
        // Without it there is no legitimate way to reach the stored-value read path here: the
        // table is built by `add_service`, which is declared on `bluetooth_ble_started` and on
        // no other event, and this radio-free loop never raises that event. Seeding it through
        // the *read* response instead — which is what the tests used to do — is a mock a real
        // model could never produce, because `call_llm` offers only the firing event's actions,
        // and `tests/helpers/mock_action_names.rs` rejects it for exactly that reason.
        let characteristics = seed_characteristics
            .into_iter()
            .map(|(uuid, current_value)| {
                (
                    // Keyed through `characteristic_key`, exactly as the production
                    // `add_service` path does at its insert site — so a test may seed in any
                    // spelling a model could use and gets the same table a real `add_service`
                    // would build. That symmetry is the point: seeding pre-canonicalised was
                    // what hid the key mismatch `characteristic_key` documents, because the
                    // tests then only ever exercised the one spelling that happened to work.
                    characteristic_key(&uuid),
                    CharacteristicData {
                        uuid: uuid.clone(),
                        properties: vec!["read".to_string(), "write".to_string()],
                        permissions: vec!["readable".to_string(), "writable".to_string()],
                        current_value,
                    },
                )
            })
            .collect();

        let server_data = Arc::new(Mutex::new(ServerData {
            hub: None,
            event_tx: None,
            memory: String::new(),
            characteristics,
        }));

        Self::event_loop(
            event_rx,
            server_id,
            llm_client,
            app_state,
            status_tx,
            server_data,
            Arc::new(BluetoothBleProtocol::new()),
        )
        .await;
    }

    /// Main event processing loop
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn event_loop(
        mut event_rx: mpsc::Receiver<PeripheralEvent>,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_data: Arc<Mutex<ServerData>>,
        protocol: Arc<BluetoothBleProtocol>,
    ) {
        while let Some(event) = event_rx.recv().await {
            match event {
                PeripheralEvent::StateUpdate { is_powered, .. } => {
                    Log::new(Some(&status_tx))
                        .info(format!("Bluetooth state update: powered = {}", is_powered));

                    // Create event for LLM
                    let llm_event = Event::new(
                        &BLUETOOTH_STATE_CHANGED_EVENT,
                        serde_json::json!({
                            "state": if is_powered { "powered_on" } else { "powered_off" },
                        }),
                    );

                    // Call LLM with state change. There is no peer waiting on an adapter
                    // state change, so silence towards the radio is the only possible
                    // behaviour - but the failure must still be visible. This used to be
                    // `let _ = ...`, which discarded the error with no log on either channel.
                    if let Err(e) = Self::call_llm_for_event(
                        &server_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &server_data,
                        &protocol,
                        llm_event,
                    )
                    .await
                    {
                        console_error!(
                            status_tx,
                            "BLE adapter state change (powered = {}) was not handled: the \
                             handler failed ({}). Nothing was reconfigured.",
                            is_powered,
                            e
                        );
                    }
                }
                PeripheralEvent::ReadRequest {
                    request,
                    offset,
                    responder,
                } => {
                    let char_uuid_str = request.characteristic.to_string();

                    Log::new(Some(&status_tx)).debug(format!(
                        "BLE read request on {} (offset: {})",
                        char_uuid_str, offset
                    ));

                    // Create read request event
                    let llm_event = Event::new(
                        &BLUETOOTH_READ_REQUEST_EVENT,
                        serde_json::json!({
                            "characteristic_uuid": char_uuid_str,
                            "offset": offset,
                        }),
                    );

                    // Call LLM
                    match Self::call_llm_for_event(
                        &server_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &server_data,
                        &protocol,
                        llm_event,
                    )
                    .await
                    {
                        Ok(llm_result) => {
                            // Three outcomes, kept apart on purpose. ATT carries only
                            // "here is a value" or an error code, so what the wire
                            // cannot distinguish the log must: every branch below names
                            // its `decision=`.
                            //
                            // The stored-value fallback is deliberate and is *not* an
                            // invented answer: the characteristic's current value is
                            // this server's own state, set by `add_service`'s
                            // `initial_value`, by `send_notification`, or by the last
                            // write. Serving it when the handler declined to name a
                            // value is ordinary GATT behaviour. What is not allowed is
                            // conjuring a value where there is none, or substituting the
                            // stored value for an answer we failed to decode.
                            //
                            // The lookup is `.await`ed, not
                            // `futures::executor::block_on(server_data.lock())` inside a
                            // synchronous closure as it once was — a blocking lock on a
                            // tokio worker thread, which can panic ("Cannot block the
                            // current thread from within a runtime") into the
                            // `tokio::spawn` that swallows it, leaving the server
                            // looking healthy while the read died.
                            let reply = match read_decision(&llm_result.raw_actions) {
                                ReadDecision::Value(value) => {
                                    Log::new(Some(&status_tx)).debug(format!(
                                        "BLE read of {} answered by handler \
                                                 (decision=model_value, {} bytes)",
                                        char_uuid_str,
                                        value.len()
                                    ));
                                    ReadRequestResponse {
                                        value,
                                        response: RequestResponse::Success,
                                    }
                                }
                                ReadDecision::UseStored => {
                                    let stored = {
                                        let guard = server_data.lock().await;
                                        guard
                                            .characteristics
                                            .get(&characteristic_key(&char_uuid_str))
                                            .map(|c| c.current_value.clone())
                                    };
                                    match stored {
                                        Some(value) => {
                                            Log::new(Some(&status_tx)).debug(format!(
                                                "BLE read of {} not answered by the \
                                                         handler (decision=model_silent); \
                                                         serving the stored value ({} bytes)",
                                                char_uuid_str,
                                                value.len()
                                            ));
                                            ReadRequestResponse {
                                                value,
                                                response: RequestResponse::Success,
                                            }
                                        }
                                        None => {
                                            // Nothing was said and nothing is stored:
                                            // an empty Success here would assert that
                                            // this characteristic holds zero bytes,
                                            // which nothing is in a position to claim.
                                            console_error!(
                                                status_tx,
                                                "BLE read of {} could not be answered \
                                                         (decision=fail_closed_model_silent_no_\
                                                         value): the handler named no value and \
                                                         this characteristic has none stored. \
                                                         Replying ATT Unlikely Error (0x0E).",
                                                char_uuid_str
                                            );
                                            ReadRequestResponse {
                                                value: Vec::new(),
                                                response: RequestResponse::UnlikelyError,
                                            }
                                        }
                                    }
                                }
                                ReadDecision::Unusable(reason) => {
                                    console_error!(
                                        status_tx,
                                        "BLE read of {} could not be answered \
                                                 (decision=fail_closed_bad_value): {}. Replying \
                                                 ATT Unlikely Error (0x0E); the stored value is \
                                                 NOT substituted for an answer that failed to \
                                                 decode.",
                                        char_uuid_str,
                                        reason
                                    );
                                    ReadRequestResponse {
                                        value: Vec::new(),
                                        response: RequestResponse::UnlikelyError,
                                    }
                                }
                            };

                            let _ = responder.send(reply);
                        }
                        Err(e) => {
                            // Fail closed, and say so on both channels. ATT has no
                            // "try again later"; `UnlikelyError` (0x0E) is the generic
                            // "the server could not do it" the central will surface as
                            // a failed read. This is a *backend* failure and stays
                            // distinct from the Ok branch's decisions above: no handler
                            // ran, so not even the stored value is served — it would be
                            // a claim about the characteristic that nothing here is in
                            // a position to make.
                            console_error!(
                                status_tx,
                                "BLE read of {} could not be answered \
                                         (decision=fail_closed_llm_error): the handler failed \
                                         ({}). Replying ATT Unlikely Error (0x0E); no \
                                         characteristic value is being invented.",
                                char_uuid_str,
                                e
                            );
                            let _ = responder.send(ReadRequestResponse {
                                value: Vec::new(),
                                response: RequestResponse::UnlikelyError,
                            });
                        }
                    }
                }
                PeripheralEvent::WriteRequest {
                    request,
                    value,
                    offset,
                    responder,
                } => {
                    let char_uuid_str = request.characteristic.to_string();
                    let value_hex = hex::encode(&value);

                    Log::new(Some(&status_tx)).debug(format!(
                        "BLE write request on {} ({} bytes)",
                        char_uuid_str,
                        value.len()
                    ));
                    console_trace!(status_tx, "BLE write data (hex): {}", value_hex);

                    // Update stored value
                    {
                        let mut guard = server_data.lock().await;
                        if let Some(char_data) = guard
                            .characteristics
                            .get_mut(&characteristic_key(&char_uuid_str))
                        {
                            char_data.current_value = value.clone();
                        }
                    }

                    // Create write request event
                    let llm_event = Event::new(
                        &BLUETOOTH_WRITE_REQUEST_EVENT,
                        serde_json::json!({
                            "characteristic_uuid": char_uuid_str,
                            "value": value_hex,
                            "offset": offset,
                        }),
                    );

                    // Call LLM
                    match Self::call_llm_for_event(
                        &server_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &server_data,
                        &protocol,
                        llm_event,
                    )
                    .await
                    {
                        Ok(llm_result) => {
                            // `respond_to_write` declares a `status` of 'success' or
                            // 'error', and nothing read it: every answered write was
                            // acknowledged Success, so a model rejecting a value -
                            // out of range, wrong length, not writable right now -
                            // was told the peer it had been accepted. The ATT Write
                            // Response is the only signal the central gets.
                            let response = write_response_status(&llm_result.raw_actions);
                            if matches!(response, RequestResponse::UnlikelyError) {
                                Log::new(Some(&status_tx)).info(format!(
                                    "BLE write to {} rejected by handler \
                                             (decision=model_reject); replying ATT Unlikely \
                                             Error (0x0E)",
                                    char_uuid_str
                                ));
                            } else if !llm_result.raw_actions.iter().any(|a| {
                                matches!(
                                    a.get("type").and_then(|v| v.as_str()),
                                    Some("respond_to_write") | Some("send_write_response")
                                )
                            }) {
                                // The write itself already took effect above — the
                                // stored value was updated before the handler ran — so
                                // acknowledging it is accurate rather than permissive.
                                // But silence and an explicit success are the same
                                // Write Response on the wire, so the log has to hold
                                // them apart from each other and from `model_reject`.
                                Log::new(Some(&status_tx)).debug(format!(
                                    "BLE write to {} not answered by the handler \
                                             (decision=model_silent); the value was stored, so \
                                             replying ATT Success",
                                    char_uuid_str
                                ));
                            }
                            let _ = responder.send(WriteRequestResponse { response });
                        }
                        Err(e) => {
                            // Fail closed: the central must be told the write did not
                            // take effect. An ATT Write Response is an acknowledgement,
                            // so answering Success here would tell the peer its value
                            // was accepted by a handler that never ran.
                            console_error!(
                                status_tx,
                                "BLE write to {} could not be answered: the handler \
                                         failed ({}). Replying ATT Unlikely Error (0x0E); the \
                                         write is NOT acknowledged.",
                                char_uuid_str,
                                e
                            );
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::UnlikelyError,
                            });
                        }
                    }
                }
                PeripheralEvent::CharacteristicSubscriptionUpdate {
                    request,
                    subscribed,
                } => {
                    let char_uuid_str = request.characteristic.to_string();
                    if subscribed {
                        console_info!(
                            status_tx,
                            "Client subscribed to notifications on {}",
                            char_uuid_str
                        );
                    } else {
                        console_info!(
                            status_tx,
                            "Client unsubscribed from notifications on {}",
                            char_uuid_str
                        );
                    }

                    let llm_event = Event::new(
                        &BLUETOOTH_SUBSCRIBE_EVENT,
                        serde_json::json!({
                            "characteristic_uuid": char_uuid_str,
                            "subscribed": subscribed,
                        }),
                    );

                    // A CCCD subscription update is reported after the fact - the stack has
                    // already acknowledged the descriptor write and there is no responder here,
                    // so there is nothing to answer. What there is to do is say the
                    // subscription will not be served, because the notifications the central is
                    // now waiting for were never set up. This used to be `let _ = ...`.
                    if let Err(e) = Self::call_llm_for_event(
                        &server_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &server_data,
                        &protocol,
                        llm_event,
                    )
                    .await
                    {
                        console_error!(
                            status_tx,
                            "BLE subscription change on {} (subscribed = {}) was not handled: \
                             the handler failed ({}). No notifications will be sent for it.",
                            char_uuid_str,
                            subscribed,
                            e
                        );
                    }
                }
            }
        }
    }

    /// Call LLM with an event and execute resulting actions
    #[cfg(all(unix, feature = "bluetooth"))]
    async fn call_llm_for_event(
        server_id: &crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        server_data: &Arc<Mutex<ServerData>>,
        protocol: &Arc<BluetoothBleProtocol>,
        event: Event,
    ) -> Result<crate::llm::actions::executor::ExecutionResult> {
        let _memory = server_data.lock().await.memory.clone();

        let llm_result = call_llm(
            llm_client,
            app_state,
            *server_id,
            None, // No connection_id for server-level events
            &event,
            protocol.as_ref(),
        )
        .await?;

        // Execute returned actions (except read/write responses which are handled inline)
        for action in &llm_result.raw_actions {
            let action_type = action.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match action_type {
                "respond_to_read"
                | "send_read_response"
                | "respond_to_write"
                | "send_write_response" => {
                    // These are handled inline in the event match arms
                    continue;
                }
                _ => {
                    if let Err(e) =
                        Self::execute_action(server_data, "NetGet-BLE", action.clone(), status_tx)
                            .await
                    {
                        error!("Failed to execute action: {}", e);
                    }
                }
            }
        }

        Ok(llm_result)
    }
}

#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBle {
    pub async fn spawn_with_llm_actions(
        _device_name: String,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _instruction: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!(
            "Bluetooth server support not enabled - compile with --features bluetooth-ble"
        )
    }
}

/// Decode a characteristic's `initial_value` from `add_service`.
///
/// Absent is `Vec::new()` — a characteristic may legitimately start empty. Present but not
/// hex is an **error**, not zero bytes: `unwrap_or_default()` here used to turn a malformed
/// `initial_value` into zero bytes stored for that characteristic, and the read path then
/// served exactly those zero bytes under `RequestResponse::Success` on `decision=model_silent`
/// — telling the central "this characteristic holds nothing" on the strength of a value nobody
/// could read. That is the defect `ReadDecision::Unusable` exists to prevent one layer up: an
/// answer that cannot be decoded is not an answer.
///
/// Extracted so the property is testable. `add_service` is declared only on
/// `bluetooth_ble_started`, which the radio-free test loop never raises, so there is no way to
/// reach this through `run_event_loop_without_radio` — and reaching it by returning
/// `add_service` from a *read* response is a mock no real model could produce.
pub fn parse_initial_value(char_uuid: &str, value: &serde_json::Value) -> Result<Vec<u8>> {
    let Some(val_str) = value.as_str() else {
        return Ok(Vec::new());
    };
    hex::decode(val_str.trim_start_matches("0x")).with_context(|| {
        format!(
            "characteristic {char_uuid}: initial_value {val_str:?} is not hex-encoded bytes \
             (expected something like \"0048\" or \"0x0048\")"
        )
    })
}
