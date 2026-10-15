//! USB HID Keyboard server implementation
//!
//! This module implements a virtual USB HID keyboard using the USB/IP protocol.
//! The keyboard can be controlled by the LLM to type text, press keys, and handle
//! key combinations (Ctrl+C, Alt+Tab, etc.).
//!
//! ## When the LLM call fails, the keyboard stays silent — deliberately
//!
//! Most protocols owe the peer an answer, and going quiet on an LLM failure leaves it hanging
//! until its own timeout. A HID keyboard owes nothing. The host polls the interrupt IN endpoint
//! and is NAKed whenever no key is down; a keyboard with nothing to report is the *normal*
//! state of every keyboard in the world, not an error condition. There is no HID vocabulary for
//! "the device's brain is unreachable" either: STALLing the interrupt endpoint is a fault
//! condition that makes a host reset or unbind the device, which is a worse and less truthful
//! answer than reporting no keystrokes. (`usbip` also has no way to express it — returning
//! `Err` from `handle_urb` aborts the USB/IP session for the whole device.)
//!
//! The fail-closed property that *does* matter here is the one this direction makes free: a
//! failed LLM call must never put a keystroke on the wire. Nothing below can synthesise a
//! report; reports exist only where an action produced them.
//!
//! So the failure is dual-logged at ERROR and nothing is sent. The log carries a `decision=`
//! tag so the three outcomes an operator would otherwise see as one quiet keyboard stay apart:
//! `decision=fail_closed_llm_error` (the backend failed), `decision=model_no_actions` (the model answered
//! and asked for no keystrokes) and `decision=model_actions` (something was typed).
//! `tests/server/usb_keyboard/llm_failure_test.rs` pins both halves.

pub mod actions;

#[cfg(all(unix, feature = "libusb"))]
pub mod handler;

// Re-export protocol struct for registration
#[cfg(all(unix, feature = "libusb"))]
pub use actions::UsbKeyboardProtocol;

#[cfg(all(unix, feature = "libusb"))]
use anyhow::Result;
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::net::SocketAddr;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::Arc;
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::{mpsc, Mutex};
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, error, info};

#[cfg(all(unix, feature = "libusb"))]
use crate::console_error;
#[cfg(all(unix, feature = "libusb"))]
use crate::llm::action_helper::call_llm;
#[cfg(all(unix, feature = "libusb"))]
use crate::llm::ollama_client::OllamaClient;
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::Event;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};
#[cfg(all(unix, feature = "libusb"))]
use crate::server::connection::ConnectionId;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::guard::{MAX_USBIP_CONNECTIONS, USBIP_NO_REFUSAL};
#[cfg(all(unix, feature = "libusb"))]
use crate::state::app_state::AppState;
#[cfg(all(unix, feature = "libusb"))]
use actions::{
    USB_KEYBOARD_ATTACHED_EVENT, USB_KEYBOARD_DETACHED_EVENT, USB_KEYBOARD_LED_STATUS_EVENT,
};
#[cfg(all(unix, feature = "libusb"))]
use handler::{LedState, NetGetKeyboardHandler};

/// Connection state for LLM processing
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-connection data for USB keyboard
#[cfg(all(unix, feature = "libusb"))]
struct ConnectionData {
    state: ConnectionState,
    #[allow(dead_code)]
    memory: String,
    /// Last LED byte the host set, kept so the TUI/state view can show it.
    led_status: u8,
}

/// USB HID Keyboard server
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbKeyboardServer;

#[cfg(all(unix, feature = "libusb"))]
impl UsbKeyboardServer {
    /// Spawn the USB keyboard server with LLM integration
    ///
    /// This creates a USB/IP server that exports a virtual HID keyboard device.
    /// The LLM can control the keyboard through actions like type_text and press_key.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // Create and bind TCP server for USB/IP protocol
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("USB Keyboard server listening on {}", local_addr);
        let _ = status_tx.send(format!("USB Keyboard server listening on {}", local_addr));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(crate::server::usb::keyboard::UsbKeyboardProtocol::new());

        // The two read deadlines, argued in `src/server/usb/guard.rs` and overridable per
        // server. Copied into each connection task; the screen is the only thing that reads
        // from the socket, so it is the only place they can be applied.
        let deadlines = crate::server::usb::guard::UsbIpDeadlines::from_secs(
            first_byte_timeout_secs,
            idle_timeout_secs,
        );
        let task_registrar = app_state.clone();
        // One emulated device per connection, so the cap is small and lives with the screen.
        let limiter = ConnectionLimiter::new(MAX_USBIP_CONNECTIONS);
        // Spawn accept loop for USB/IP connections
        let accept_handle = tokio::spawn(async move {
            loop {
                match accept_bounded(
                    &listener,
                    &limiter,
                    USBIP_NO_REFUSAL,
                    "USB keyboard",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "USB/IP connection {} from {} (USB keyboard device)",
                            connection_id, remote_addr
                        );

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr,
                            local_addr: local_addr_conn,
                            bytes_sent: 0,
                            bytes_received: 0,
                            packets_sent: 0,
                            packets_received: 0,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                                "state": "WaitingForImport",
                                "led_status": 0
                            })),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // Handle USB/IP connection
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early
                                // releases the slot while the device is still exported.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    connection_id,
                                    remote_addr,
                                    llm_client_clone,
                                    app_state_clone,
                                    status_tx_clone,
                                    connections_clone,
                                    protocol_clone,
                                    server_id,
                                    deadlines,
                                )
                                .await
                                {
                                    error!(
                                        "USB keyboard connection {} error: {}",
                                        connection_id, e
                                    );
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error recurs immediately, so continuing spins a
                        // hot loop on an unbounded status channel. Give up the listener.
                        error!("USB keyboard accept failed, stopping accept loop: {}", e);
                        break;
                    }
                }
            }
        });

        // Without this, stop_server has no handle to abort and the listener stays bound.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Handle USB/IP server lifecycle
    ///
    /// This creates a USB/IP server that exports a virtual HID keyboard device.
    /// The server handles USB/IP protocol operations and integrates with LLM actions.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<crate::server::usb::keyboard::UsbKeyboardProtocol>,
        server_id: crate::state::ServerId,
        deadlines: crate::server::usb::guard::UsbIpDeadlines,
    ) -> Result<()> {
        info!(
            "USB keyboard connection {} from {} - device ready for USB/IP import",
            connection_id, remote_addr
        );

        let local_addr = stream.local_addr().unwrap_or(remote_addr);

        // Initialize connection data
        connections.lock().await.insert(
            connection_id,
            ConnectionData {
                state: ConnectionState::Idle,
                memory: String::new(),
                led_status: 0,
            },
        );

        // LED reports arrive on a synchronous URB callback, which cannot raise an event by
        // itself. The channel is the seam between the two, exactly as in usb/msc.
        let (led_tx, mut led_rx) = mpsc::unbounded_channel::<LedState>();

        // A wrapper around the crate's keyboard handler: it keeps the key-down/key-up state
        // machine but takes over endpoint 0, so LED SET_REPORTs are seen (the crate discards
        // them, which is why usb_keyboard_led_status could never fire) and no control request
        // reaches the crate's `unimplemented!()`.
        let handler = Arc::new(std::sync::Mutex::new(Box::new(
            NetGetKeyboardHandler::new().with_led_events(led_tx),
        )
            as Box<dyn usbip::UsbInterfaceHandler + Send>));

        // Store handler in protocol for action execution
        protocol.set_handler(connection_id, handler.clone());

        // Create USB device with HID keyboard interface
        let device = usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::HID as u8,
            0x00, // Subclass: no subclass
            0x00, // Protocol: none
            Some("NetGet Virtual Keyboard"),
            vec![usbip::UsbEndpoint {
                address: 0x81,         // EP1 IN (interrupt)
                attributes: 0x03,      // Interrupt transfer
                max_packet_size: 0x08, // 8 bytes (keyboard report)
                interval: 10,          // 10ms polling interval
            }],
            handler.clone(),
        );

        let usbip_server = Arc::new(usbip::UsbIpServer::new_simulated(vec![device]));

        info!(
            "USB keyboard device ready for connection {} from {}",
            connection_id, remote_addr
        );
        let _ = status_tx.send(format!(
            "USB keyboard ready on {} - run: sudo usbip attach -r {} -b 0-0-0",
            local_addr,
            local_addr.ip()
        ));

        // Drive the USB/IP protocol on the socket we already accepted.
        //
        // This deliberately does not call `usbip::server()`: that binds a *second*
        // listener, which forced a hardcoded port (3240) and limited the protocol to one
        // instance per host. `usbip::handler` speaks the same protocol over an existing
        // socket, so the netget listener is the USB/IP listener and the port is whatever
        // the caller asked for.
        // Not `usbip::handler(&mut stream, ...)` directly: the crate allocates from the peer's
        // `transfer_buffer_length` and `number_of_packets` without checking either, on a socket
        // USB/IP never authenticates. `run_guarded_usbip` screens both before a byte reaches it
        // -- see `src/server/usb/guard.rs`.
        //
        // The attach event hangs off `import_rx`, not off the accept: see the note above
        // `import_pending` below.
        let guard_status_tx = status_tx.clone();
        let (import_tx, mut import_rx) = tokio::sync::oneshot::channel();
        let usbip_task = tokio::spawn(async move {
            match crate::server::usb::guard::run_guarded_usbip(
                stream,
                usbip_server,
                "USB keyboard",
                connection_id.to_string(),
                guard_status_tx,
                Some(import_tx),
                deadlines,
            )
            .await
            {
                Ok(()) => debug!(
                    "USB/IP session ended for keyboard connection {}",
                    connection_id
                ),
                Err(e) => debug!(
                    "USB/IP session for keyboard connection {} ended with error: {}",
                    connection_id, e
                ),
            }
        });

        // Serve the host until the USB/IP session ends. This loop is why
        // usb_keyboard_led_status can fire at all: the previous version awaited the session
        // handle directly and never looked at the LED channel.
        //
        // It is also where the attach event is raised. USB/IP authenticates nothing, so a bare
        // TCP connect must cost nothing: `import_rx` fires only once the screen has admitted an
        // `OP_REQ_IMPORT`, which is the first moment the peer has asked for the keyboard.
        // `import_pending` is the select! guard — a `oneshot::Receiver` must not be polled
        // again once it has resolved — and `imported` is the record, because the detach event
        // is the other half of an attachment and must not fire without one.
        let mut usbip_task = usbip_task;
        let mut import_pending = true;
        let mut imported = false;
        loop {
            tokio::select! {
                asked = &mut import_rx, if import_pending => {
                    import_pending = false;
                    if asked.is_ok() {
                        imported = true;
                        if let Err(e) = Self::call_llm_on_attach(
                            connection_id,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            &connections,
                            &protocol,
                            server_id,
                        )
                        .await
                        {
                            error!(
                                "Failed to call LLM on keyboard attach for connection {}: {}",
                                connection_id, e
                            );
                        }
                    }
                }
                received = led_rx.recv() => {
                    let Some(mut leds) = received else { break };
                    // A burst of LED writes (Caps then Num within a millisecond) is folded
                    // into the last state, so one keypress does not become several LLM calls.
                    while let Ok(newer) = led_rx.try_recv() {
                        leds = newer;
                    }
                    Self::call_llm_on_led_status(
                        connection_id,
                        leds,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &connections,
                        &protocol,
                        server_id,
                    )
                    .await;
                }
                _ = &mut usbip_task => break,
            }
        }

        info!(
            "USB keyboard host detached on connection {} from {}",
            connection_id, remote_addr
        );

        // Call LLM on device detach — only for a host that actually attached. A peer that
        // opened a socket and closed it again detached nothing.
        if imported {
            if let Err(e) = Self::call_llm_on_detach(
                connection_id,
                &llm_client,
                &app_state,
                &status_tx,
                &connections,
                &protocol,
                server_id,
            )
            .await
            {
                error!(
                    "Failed to call LLM on keyboard detach for connection {}: {}",
                    connection_id, e
                );
            }
        }

        // The USB/IP session owned this handler; drop it so a later connection with the
        // same id cannot reach a dead device.
        protocol.remove_handler(connection_id);
        connections.lock().await.remove(&connection_id);

        Ok(())
    }

    /// Raise `usb_keyboard_led_status` after the host changed a lock LED.
    ///
    /// This is the event's only emit site, and it did not exist before: the event was declared,
    /// advertised to the model with a full action vocabulary, and could never fire, because the
    /// crate's keyboard handler discards HID output reports.
    #[allow(clippy::too_many_arguments)]
    async fn call_llm_on_led_status(
        connection_id: ConnectionId,
        leds: LedState,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<crate::server::usb::keyboard::UsbKeyboardProtocol>,
        server_id: crate::state::ServerId,
    ) {
        {
            let mut conns = connections.lock().await;
            match conns.get_mut(&connection_id) {
                Some(conn) if conn.state != ConnectionState::Idle => {
                    debug!(
                        "USB keyboard connection {} already processing, skipping LED event",
                        connection_id
                    );
                    return;
                }
                Some(conn) => {
                    conn.state = ConnectionState::Processing;
                    conn.led_status = leds.raw;
                }
                None => {}
            }
        }

        let event = Event::new(
            &USB_KEYBOARD_LED_STATUS_EVENT,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
                "num_lock": leds.num_lock(),
                "caps_lock": leds.caps_lock(),
                "scroll_lock": leds.scroll_lock(),
            }),
        );

        match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                let acted =
                    execution_result.protocol_results.len() + execution_result.raw_actions.len();
                info!(
                    "USB keyboard LLM call completed (led_status) for connection {} decision={} actions={}",
                    connection_id,
                    if acted == 0 {
                        "model_no_actions"
                    } else {
                        "model_actions"
                    },
                    acted
                );
            }
            Err(e) => console_error!(
                status_tx,
                "LLM call failed for USB keyboard led_status on connection {} decision=fail_closed_llm_error: \
                 {}; the keyboard stays silent (see the module docs for why silence is the \
                 refusal here)",
                connection_id,
                e
            ),
        }

        let mut conns = connections.lock().await;
        if let Some(conn) = conns.get_mut(&connection_id) {
            conn.state = ConnectionState::Idle;
        }
    }

    /// Call LLM when the USB/IP host detaches.
    ///
    /// `usb_keyboard_detached` is declared `with_no_actions()`, so the model's vocabulary
    /// here is the common action set (`show_message`, memory operations); there is no
    /// wire left to write to.
    async fn call_llm_on_detach(
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<crate::server::usb::keyboard::UsbKeyboardProtocol>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        {
            let mut conns = connections.lock().await;
            if let Some(conn_data) = conns.get_mut(&connection_id) {
                conn_data.state = ConnectionState::Processing;
            }
        }

        let event = Event::new(
            &USB_KEYBOARD_DETACHED_EVENT,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
            }),
        );

        let result = call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await;

        match &result {
            Err(e) => console_error!(
                status_tx,
                "LLM call failed for USB keyboard detach on connection {} decision=fail_closed_llm_error: {}",
                connection_id,
                e
            ),
            Ok(execution_result) => {
                let acted =
                    execution_result.protocol_results.len() + execution_result.raw_actions.len();
                info!(
                    "USB keyboard detach LLM call completed for connection {} decision={} actions={}",
                    connection_id,
                    if acted == 0 {
                        "model_no_actions"
                    } else {
                        "model_actions"
                    },
                    acted
                );
            }
        }

        let mut conns = connections.lock().await;
        if let Some(conn_data) = conns.get_mut(&connection_id) {
            conn_data.state = ConnectionState::Idle;
        }

        Ok(())
    }

    /// Call LLM when device is attached
    async fn call_llm_on_attach(
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<crate::server::usb::keyboard::UsbKeyboardProtocol>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        // Check if already processing
        {
            let conns = connections.lock().await;
            if let Some(conn_data) = conns.get(&connection_id) {
                if conn_data.state != ConnectionState::Idle {
                    debug!(
                        "USB keyboard connection {} already processing, skipping LLM call",
                        connection_id
                    );
                    return Ok(());
                }
            }
        }

        // Set state to processing
        {
            let mut conns = connections.lock().await;
            if let Some(conn_data) = conns.get_mut(&connection_id) {
                conn_data.state = ConnectionState::Processing;
            }
        }

        // Get instruction and memory
        let (_instruction, _memory) = {
            if let Some(server) = app_state.get_server(server_id).await {
                (server.instruction.clone(), String::new())
            } else {
                return Err(anyhow::anyhow!("Server not found"));
            }
        };

        // Create attached event
        let event = Event::new(
            &USB_KEYBOARD_ATTACHED_EVENT,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
            }),
        );

        info!(
            "Calling LLM for USB keyboard attached event on connection {}",
            connection_id
        );

        // Call LLM
        let result = call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await;

        // Process result
        match result {
            Ok(execution_result) => {
                // Actions have already been executed by call_llm. Whether the model actually
                // asked for keystrokes is the distinction an operator needs in the log: a
                // model that answered with nothing looks exactly like a working keyboard
                // nobody is typing on, and so does a backend outage. Tag all three.
                let acted =
                    execution_result.protocol_results.len() + execution_result.raw_actions.len();
                if acted == 0 {
                    info!(
                        "USB keyboard LLM call completed for connection {} decision=model_no_actions (nothing typed)",
                        connection_id
                    );
                } else {
                    info!(
                        "USB keyboard LLM call completed for connection {} decision=model_actions actions={}",
                        connection_id, acted
                    );
                }

                // Set state back to idle
                let mut conns = connections.lock().await;
                if let Some(conn_data) = conns.get_mut(&connection_id) {
                    conn_data.state = ConnectionState::Idle;
                }
            }
            Err(e) => {
                // Silence is the correct wire behaviour here, and it is deliberate — see the
                // module docs. What must not happen is that it goes unrecorded, so this is
                // dual-logged at ERROR rather than only reaching `netget.log`.
                console_error!(
                    status_tx,
                    "LLM call failed for USB keyboard connection {} decision=fail_closed_llm_error: {}; no \
                     HID report will be sent, so the host sees a keyboard nobody is typing on",
                    connection_id,
                    e
                );

                // Set state back to idle
                let mut conns = connections.lock().await;
                if let Some(conn_data) = conns.get_mut(&connection_id) {
                    conn_data.state = ConnectionState::Idle;
                }
            }
        }

        Ok(())
    }
}
