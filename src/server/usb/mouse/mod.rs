//! USB HID Mouse server implementation
//!
//! This module implements a virtual USB HID mouse using the USB/IP protocol.
//! The mouse can be controlled by the LLM to move the cursor, click buttons,
//! and scroll the wheel.
//!
//! ## What was wrong here
//!
//! `handle_connection` took the accepted socket as `_stream` and **dropped it**. It never ran
//! a USB/IP session at all: it logged "NOT YET FUNCTIONAL - waiting for usbip crate mouse
//! support", called the LLM once for `usb_mouse_attached`, and then parked on
//! `sleep(Duration::from_secs(u64::MAX))` forever. So the device could not be enumerated, let
//! alone imported; `usb_mouse_detached` had no emit site and could never fire; and the
//! connection task leaked for the lifetime of the process.
//!
//! The premise was also stale. `usbip` 0.9 still has no mouse handler, but netget has had its
//! own complete one in `handler.rs` — report descriptor, 4-byte reports, automatic release —
//! for some time. Nothing was wired to it.
//!
//! ## When the LLM call fails, the mouse stays still — deliberately
//!
//! A HID mouse owes the host no reply. The host polls the interrupt IN endpoint and is NAKed
//! whenever the pointer is not moving, which is what every mouse does most of the time; there is
//! no HID vocabulary for "the device's brain is unreachable", and STALLing the endpoint is a
//! fault that makes a host reset or unbind the device rather than a refusal it can act on.
//! (`usbip` cannot express it either — returning `Err` from `handle_urb` aborts the session for
//! the whole device.)
//!
//! What matters is the other direction, and it comes for free: a failed LLM call must never move
//! the pointer or press a button. Reports exist only where an action produced them.
//!
//! So the failure is dual-logged at ERROR and nothing is sent.
//! `tests/server/usb_mouse/llm_failure_test.rs` pins both halves.
//!
//! Because the wire looks identical in every failure mode, the log is the only place the cases
//! are distinguishable, and each carries a `decision=` tag: `decision=fail_closed_llm_error`
//! when the backend erred, `decision=no_action` when the model answered with nothing, and
//! `decision=model_action` when it queued reports. There is no `decision=model_reject`: this
//! protocol advertises no verb with which a model can refuse (`wait_for_more` is holding still,
//! which is an action).

pub mod actions;

#[cfg(all(unix, feature = "libusb"))]
pub mod handler;

// Re-export protocol struct for registration
#[cfg(all(unix, feature = "libusb"))]
pub use actions::UsbMouseProtocol;

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
use actions::{USB_MOUSE_ATTACHED_EVENT, USB_MOUSE_DETACHED_EVENT};

/// Connection state for LLM processing
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-connection data for USB mouse
#[cfg(all(unix, feature = "libusb"))]
struct ConnectionData {
    state: ConnectionState,
    #[allow(dead_code)]
    memory: String,
}

/// USB HID Mouse server
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbMouseServer;

#[cfg(all(unix, feature = "libusb"))]
impl UsbMouseServer {
    /// Spawn the USB mouse server with LLM integration
    ///
    /// This creates a USB/IP server that exports a virtual HID mouse device.
    /// The LLM can control the mouse through actions like move, click, and scroll.
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
        info!("USB Mouse server listening on {}", local_addr);
        let _ = status_tx.send(format!("USB Mouse server listening on {}", local_addr));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(crate::server::usb::mouse::UsbMouseProtocol::new());

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
                    "USB mouse",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "USB/IP connection {} from {} (USB mouse device)",
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
                                "state": "WaitingForImport"
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
                                    error!("USB mouse connection {} error: {}", connection_id, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error recurs immediately, so continuing spins a
                        // hot loop on an unbounded status channel. Give up the listener.
                        error!("USB mouse accept failed, stopping accept loop: {}", e);
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
    /// This creates a USB/IP server that exports a virtual HID mouse device.
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
        protocol: Arc<crate::server::usb::mouse::UsbMouseProtocol>,
        server_id: crate::state::ServerId,
        deadlines: crate::server::usb::guard::UsbIpDeadlines,
    ) -> Result<()> {
        info!(
            "USB mouse connection {} from {} - device ready for USB/IP import",
            connection_id, remote_addr
        );

        // Initialize connection data
        connections.lock().await.insert(
            connection_id,
            ConnectionData {
                state: ConnectionState::Idle,
                memory: String::new(),
            },
        );

        let local_addr = stream.local_addr().unwrap_or(remote_addr);

        // netget's own HID mouse handler. `usbip` 0.9 ships a keyboard handler and no mouse
        // equivalent, which is what the "not yet functional" placeholder here was waiting for;
        // handler.rs has implemented one for some time.
        let handler = Arc::new(std::sync::Mutex::new(
            Box::new(handler::UsbHidMouseHandler::new())
                as Box<dyn usbip::UsbInterfaceHandler + Send>,
        ));
        protocol.set_handler(connection_id, handler.clone()).await;

        let device = usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::HID as u8,
            0x01, // Subclass: boot interface
            0x02, // Protocol: mouse
            Some("NetGet Virtual Mouse"),
            handler::UsbHidMouseHandler::endpoints(),
            handler.clone(),
        );

        let usbip_server = Arc::new(usbip::UsbIpServer::new_simulated(vec![device]));

        let _ = status_tx.send(format!(
            "USB mouse ready on {} - run: sudo usbip attach -r {} -b 0-0-0",
            local_addr,
            local_addr.ip()
        ));

        // Drive USB/IP on the socket netget already accepted. Calling `usbip::server()` here
        // would bind a second listener on the client's own address; the previous version did
        // neither and simply dropped the socket.
        // Not `usbip::handler(&mut stream, ...)` directly: the crate allocates from the peer's
        // `transfer_buffer_length` and `number_of_packets` without checking either, on a socket
        // USB/IP never authenticates. `run_guarded_usbip` screens both before a byte reaches it
        // -- see `src/server/usb/guard.rs`.
        //
        // The attach event hangs off `import_rx`, not off the accept: see the loop below.
        let guard_status_tx = status_tx.clone();
        let (import_tx, mut import_rx) = tokio::sync::oneshot::channel();
        let usbip_task = tokio::spawn(async move {
            match crate::server::usb::guard::run_guarded_usbip(
                stream,
                usbip_server,
                "USB mouse",
                connection_id.to_string(),
                guard_status_tx,
                Some(import_tx),
                deadlines,
            )
            .await
            {
                Ok(()) => debug!(
                    "USB/IP session ended for mouse connection {}",
                    connection_id
                ),
                Err(e) => debug!(
                    "USB/IP session for mouse connection {} ended with error: {}",
                    connection_id, e
                ),
            }
        });

        // Serve the host until the USB/IP session ends (host detached, or socket closed). This
        // replaced `sleep(u64::MAX)`, which is why usb_mouse_detached could never fire.
        //
        // The attach event is raised here rather than on the accept. USB/IP authenticates
        // nothing, so a bare TCP connect must cost nothing: `import_rx` fires only once the
        // screen has admitted an `OP_REQ_IMPORT`, which is the first moment the peer has asked
        // for the mouse. `import_pending` is the select! guard — a `oneshot::Receiver` must not
        // be polled again once it has resolved — and `imported` is the record, because the
        // detach event is the other half of an attachment and must not fire without one.
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
                                "Failed to call LLM on mouse attach for connection {}: {}",
                                connection_id, e
                            );
                        }
                    }
                }
                _ = &mut usbip_task => break,
            }
        }

        info!(
            "USB mouse host detached on connection {} from {}",
            connection_id, remote_addr
        );

        // Only for a host that actually attached: a peer that opened a socket and closed it
        // again detached nothing.
        if imported {
            Self::call_llm_on_detach(
                connection_id,
                &llm_client,
                &app_state,
                &status_tx,
                &connections,
                &protocol,
                server_id,
            )
            .await;
        }

        // The USB/IP session owned this handler; drop it so a later action cannot move a mouse
        // that no longer exists.
        protocol.remove_handler(connection_id).await;
        connections.lock().await.remove(&connection_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        Ok(())
    }

    /// Raise `usb_mouse_detached` once the USB/IP session has ended.
    ///
    /// This is the event's only emit site, and it did not exist before. The event is declared
    /// `with_no_actions()`: there is no wire left to write to, so the model's vocabulary here is
    /// the common action set.
    async fn call_llm_on_detach(
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<crate::server::usb::mouse::UsbMouseProtocol>,
        server_id: crate::state::ServerId,
    ) {
        {
            let mut conns = connections.lock().await;
            if let Some(conn) = conns.get_mut(&connection_id) {
                conn.state = ConnectionState::Processing;
            }
        }

        let event = Event::new(
            &USB_MOUSE_DETACHED_EVENT,
            serde_json::json!({ "connection_id": connection_id.to_string() }),
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
                let acted = !execution_result.protocol_results.is_empty()
                    || !execution_result.raw_actions.is_empty();
                info!(
                    "USB mouse LLM call completed (detach) for connection {} decision={}",
                    connection_id,
                    if acted { "model_action" } else { "no_action" }
                )
            }
            Err(e) => console_error!(
                status_tx,
                "LLM call failed for USB mouse detach on connection {} \
                 decision=fail_closed_llm_error: {}",
                connection_id,
                e
            ),
        }

        let mut conns = connections.lock().await;
        if let Some(conn) = conns.get_mut(&connection_id) {
            conn.state = ConnectionState::Idle;
        }
    }

    /// Call LLM when device is attached
    async fn call_llm_on_attach(
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<crate::server::usb::mouse::UsbMouseProtocol>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        // Check if already processing
        {
            let conns = connections.lock().await;
            if let Some(conn_data) = conns.get(&connection_id) {
                if conn_data.state != ConnectionState::Idle {
                    debug!(
                        "USB mouse connection {} already processing, skipping LLM call",
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
            &USB_MOUSE_ATTACHED_EVENT,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
            }),
        );

        info!(
            "Calling LLM for USB mouse attached event on connection {}",
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
                // Actions have already been executed by call_llm. Distinguish "the model asked
                // for pointer movement" from "the model answered with nothing" in the log: on
                // the wire the two are identical (a mouse that does not move), so the log is
                // the only place an operator can tell them apart. This protocol has no verb
                // that refuses, so `decision=model_reject` cannot occur here; `wait_for_more`
                // is the model deliberately holding still and counts as an action.
                let acted = !execution_result.protocol_results.is_empty()
                    || !execution_result.raw_actions.is_empty();
                info!(
                    "USB mouse LLM call completed for connection {} decision={} ({} action \
                     results)",
                    connection_id,
                    if acted { "model_action" } else { "no_action" },
                    execution_result.protocol_results.len()
                );

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
                    "LLM call failed for USB mouse connection {} decision=fail_closed_llm_error: \
                     {}; no HID report will be sent, so the host's pointer does not move",
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
