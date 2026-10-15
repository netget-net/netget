//! USB Mass Storage Class (MSC) server implementation
//!
//! This module implements a virtual USB Mass Storage device using the USB/IP protocol.
//! The device uses Bulk-Only Transport (BOT) and SCSI transparent command set to expose
//! a virtual disk that can be read (and, if write protection is off, written) by anything
//! that speaks USB/IP.
//!
//! The USB/IP session runs on the socket netget already accepted (`usbip::handler`). It used
//! to call `usbip::server(remote_addr, ...)` instead, which tries to *bind* a fresh listener
//! to the client's own address and drops the accepted socket on the floor — no host could ever
//! have talked to this device.
//!
//! Event flow:
//!
//! * `usb_msc_attached` — a host connected; the device is exported.
//! * `usb_msc_read` / `usb_msc_write` — the host moved sectors. `handle_urb` is synchronous
//!   and cannot call the LLM, so the handler reports transfers over a channel and this module
//!   raises the events from the connection task. Reads are served from the image first: the
//!   event is a notification, never something the data path waits on.
//! * `usb_msc_detached` — the USB/IP session ended.

pub mod actions;

// Re-export protocol struct for registration
#[cfg(all(unix, feature = "libusb"))]
pub use actions::UsbMscProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub mod disk;
pub mod image_dir;

#[cfg(all(unix, feature = "libusb"))]
pub mod fat16;

#[cfg(all(unix, feature = "libusb"))]
pub mod handler;

#[cfg(all(unix, feature = "libusb"))]
use anyhow::{Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::net::SocketAddr;
#[cfg(all(unix, feature = "libusb"))]
use std::path::PathBuf;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::Arc;
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::{mpsc, Mutex};
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, error, info, warn};

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
    USB_MSC_ATTACHED_EVENT, USB_MSC_DETACHED_EVENT, USB_MSC_READ_EVENT, USB_MSC_WRITE_EVENT,
};
#[cfg(all(unix, feature = "libusb"))]
use handler::MscIoEvent;

/// Default size of a disk image netget has to create itself.
#[cfg(all(unix, feature = "libusb"))]
const DEFAULT_DISK_SIZE_MB: u32 = 10;

/// Connection state for LLM processing
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
}

/// Per-connection data for USB MSC
#[cfg(all(unix, feature = "libusb"))]
#[derive(Clone)]
struct ConnectionData {
    state: ConnectionState,
}

/// USB Mass Storage Class server
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbMscServer;

#[cfg(all(unix, feature = "libusb"))]
impl UsbMscServer {
    /// Spawn the USB MSC server with LLM integration
    ///
    /// This creates a USB/IP server that exports a virtual mass storage device.
    /// The LLM can control the device through actions like mount_disk, eject_disk, etc.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        image_dir: image_dir::ImageDir,
        disk_image: Option<PathBuf>,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // Create and bind TCP server for USB/IP protocol
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("USB Mass Storage server listening on {}", local_addr);
        let _ = status_tx.send(format!(
            "USB Mass Storage server listening on {}",
            local_addr
        ));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(UsbMscProtocol::with_image_dir(image_dir));

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
        let accept_handle = tokio::spawn(async move {
            loop {
                match accept_bounded(
                    &listener,
                    &limiter,
                    USBIP_NO_REFUSAL,
                    "USB MSC",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "USB/IP connection {} from {} (USB MSC device)",
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
                                "write_protect": true,
                                "total_sectors": 0
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
                        let disk_image_clone = disk_image.clone();

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
                                    disk_image_clone,
                                    deadlines,
                                )
                                .await
                                {
                                    error!("USB MSC connection {} error: {}", connection_id, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error (EMFILE, socket torn down) recurs
                        // immediately, so continuing spins a hot loop on an unbounded status
                        // channel. Give up the listener instead.
                        error!("USB MSC accept failed, stopping accept loop: {}", e);
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Drive one USB/IP session and the events that hang off it.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<UsbMscProtocol>,
        server_id: crate::state::ServerId,
        disk_image: Option<PathBuf>,
        deadlines: crate::server::usb::guard::UsbIpDeadlines,
    ) -> Result<()> {
        info!(
            "USB MSC connection {} from {} - mass storage device initialization",
            connection_id, remote_addr
        );

        let write_protect = true; // Start write-protected for safety

        // The medium. Default is an **empty in-memory FAT16 volume**, which the model then
        // fills with `serve_files` in response to `usb_msc_attached`. A path is used only when
        // the caller named one.
        //
        // The default used to be `./tmp/netget_msc_disk.img` in the process's working
        // directory, which made the protocol implement storage: the sectors a host read came
        // from a file netget created, not from the model, and the read/write events were
        // notifications about data nobody had been asked for.
        let (disk, medium) = match &disk_image {
            Some(path) => (
                disk::DiskImage::open_or_create(path, DEFAULT_DISK_SIZE_MB)
                    .with_context(|| format!("Failed to open disk image {}", path.display()))?,
                path.display().to_string(),
            ),
            None => (
                disk::DiskImage::in_memory(
                    fat16::build_volume(&[], fat16::DEFAULT_TOTAL_SECTORS, "NETGET")
                        .context("Failed to build the empty in-memory volume")?,
                )
                .context("Failed to create the in-memory disk")?,
                "in-memory FAT16 volume (use serve_files to fill it)".to_string(),
            ),
        };
        let disk = Arc::new(std::sync::Mutex::new(disk));

        let (total_sectors, bytes_per_sector) = {
            let d = disk
                .lock()
                .map_err(|_| anyhow::anyhow!("disk image mutex poisoned"))?;
            (d.total_sectors(), d.bytes_per_sector())
        };
        let capacity_mb =
            (total_sectors as u64 * bytes_per_sector as u64) as f64 / (1024.0 * 1024.0);

        connections.lock().await.insert(
            connection_id,
            ConnectionData {
                state: ConnectionState::Idle,
            },
        );

        info!(
            "USB MSC device: medium={}, sectors={}, bytes_per_sector={}, write_protect={}",
            medium, total_sectors, bytes_per_sector, write_protect
        );

        // Sector transfers arrive on a synchronous URB callback, which cannot await an LLM
        // call. The channel is the seam between the two.
        let (io_tx, mut io_rx) = mpsc::unbounded_channel::<MscIoEvent>();

        let msc_handler = Arc::new(std::sync::Mutex::new(Box::new(
            handler::UsbMscHandler::new(disk, write_protect).with_io_events(io_tx),
        )
            as Box<dyn usbip::UsbInterfaceHandler + Send>));

        protocol.set_handler(connection_id, msc_handler.clone());

        // Bulk IN 0x81 and bulk OUT 0x01, i.e. endpoint 1 in both directions, as a real
        // BOT device presents itself.
        let device = usbip::UsbDevice::new(0).with_interface(
            0x08, // Mass Storage Class
            0x06, // SCSI Transparent Command Set
            0x50, // Bulk-Only Transport
            Some("NetGet Virtual Disk"),
            vec![
                usbip::UsbEndpoint {
                    address: 0x81,        // EP1 IN (Bulk)
                    attributes: 0x02,     // Bulk transfer
                    max_packet_size: 512, // 512 bytes
                    interval: 0,          // Not used for bulk
                },
                usbip::UsbEndpoint {
                    address: 0x01,        // EP1 OUT (Bulk)
                    attributes: 0x02,     // Bulk transfer
                    max_packet_size: 512, // 512 bytes
                    interval: 0,          // Not used for bulk
                },
            ],
            msc_handler.clone(),
        );

        let usbip_server = Arc::new(usbip::UsbIpServer::new_simulated(vec![device]));

        let _ = status_tx.send(format!(
            "USB MSC device ready: {} ({} sectors, {:.1} MB) - run: sudo usbip attach -r {} -b 0-0-0",
            medium,
            total_sectors,
            capacity_mb,
            remote_addr.ip()
        ));

        // Not `usbip::handler(&mut stream, ...)` directly: the crate allocates from the peer's
        // `transfer_buffer_length` and `number_of_packets` without checking either, on a socket
        // USB/IP never authenticates. `run_guarded_usbip` screens both before a byte reaches it
        // -- see `src/server/usb/guard.rs`.
        //
        // The attach event hangs off `import_rx`, not off the accept: see the loop below.
        let guard_status_tx = status_tx.clone();
        let (import_tx, mut import_rx) = tokio::sync::oneshot::channel();
        let mut usbip_task = tokio::spawn(async move {
            match crate::server::usb::guard::run_guarded_usbip(
                stream,
                usbip_server,
                "USB MSC",
                connection_id.to_string(),
                guard_status_tx,
                Some(import_tx),
                deadlines,
            )
            .await
            {
                Ok(()) => debug!("USB/IP session ended for MSC connection {}", connection_id),
                Err(e) => debug!(
                    "USB/IP session for MSC connection {} ended with error: {}",
                    connection_id, e
                ),
            }
        });

        // Serve the host until the USB/IP session ends. This loop is the whole reason
        // usb_msc_read / usb_msc_write / usb_msc_detached can fire: the previous version
        // parked on sleep(u64::MAX) right here.
        //
        // It is also where the attach event is raised. USB/IP authenticates nothing, so a bare
        // TCP connect must cost nothing: `import_rx` fires only once the screen has admitted an
        // `OP_REQ_IMPORT`, which is the first moment the peer has asked for the disk.
        // `import_pending` is the select! guard — a `oneshot::Receiver` must not be polled again
        // once it has resolved — and `imported` is the record, because the detach event is the
        // other half of an attachment and must not fire without one.
        let mut import_pending = true;
        let mut imported = false;
        loop {
            tokio::select! {
                asked = &mut import_rx, if import_pending => {
                    import_pending = false;
                    if asked.is_ok() {
                        imported = true;
                        Self::call_llm_for_event(
                            connection_id,
                            &llm_client,
                            &app_state,
                            &connections,
                            &protocol,
                            &status_tx,
                            server_id,
                            Event::new(
                                &USB_MSC_ATTACHED_EVENT,
                                serde_json::json!({
                                    "connection_id": connection_id.to_string(),
                                    "remote_addr": remote_addr.to_string(),
                                    "total_sectors": total_sectors,
                                    "capacity_mb": (capacity_mb * 100.0).round() / 100.0,
                                }),
                            ),
                            "attach",
                        )
                        .await;
                    }
                }
                received = io_rx.recv() => {
                    let Some(first) = received else { break };

                    // A single mount does hundreds of sector transfers. One LLM round trip per
                    // URB would be unusable, so drain whatever else is already queued and
                    // report it as one read event and one write event.
                    let mut batch = vec![first];
                    while let Ok(more) = io_rx.try_recv() {
                        batch.push(more);
                    }

                    if let Some(event) = Self::summarize(connection_id, &batch, false) {
                        Self::call_llm_for_event(
                            connection_id, &llm_client, &app_state, &connections, &protocol,
                            &status_tx, server_id, event, "read",
                        )
                        .await;
                    }
                    if let Some(event) = Self::summarize(connection_id, &batch, true) {
                        Self::call_llm_for_event(
                            connection_id, &llm_client, &app_state, &connections, &protocol,
                            &status_tx, server_id, event, "write",
                        )
                        .await;
                    }
                }
                _ = &mut usbip_task => break,
            }
        }

        info!(
            "USB MSC host detached on connection {} from {}",
            connection_id, remote_addr
        );

        // Only for a host that actually attached: a peer that opened a socket and closed it
        // again detached nothing.
        if imported {
            Self::call_llm_for_event(
                connection_id,
                &llm_client,
                &app_state,
                &connections,
                &protocol,
                &status_tx,
                server_id,
                Event::new(
                    &USB_MSC_DETACHED_EVENT,
                    serde_json::json!({ "connection_id": connection_id.to_string() }),
                ),
                "detach",
            )
            .await;
        }

        // The session owned this handler; drop it so a later action cannot mount a disk into
        // a device that no longer exists.
        protocol.remove_handler(connection_id);
        connections.lock().await.remove(&connection_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        Ok(())
    }

    /// Fold a batch of sector transfers into one read (or write) event.
    ///
    /// Returns `None` when the batch contains nothing of that direction.
    fn summarize(connection_id: ConnectionId, batch: &[MscIoEvent], writes: bool) -> Option<Event> {
        let mut first_lba = None;
        let mut sectors: u64 = 0;
        let mut bytes: u64 = 0;

        for io in batch {
            let (lba, s, b) = match (io, writes) {
                (
                    MscIoEvent::Read {
                        lba,
                        sectors,
                        bytes,
                    },
                    false,
                )
                | (
                    MscIoEvent::Write {
                        lba,
                        sectors,
                        bytes,
                    },
                    true,
                ) => (*lba, *sectors, *bytes),
                _ => continue,
            };
            first_lba.get_or_insert(lba);
            sectors += s as u64;
            bytes += b as u64;
        }

        let lba = first_lba?;
        Some(if writes {
            Event::new(
                &USB_MSC_WRITE_EVENT,
                serde_json::json!({
                    "connection_id": connection_id.to_string(),
                    "lba": lba,
                    "sector_count": sectors,
                    "bytes_written": bytes,
                }),
            )
        } else {
            Event::new(
                &USB_MSC_READ_EVENT,
                serde_json::json!({
                    "connection_id": connection_id.to_string(),
                    "lba": lba,
                    "sector_count": sectors,
                    "bytes_read": bytes,
                }),
            )
        })
    }

    /// Raise one event with the LLM, guarding against overlapping calls on the same device.
    ///
    /// On failure the device answers in SCSI's own vocabulary — see the `Err` arm.
    #[allow(clippy::too_many_arguments)]
    async fn call_llm_for_event(
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: &Arc<UsbMscProtocol>,
        status_tx: &mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        event: Event,
        what: &str,
    ) {
        {
            let mut conns = connections.lock().await;
            match conns.get_mut(&connection_id) {
                Some(conn) if conn.state != ConnectionState::Idle => {
                    debug!(
                        "USB MSC connection {} already processing, skipping {} event",
                        connection_id, what
                    );
                    return;
                }
                Some(conn) => conn.state = ConnectionState::Processing,
                // Detach removes the entry before raising its own event; not an error.
                None => {}
            }
        }

        let result = call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await;

        match result {
            // The event kind comes before the id so a test can wait on one specific event
            // with a substring match.
            Ok(_) => info!(
                "USB MSC LLM call completed ({}) for connection {} decision=model_answered",
                what, connection_id
            ),
            Err(e) => {
                // `decision=` tags, as `src/server/radius/` does. SCSI cannot distinguish a
                // refusal from an outage -- both leave the host with NOT READY -- so the log
                // has to, or the two are indistinguishable after the fact.
                console_error!(
                    status_tx,
                    "LLM call failed for USB MSC connection {} ({}) \
                     decision=fail_closed_llm_error: {}",
                    connection_id,
                    what,
                    e
                );

                // `attach` is the only event whose answer the host depends on: it is where the
                // model says what is on the drive (`serve_files`). Without it the device would
                // present an empty but perfectly valid FAT16 volume, and a host cannot tell
                // "the model was unreachable" from "the model served an empty disk" — the
                // fail-open shape this project keeps getting bitten by.
                //
                // So take the medium away. Every command that needs one then fails CHECK
                // CONDITION with NOT READY / MEDIUM NOT PRESENT (02/3A/00), which is exactly
                // what SCSI has to say about a drive with nothing in it. INQUIRY still answers,
                // so the device stays enumerable and the host learns *why* rather than hanging.
                //
                // Read and write events are notifications about transfers the image already
                // served, so there is nothing for the host to be told and nothing to withdraw;
                // detach has no wire left. Those log and stop.
                if what == "attach" && protocol.fail_closed_eject(connection_id) {
                    let _ = status_tx.send(format!(
                        "[ERROR] USB MSC device on {connection_id} reports NOT READY / MEDIUM \
                         NOT PRESENT: the model never said what the drive contains"
                    ));
                    warn!(
                        "USB MSC connection {} ejected the medium after the attach handler \
                         failed; the host will see NOT READY / MEDIUM NOT PRESENT until a \
                         serve_files or mount_disk succeeds",
                        connection_id
                    );
                }
            }
        }

        let mut conns = connections.lock().await;
        if let Some(conn) = conns.get_mut(&connection_id) {
            conn.state = ConnectionState::Idle;
        }
    }
}
