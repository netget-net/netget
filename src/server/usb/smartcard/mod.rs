//! USB Smart Card (CCID) server — a virtual chip card interface device over USB/IP.
//!
//! NetGet exports a **real USB CCID class device** (interface class `0x0B`). A Linux host that
//! imports it and runs `pcscd` sees a card reader with a card in it; anything that speaks
//! USB/IP over TCP can drive it with no kernel module.
//!
//! This replaced a `vpicc`/`vpcd` design that never ran: `Server::spawn` was
//! `bail!("not yet implemented")`, so the protocol was `Incomplete` and unreachable. The
//! `usbip` 0.9 upgrade (0.3 pinned tokio 0.3 and panicked "there is no reactor running" on
//! every attach) made the USB/IP path viable, and CCID removes the external daemon entirely.
//!
//! ## Layers
//!
//! ```text
//! USB/IP over TCP                       ← usbip::handler on the socket we accepted
//!   └─ USB CCID class 0x0B              ← handler.rs (UsbInterfaceHandler)
//!        └─ ISO 7816-4 command APDUs    ← apdu.rs
//!             └─ the handler's answer   ← call_llm / script / static
//! ```
//!
//! ## Who decides what
//!
//! Rust owns the CCID framing, the sequence numbers, the slot state machine and the APDU
//! parsing. The **handler** owns everything the card says: the ATR (`set_atr`), whether a card
//! is in the slot (`set_card_present`), and every response APDU (`respond_to_apdu`). There is
//! no file system, no PIN store and no key store here — the previous implementation had all
//! three, which is storage inside a protocol and the root CLAUDE.md forbids it.
//!
//! ## Fail closed
//!
//! If the handler errors, returns no `respond_to_apdu`, or returns one that cannot be decoded,
//! the card answers **`6F00`** (ISO 7816-4 "no precise diagnosis") and logs at ERROR. It never
//! falls through to `9000`, so the model's own refusal (`6982`, `6A82`, …) stays structurally
//! distinguishable from the model having said nothing.
//!
//! ## No connection state machine, deliberately
//!
//! `XfrBlock` payloads arrive on one channel and are answered one at a time before the next is
//! taken, so a connection can never have two handler calls in flight and there is nothing to
//! reassemble — the CCID header carries its own length.

pub mod actions;
pub mod apdu;
pub mod ccid;
pub mod handler;

pub use actions::UsbSmartCardProtocol;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};
use crate::server::connection::ConnectionId;
use crate::server::usb::guard::{MAX_USBIP_CONNECTIONS, USBIP_NO_REFUSAL};
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error};

use actions::{
    USB_SMARTCARD_APDU_RECEIVED_EVENT, USB_SMARTCARD_ATTACHED_EVENT, USB_SMARTCARD_DETACHED_EVENT,
    USB_SMARTCARD_READER_READY_EVENT,
};
use apdu::{ApduCommand, ApduResponse};
use handler::{CardState, PendingApdu, UsbCcidHandler};

/// Answer To Reset used until the handler calls `set_atr`.
///
/// `3B 90 11 00` is a minimal, valid, T=0-only ATR: TS direct convention, T0 announcing TA1
/// and TD1 with no historical bytes, TA1 = 372/1, TD1 = 0 (protocol T=0, no further interface
/// bytes). T=0-only ATRs carry no TCK, so there is no checksum to get wrong.
const DEFAULT_ATR: &[u8] = &[0x3B, 0x90, 0x11, 0x00];

/// Boxed interface handler as `usbip` wants it.
type SharedUsbHandler = Arc<StdMutex<Box<dyn usbip::UsbInterfaceHandler + Send>>>;

pub struct UsbSmartCardServer;

impl UsbSmartCardServer {
    /// Bind the USB/IP listener and start exporting the virtual reader.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        card_type: Option<String>,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        let card_type = card_type.unwrap_or_else(|| "generic".to_string());

        // Bind before anything else so a port conflict is reported as a startup failure
        // rather than a server that claims to be Running with no socket.
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!(
            "USB smart card reader listening on {local_addr} (card_type={card_type}) - \
             attach with: sudo usbip attach -r {} -b 0-0-0",
            local_addr.ip()
        ));

        let card = Arc::new(StdMutex::new(CardState {
            atr: DEFAULT_ATR.to_vec(),
            card_present: true,
        }));
        let protocol = Arc::new(UsbSmartCardProtocol::new());

        // Configure the card before the first host can reach it.
        let ready_event = Event::new(
            &USB_SMARTCARD_READER_READY_EVENT,
            json!({
                "listen_addr": local_addr.to_string(),
                "card_type": card_type,
                "atr_hex": hex::encode_upper(DEFAULT_ATR),
            }),
        );
        // Opening a socket must not require the model to be reachable: the LLM answers
        // traffic, it does not open listeners. This call used to propagate with `?`, so an
        // Ollama outage made `spawn()` return `Err` and the reader never started at all.
        //
        // The reader is fully usable without it — `card` already holds `DEFAULT_ATR` and
        // `card_present: true`, and every APDU from the host still goes through `call_llm`
        // with its own failure handling — so a failure here means "unconfigured, not broken".
        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            None, // Server-level event, no connection yet
            &ready_event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution) => {
                for message in execution.messages {
                    let _ = status_tx.send(message);
                }
                Self::apply_card_config(execution.protocol_results, &card, None, &status_tx);
            }
            Err(e) => {
                Log::new(Some(&status_tx)).error(format!(
                    "USB smart card startup configuration failed ({}); the reader is listening \
                     on {} with the default ATR {} and a card inserted",
                    e,
                    local_addr,
                    hex::encode_upper(DEFAULT_ATR)
                ));
            }
        }

        {
            let snapshot = lock_card(&card);
            debug!(
                "Virtual smart card configured: atr={}, card_present={}",
                hex::encode_upper(&snapshot.atr),
                snapshot.card_present
            );
        }

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
                let (stream, remote_addr, permit) = match accept_bounded(
                    &listener,
                    &limiter,
                    USBIP_NO_REFUSAL,
                    "USB smart card",
                    Some(&status_tx),
                )
                .await
                {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // A persistent accept error (EMFILE, socket torn down) recurs
                        // immediately, so continuing spins a hot loop on an unbounded status
                        // channel. Give up the listener instead.
                        Log::new(Some(&status_tx)).error(format!(
                            "USB smart card accept failed, stopping accept loop: {}",
                            e
                        ));
                        break;
                    }
                };

                let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
                info!(
                    "USB/IP connection {} from {} (USB smart card)",
                    connection_id, remote_addr
                );

                {
                    use crate::state::server::{
                        ConnectionState, ConnectionStatus, ProtocolConnectionInfo,
                    };
                    let now = crate::utils::clock::Instant::now();
                    let conn_state = ConnectionState {
                        id: connection_id,
                        remote_addr,
                        local_addr: stream.local_addr().unwrap_or(local_addr),
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        last_activity: now,
                        status: ConnectionStatus::Active,
                        status_changed_at: now,
                        protocol_info: ProtocolConnectionInfo::new(json!({
                            "transport": "usbip",
                            "usb_class": "ccid",
                            "card_type": card_type,
                        })),
                    };
                    app_state
                        .add_connection_to_server(server_id, conn_state)
                        .await;
                }
                let _ = status_tx.send("__UPDATE_UI__".to_string());

                let llm_client = llm_client.clone();
                let conn_app_state = app_state.clone();
                let status_tx = status_tx.clone();
                let card = card.clone();
                let protocol = protocol.clone();
                let card_type = card_type.clone();
                // Tracked, not detached: stop_server must abort this task too.
                let task_owner = app_state.clone();
                task_owner
                    .spawn_server_task(server_id, async move {
                        // Held for the life of the connection: dropping it early releases the
                        // slot while the device is still exported.
                        let _permit = permit;
                        if let Err(e) = Self::handle_connection(
                            stream,
                            connection_id,
                            server_id,
                            card,
                            card_type,
                            llm_client,
                            conn_app_state.clone(),
                            status_tx.clone(),
                            protocol,
                            deadlines,
                        )
                        .await
                        {
                            console_error!(
                                status_tx,
                                "USB smart card connection {} error: {}",
                                connection_id,
                                e
                            );
                        }
                        conn_app_state
                            .close_connection_on_server(server_id, connection_id)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                    })
                    .await;
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Drive one USB/IP session and the CCID exchange that hangs off it.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        connection_id: ConnectionId,
        server_id: ServerId,
        card: Arc<StdMutex<CardState>>,
        card_type: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<UsbSmartCardProtocol>,
        deadlines: crate::server::usb::guard::UsbIpDeadlines,
    ) -> Result<()> {
        // `handle_urb` is synchronous and cannot await an LLM call, so XfrBlock payloads cross
        // to this task on a channel and the answer is queued back on the handler.
        let (apdu_tx, mut apdu_rx) = mpsc::unbounded_channel::<PendingApdu>();

        let ccid_handler: SharedUsbHandler = Arc::new(StdMutex::new(Box::new(UsbCcidHandler::new(
            card.clone(),
            apdu_tx,
        ))
            as Box<dyn usbip::UsbInterfaceHandler + Send>));

        let device = usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::SmartCard as u8,
            0x00, // bInterfaceSubClass: no subclass
            0x00, // bInterfaceProtocol: bulk transfer, CCID rev 1.1
            Some("NetGet Virtual CCID Reader"),
            UsbCcidHandler::endpoints(),
            ccid_handler.clone(),
        );

        let usbip_server = Arc::new(usbip::UsbIpServer::new_simulated(vec![device]));

        // Not `usbip::handler(&mut stream, ...)` directly: the crate allocates from the peer's
        // `transfer_buffer_length` and `number_of_packets` without checking either, on a socket
        // USB/IP never authenticates. `run_guarded_usbip` screens both before a byte reaches it
        // -- see `src/server/usb/guard.rs`.
        //
        // The attach event hangs off `import_rx`, not off the accept: see the loop below.
        let guard_status_tx = status_tx.clone();
        let (import_tx, mut import_rx) = tokio::sync::oneshot::channel();
        // Held in `AbortOnDrop`: this connection task is what `stop_server` aborts, and the abort
        // drops the handle the `select!` below awaits. A dropped `JoinHandle` detaches its task
        // rather than ending it, so without the guard the USB/IP session outlived the stop,
        // still holding the peer's socket.
        let mut usbip_task = crate::utils::task_guard::AbortOnDrop(tokio::spawn(async move {
            match crate::server::usb::guard::run_guarded_usbip(
                stream,
                usbip_server,
                "USB smart card",
                connection_id.to_string(),
                guard_status_tx,
                Some(import_tx),
                deadlines,
            )
            .await
            {
                Ok(()) => debug!(
                    "USB/IP session ended for smart card connection {}",
                    connection_id
                ),
                Err(e) => debug!(
                    "USB/IP session for smart card connection {} ended with error: {}",
                    connection_id, e
                ),
            }
        }));

        // Serve APDUs until the USB/IP session ends. Each is answered before the next is
        // taken, so there is never more than one handler call in flight per connection.
        //
        // The attach event is raised here rather than on the accept. USB/IP authenticates
        // nothing, so a bare TCP connect must cost nothing: `import_rx` fires only once the
        // screen has admitted an `OP_REQ_IMPORT`, which is the first moment the peer has asked
        // for the reader. `import_pending` is the select! guard — a `oneshot::Receiver` must not
        // be polled again once it has resolved — and `imported` is the record, because the
        // detach event is the other half of an attachment and must not fire without one.
        let mut import_pending = true;
        let mut imported = false;
        loop {
            tokio::select! {
                attached = &mut import_rx, if import_pending => {
                    import_pending = false;
                    if attached.is_ok() {
                        imported = true;
                        // Tell the handler a host is here, and let it reconfigure the card for
                        // this session.
                        let (atr_hex, card_present) = {
                            let snapshot = lock_card(&card);
                            (hex::encode_upper(&snapshot.atr), snapshot.card_present)
                        };
                        let attached_event = Event::new(
                            &USB_SMARTCARD_ATTACHED_EVENT,
                            json!({
                                "connection_id": connection_id.to_string(),
                                "card_type": card_type,
                                "card_present": card_present,
                                "atr_hex": atr_hex,
                            }),
                        );
                        match call_llm(
                            &llm_client,
                            &app_state,
                            server_id,
                            Some(connection_id),
                            &attached_event,
                            protocol.as_ref(),
                        )
                        .await
                        {
                            Ok(execution) => {
                                for message in execution.messages {
                                    let _ = status_tx.send(message);
                                }
                                Self::apply_card_config(
                                    execution.protocol_results,
                                    &card,
                                    Some(&ccid_handler),
                                    &status_tx,
                                );
                                info!(
                                    "USB smart card LLM call completed for connection {} (attach)",
                                    connection_id
                                );
                            }
                            Err(e) => {
                                console_error!(
                                    status_tx,
                                    "USB smart card attach handler failed for {}: {}",
                                    connection_id,
                                    e
                                );
                            }
                        }
                    }
                }
                pending = apdu_rx.recv() => {
                    let Some(pending) = pending else { break };
                    let response = Self::answer_apdu(
                        &pending,
                        connection_id,
                        server_id,
                        &card_type,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        protocol.as_ref(),
                    )
                    .await;

                    let status_word = response.status_word();
                    let bytes = response.into_bytes();
                    let _ = status_tx.send(format!(
                        "→ USB smart card response SW={} ({} data byte(s)) to {}",
                        status_word,
                        bytes.len().saturating_sub(2),
                        connection_id
                    ));
                    if with_ccid_handler(&ccid_handler, |h| {
                        h.queue_apdu_response(pending.slot, pending.seq, &bytes)
                    })
                    .is_none()
                    {
                        console_error!(
                            status_tx,
                            "USB smart card could not reach the CCID handler for {}; the host \
                             will not get an answer to seq {}",
                            connection_id,
                            pending.seq
                        );
                    }
                }
                _ = &mut usbip_task.0 => break,
            }
        }

        info!(
            "USB smart card host detached on connection {}",
            connection_id
        );

        // Only for a host that actually attached: a peer that opened a socket and closed it
        // again detached nothing.
        if imported {
            let detached_event = Event::new(
                &USB_SMARTCARD_DETACHED_EVENT,
                json!({ "connection_id": connection_id.to_string() }),
            );
            match call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &detached_event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution) => {
                    for message in execution.messages {
                        let _ = status_tx.send(message);
                    }
                    info!(
                        "USB smart card LLM call completed for connection {} (detach)",
                        connection_id
                    );
                }
                Err(e) => {
                    console_error!(
                        status_tx,
                        "USB smart card detach handler failed for {}: {}",
                        connection_id,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// Raise `usb_smartcard_apdu_received` and turn the handler's answer into a response APDU.
    ///
    /// Fails **closed**: a malformed command APDU is answered `6700` without reaching the
    /// handler, and a handler that errors, says nothing, or returns something undecodable gets
    /// `6F00`. Never `9000`.
    #[allow(clippy::too_many_arguments)]
    async fn answer_apdu(
        pending: &PendingApdu,
        connection_id: ConnectionId,
        server_id: ServerId,
        card_type: &str,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &UsbSmartCardProtocol,
    ) -> ApduResponse {
        let command = match ApduCommand::parse(&pending.apdu) {
            Ok(command) => command,
            Err(e) => {
                console_error!(
                    status_tx,
                    "USB smart card host {} sent a malformed APDU: {}",
                    connection_id,
                    e
                );
                return ApduResponse::wrong_length();
            }
        };

        let mut event_data = json!({
            "connection_id": connection_id.to_string(),
            "card_type": card_type,
            "ins_name": command.ins_name(),
            "cla": format!("{:02X}", command.cla),
            "ins": format!("{:02X}", command.ins),
            "p1": format!("{:02X}", command.p1),
            "p2": format!("{:02X}", command.p2),
            "lc": command.data.len(),
            "data_hex": hex::encode_upper(&command.data),
            "le": command.le,
        });
        if let Some(map) = event_data.as_object_mut() {
            if let Some(text) = apdu::printable_text(&command.data) {
                map.insert("data_text".into(), json!(text));
            }
            if command.is_select_by_aid() {
                map.insert(
                    "application_id".into(),
                    json!(hex::encode_upper(&command.data)),
                );
            }
        }

        let event = Event::new(&USB_SMARTCARD_APDU_RECEIVED_EVENT, event_data);
        console_debug!(
            status_tx,
            "USB smart card {} on {} (Lc={}, Le={:?})",
            command.ins_name(),
            connection_id,
            command.data.len(),
            command.le
        );

        let execution = match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol,
        )
        .await
        {
            Ok(execution) => execution,
            Err(e) => {
                // `decision=` tags, as `src/server/radius/` does. 6F00 is what the card
                // answers whether the model refused, said nothing, or could not be reached,
                // so the wire cannot carry the distinction and the log must.
                console_error!(
                    status_tx,
                    "USB smart card handler failed for {} on {} \
                     decision=fail_closed_llm_error, answering 6F00: {}",
                    event.id(),
                    connection_id,
                    e
                );
                return ApduResponse::card_error();
            }
        };

        for message in execution.messages {
            let _ = status_tx.send(message);
        }

        let mut response = None;
        let mut results = Vec::new();
        flatten_results(execution.protocol_results, &mut results);
        for result in results {
            let ActionResult::Custom { name, data } = result else {
                continue;
            };
            if name != "respond_to_apdu" {
                continue;
            }
            match decode_apdu_response(&data) {
                Ok(decoded) => {
                    if response.is_none() {
                        response = Some(decoded);
                    } else {
                        console_error!(
                            status_tx,
                            "USB smart card handler returned more than one respond_to_apdu for \
                             {}; ignoring the extra one",
                            connection_id
                        );
                    }
                }
                Err(e) => {
                    console_error!(
                        status_tx,
                        "USB smart card respond_to_apdu could not be decoded on {} \
                         decision=fail_closed_undecodable, falling through to 6F00: {}",
                        connection_id,
                        e
                    );
                }
            }
        }

        match response {
            Some(response) => response,
            None => {
                console_error!(
                    status_tx,
                    "USB smart card handler produced no respond_to_apdu for {} on {} \
                     decision=model_silent, answering 6F00",
                    event.id(),
                    connection_id
                );
                ApduResponse::card_error()
            }
        }
    }

    /// Apply `set_atr` / `set_card_present` results to the shared card state, and tell a live
    /// CCID handler about a slot change so the host is notified.
    fn apply_card_config(
        results: Vec<ActionResult>,
        card: &Arc<StdMutex<CardState>>,
        ccid_handler: Option<&SharedUsbHandler>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let mut flattened = Vec::new();
        flatten_results(results, &mut flattened);
        for result in flattened {
            let ActionResult::Custom { name, data } = result else {
                continue;
            };
            match name.as_str() {
                "set_atr" => match decode_atr(&data) {
                    Ok(atr) => {
                        let atr_hex = hex::encode_upper(&atr);
                        lock_card(card).atr = atr;
                        Log::new(Some(status_tx))
                            .info(format!("USB smart card ATR set: {atr_hex}"));
                    }
                    Err(e) => {
                        console_error!(status_tx, "USB smart card set_atr rejected: {}", e);
                    }
                },
                "set_card_present" => match data.get("present").and_then(|v| v.as_bool()) {
                    Some(present) => {
                        lock_card(card).card_present = present;
                        if let Some(handler) = ccid_handler {
                            with_ccid_handler(handler, |h| h.note_slot_change());
                        }
                        Log::new(Some(status_tx)).info(format!(
                            "USB smart card slot: card {}",
                            if present { "inserted" } else { "removed" }
                        ));
                    }
                    None => {
                        console_error!(
                            status_tx,
                            "USB smart card set_card_present had no boolean 'present'"
                        );
                    }
                },
                "respond_to_apdu" => {
                    console_error!(
                        status_tx,
                        "USB smart card respond_to_apdu is only valid in response to \
                         usb_smartcard_apdu_received; ignoring it"
                    );
                }
                other => {
                    warn!(
                        "USB smart card ignoring unhandled action result '{}'",
                        other
                    );
                }
            }
        }
    }
}

/// Lock the shared card state, recovering rather than propagating a poisoned mutex: a poisoned
/// lock here would otherwise take the reader down for the rest of the process.
fn lock_card(card: &Arc<StdMutex<CardState>>) -> std::sync::MutexGuard<'_, CardState> {
    match card.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Run `f` against the live CCID handler, or return `None` if it cannot be reached.
fn with_ccid_handler<R>(
    handler: &SharedUsbHandler,
    f: impl FnOnce(&mut UsbCcidHandler) -> R,
) -> Option<R> {
    let mut guard = match handler.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let ccid = guard.as_any().downcast_mut::<UsbCcidHandler>()?;
    Some(f(ccid))
}

/// `ExecutionResult::protocol_results` can nest via `ActionResult::Multiple`; flatten so a
/// nested action is not silently dropped.
fn flatten_results(results: Vec<ActionResult>, out: &mut Vec<ActionResult>) {
    for result in results {
        match result {
            ActionResult::Multiple(nested) => flatten_results(nested, out),
            other => out.push(other),
        }
    }
}

/// Decode the normalised `set_atr` payload produced by `execute_action`.
fn decode_atr(data: &Value) -> Result<Vec<u8>> {
    let atr_hex = data
        .get("atr_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing atr_hex"))?;
    let atr = actions::parse_hex("atr_hex", atr_hex)?;
    if atr.is_empty() {
        return Err(anyhow!("ATR must not be empty"));
    }
    if atr.len() > ccid::MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "ATR is {} bytes; a CCID data block carries at most {}",
            atr.len(),
            ccid::MAX_PAYLOAD_LEN
        ));
    }
    Ok(atr)
}

/// Decode the normalised `respond_to_apdu` payload produced by `execute_action`.
fn decode_apdu_response(data: &Value) -> Result<ApduResponse> {
    let data_hex = data
        .get("data_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let body = if data_hex.is_empty() {
        Vec::new()
    } else {
        actions::parse_hex("data_hex", data_hex)?
    };

    // Response body plus SW1/SW2 has to fit in one CCID data block.
    if body.len() + 2 > ccid::MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "Response body of {} bytes does not fit in a CCID data block (max {} including SW)",
            body.len(),
            ccid::MAX_PAYLOAD_LEN
        ));
    }

    let sw1 = decode_status_byte(data, "sw1")?;
    let sw2 = decode_status_byte(data, "sw2")?;
    Ok(ApduResponse::new(body, sw1, sw2))
}

/// Decode one status byte of a normalised `respond_to_apdu` payload.
///
/// **There is deliberately no default.** `execute_action` already refuses an action that names
/// no status word; this is the second layer, so nothing between the model's answer and the wire
/// can invent one and 9000 cannot be produced except by a handler that spelled it out. A
/// missing field here is an error, which the caller logs as `decision=fail_closed_undecodable`
/// and answers `6F00`.
fn decode_status_byte(data: &Value, field: &str) -> Result<u8> {
    let Some(value) = data.get(field).and_then(|v| v.as_str()) else {
        return Err(anyhow!(
            "'{field}' is missing from the respond_to_apdu payload; a status word is never \
             defaulted, because the default would be success"
        ));
    };
    match actions::parse_hex(field, value)?.as_slice() {
        [byte] => Ok(*byte),
        other => Err(anyhow!(
            "'{field}' must be exactly one hex byte, got {} byte(s)",
            other.len()
        )),
    }
}
