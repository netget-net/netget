//! USB FIDO2/U2F Security Key server implementation
//!
//! A virtual FIDO2/U2F security key exported over USB/IP. The device presents an HID interface
//! (class 0x03) speaking CTAPHID, and answers CTAP1 (U2F) and CTAP2 (FIDO2) commands. The one
//! decision the model makes is the one a human makes on a real key: **approve or deny this
//! registration / authentication**.
//!
//! ## What was wrong here, and is worth remembering
//!
//! This protocol was registered, advertised as `Experimental`, and could not work in any way:
//!
//! 1. **No LLM integration at all.** `spawn_with_llm_actions` took `_llm_client` and
//!    `_app_state` and used neither. `get_sync_actions()` returned `vec![]` and did not
//!    delegate, so the model had no vocabulary. All three declared events had zero emit sites.
//! 2. **The model-facing actions panicked.** `execute_action({"type":"approve_request"})` did
//!    `tokio::runtime::Handle::current().block_on(...)` — *"Cannot block the current thread from
//!    within a runtime"* — and the event's own example taught the model to answer with exactly
//!    that action. The CTAP2 handler did the same thing on every MakeCredential and
//!    GetAssertion.
//! 3. **`spawn` could not report failure.** `usbip::server(listen_addr, …)` was called *inside*
//!    `tokio::spawn`, after `Ok(listen_addr)` had already been returned, so a port conflict was
//!    invisible and the server sat in `Running` having bound nothing.
//!
//! The `block_on` shape is the same one documented in `src/server/usb/msc/handler.rs`: `usbip`
//! calls the synchronous `UsbInterfaceHandler::handle_urb` from a tokio worker, so the whole
//! handler path must be synchronous. It is now.
//!
//! ## How approval works without blocking
//!
//! CTAPHID is asynchronous by design — that is what its `KEEPALIVE(UPNEEDED)` status is for.
//!
//! ```text
//!  host                     handler (sync)              connection task (async)
//!   │  CBOR MakeCredential      │                              │
//!   ├──────────────────────────►│  parse, decide it needs UP   │
//!   │                           ├── ApprovalDetails ──────────►│  open() → approval id
//!   │◄── KEEPALIVE(UPNEEDED) ───┤                              │  raise fido2_register_request
//!   │  (polls IN)               │                              │  call_llm → approve_request
//!   │                           │◄──── resolve(Approved) ──────┤  wait() → decision
//!   │◄── CBOR response ─────────┤  replay the command          │
//! ```
//!
//! Nothing is created or signed before the decision: the handler parses the command, answers
//! the *question*, and only replays it once a decision exists. A denial therefore leaves the
//! credential store exactly as it was, and an unanswered request denies (see `approval.rs`).
//!
//! ## Events
//!
//! * `fido2_device_attached` — a host connected. Informational (`with_no_actions()`).
//! * `fido2_register_request` — a credential is being created. Answer `approve_request` or
//!   `deny_request`.
//! * `fido2_authenticate_request` — an assertion is being requested. Same two actions.
//! * `fido2_device_detached` — the USB/IP session ended. Informational.

pub mod actions;
pub mod approval;
pub mod ctap2;
pub mod ctaphid;
pub mod u2f;

#[cfg(all(unix, feature = "libusb"))]
use anyhow::Result;
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::net::SocketAddr;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::{Arc, Mutex};
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::mpsc;
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
use crate::server::usb::descriptors::FIDO_HID_REPORT_DESCRIPTOR;

#[cfg(all(unix, feature = "libusb"))]
use actions::{
    UsbFido2Protocol, FIDO2_AUTHENTICATE_REQUEST_EVENT, FIDO2_DEVICE_ATTACHED_EVENT,
    FIDO2_DEVICE_DETACHED_EVENT, FIDO2_REGISTER_REQUEST_EVENT,
};
#[cfg(all(unix, feature = "libusb"))]
use approval::{
    ApprovalConfig, ApprovalDecision, ApprovalDetails, ApprovalManager, OperationType, UserPresence,
};
#[cfg(all(unix, feature = "libusb"))]
use ctap2::{Ctap2Handler, Ctap2Outcome};
#[cfg(all(unix, feature = "libusb"))]
use ctaphid::{CtapHidCommand, CtapHidHandler, CtapHidPacket, KeepaliveStatus};
#[cfg(all(unix, feature = "libusb"))]
use u2f::{U2fHandler, U2fOutcome};

/// USB FIDO2 Security Key server
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbFido2Server;

/// A CTAP command parked waiting for a user-presence decision.
#[cfg(all(unix, feature = "libusb"))]
struct ParkedCommand {
    cid: u32,
    cmd: CtapHidCommand,
    /// The raw request, replayed verbatim once the decision arrives. Parsing is pure, so
    /// replaying is exactly equivalent to resuming — and it keeps the two protocol handlers
    /// free of any half-executed state.
    data: Vec<u8>,
}

/// FIDO2 USB/IP HID handler
#[cfg(all(unix, feature = "libusb"))]
pub struct Fido2HidHandler {
    /// CTAPHID protocol handler
    ctaphid: CtapHidHandler,
    /// U2F command handler
    u2f: U2fHandler,
    /// CTAP2 command handler
    ctap2: Ctap2Handler,
    /// Pending response packets
    response_packets: Vec<Vec<u8>>,
    /// Command waiting on a user-presence decision, if any.
    parked: Option<ParkedCommand>,
    /// Where approval questions are posted for the connection task to pick up.
    approval_tx: Option<mpsc::UnboundedSender<ApprovalDetails>>,
    /// Whether CTAP1/U2F (`MSG`) is answered at all.
    support_u2f: bool,
    /// Whether CTAP2/FIDO2 (`CBOR`) is answered at all.
    support_fido2: bool,
}

#[cfg(all(unix, feature = "libusb"))]
impl Fido2HidHandler {
    pub fn new(support_u2f: bool, support_fido2: bool) -> Self {
        Self {
            ctaphid: CtapHidHandler::new(),
            u2f: U2fHandler::new(),
            ctap2: Ctap2Handler::new(),
            response_packets: Vec::new(),
            parked: None,
            approval_tx: None,
            support_u2f,
            support_fido2,
        }
    }

    /// Attach the channel the connection task listens on.
    pub fn with_approvals(mut self, tx: mpsc::UnboundedSender<ApprovalDetails>) -> Self {
        self.approval_tx = Some(tx);
        self
    }

    /// Feed a decision back in and finish the parked command.
    ///
    /// Called by the connection task once the model has answered. A decision that arrives with
    /// nothing parked is a no-op — the host may have cancelled, or the session may have ended.
    pub fn resolve_approval(&mut self, decision: ApprovalDecision) {
        let Some(parked) = self.parked.take() else {
            debug!("FIDO2 approval decision arrived with no parked command");
            return;
        };

        let presence = match decision {
            ApprovalDecision::Approved => UserPresence::Approved,
            ApprovalDecision::Denied => UserPresence::Denied,
        };

        let packets = self.run_command(parked.cid, parked.cmd, &parked.data, presence);
        self.response_packets = packets;
    }

    /// Credentials currently held, for the `list_credentials` action.
    ///
    /// Reports relying party, user name and counter — never a key handle, a credential id or
    /// any key material.
    pub fn describe_credentials(&self) -> Vec<serde_json::Value> {
        let mut out: Vec<serde_json::Value> = self
            .ctap2
            .store()
            .describe_credentials()
            .into_iter()
            .map(|(rp_id, user_name, resident, counter)| {
                serde_json::json!({
                    "protocol": "fido2",
                    "rp_id": rp_id,
                    "user_name": user_name,
                    "resident": resident,
                    "counter": counter,
                })
            })
            .collect();
        out.extend(
            self.u2f
                .store()
                .describe_credentials()
                .into_iter()
                .map(|(label, counter)| {
                    serde_json::json!({
                        "protocol": "u2f",
                        "rp_id": label,
                        "counter": counter,
                    })
                }),
        );
        out
    }

    /// Forget every credential for a relying party. Returns how many were removed.
    pub fn delete_credentials(&mut self, rp_id: &str) -> usize {
        self.ctap2.store_mut().delete_credentials(rp_id)
            + self.u2f.store_mut().delete_credentials(rp_id)
    }

    /// Run one CTAPHID command and produce the packets to hand back.
    ///
    /// `presence` is `Ask` on the first attempt; a command that needs user presence parks
    /// itself and answers KEEPALIVE instead.
    fn run_command(
        &mut self,
        cid: u32,
        cmd: CtapHidCommand,
        data: &[u8],
        presence: UserPresence,
    ) -> Vec<Vec<u8>> {
        debug!(
            "CTAPHID command: {:?}, cid={:#010x}, data_len={}, presence={:?}",
            cmd,
            cid,
            data.len(),
            presence
        );

        let response_data = match cmd {
            CtapHidCommand::Init => {
                // INIT: 8-byte nonce in, nonce + new CID + versions + capabilities out.
                if data.len() < 8 {
                    return vec![CtapHidPacket::build_error(
                        cid,
                        ctaphid::CtapHidError::InvalidLen,
                    )];
                }

                let new_cid = self.ctaphid.allocate_channel();
                let nonce = &data[..8];

                let mut response = Vec::new();
                response.extend_from_slice(nonce); // Echo nonce
                response.extend_from_slice(&new_cid.to_be_bytes()); // New CID
                response.push(2); // CTAPHID protocol version
                response.push(0); // Major device version
                response.push(0); // Minor device version
                response.push(0); // Build device version
                                  // Capabilities: WINK (0x01), plus CBOR (0x04) when CTAP2 is on
                                  // and NMSG (0x08) when CTAP1 is off. A host reads this to
                                  // decide which protocol to speak, so it must follow the
                                  // support flags rather than being a constant.
                let mut capabilities = 0x01u8;
                if self.support_fido2 {
                    capabilities |= 0x04;
                }
                if !self.support_u2f {
                    capabilities |= 0x08;
                }
                response.push(capabilities);

                info!(
                    "CTAPHID INIT: allocated CID {:#010x} (capabilities {:#04x})",
                    new_cid, capabilities
                );
                response
            }

            CtapHidCommand::Ping => {
                debug!("CTAPHID PING: {} bytes", data.len());
                data.to_vec()
            }

            CtapHidCommand::Msg => {
                if !self.support_u2f {
                    warn!("CTAPHID MSG received but U2F support is disabled");
                    return vec![CtapHidPacket::build_error(
                        cid,
                        ctaphid::CtapHidError::InvalidCmd,
                    )];
                }
                debug!("CTAPHID MSG (U2F): processing {} bytes", data.len());
                match self.u2f.process_command(data, presence) {
                    U2fOutcome::Response(bytes) => bytes,
                    U2fOutcome::NeedsApproval(details) => {
                        return self.park(cid, cmd, data, details)
                    }
                }
            }

            CtapHidCommand::Cbor => {
                if !self.support_fido2 {
                    warn!("CTAPHID CBOR received but FIDO2 support is disabled");
                    return vec![CtapHidPacket::build_error(
                        cid,
                        ctaphid::CtapHidError::InvalidCmd,
                    )];
                }
                debug!("CTAPHID CBOR (CTAP2): processing {} bytes", data.len());
                match self.ctap2.process_command(data, presence) {
                    Ctap2Outcome::Response(bytes) => bytes,
                    Ctap2Outcome::NeedsApproval(details) => {
                        return self.park(cid, cmd, data, details)
                    }
                }
            }

            CtapHidCommand::Wink => {
                debug!("CTAPHID WINK");
                Vec::new()
            }

            CtapHidCommand::Cancel => {
                // A cancelled command must not stay parked: the host has moved on, and
                // resolving it later would sign something nobody is waiting for.
                if self.parked.take().is_some() {
                    info!(
                        "CTAPHID CANCEL: dropped the parked command on cid {:#010x}",
                        cid
                    );
                }
                debug!("CTAPHID CANCEL");
                Vec::new()
            }

            _ => {
                warn!("Unsupported CTAPHID command: {:?}", cmd);
                return vec![CtapHidPacket::build_error(
                    cid,
                    ctaphid::CtapHidError::InvalidCmd,
                )];
            }
        };

        self.ctaphid.fragment_response(cid, cmd, &response_data)
    }

    /// Park a command awaiting user presence and answer the host with KEEPALIVE.
    fn park(
        &mut self,
        cid: u32,
        cmd: CtapHidCommand,
        data: &[u8],
        details: ApprovalDetails,
    ) -> Vec<Vec<u8>> {
        let Some(ref tx) = self.approval_tx else {
            // No connection task to ask means no user presence can ever be established.
            // Refuse rather than proceed: an authenticator that signs without presence
            // because nobody was listening is the fail-open shape this codebase keeps
            // getting bitten by.
            warn!(
                "FIDO2 {:?} for '{}' needs user presence but no approval channel is attached; \
                 denying",
                details.operation, details.rp_id
            );
            return self.deny_presence_command(cid, cmd, data);
        };

        info!(
            "FIDO2 {:?} for '{}' parked awaiting user presence",
            details.operation, details.rp_id
        );

        if tx.send(details).is_err() {
            warn!("FIDO2 approval channel closed; denying the request");
            return self.deny_presence_command(cid, cmd, data);
        }

        self.parked = Some(ParkedCommand {
            cid,
            cmd,
            data: data.to_vec(),
        });

        vec![CtapHidPacket::build_keepalive(
            cid,
            KeepaliveStatus::UpNeeded,
        )]
    }

    /// Replay a refused presence request exactly once, without entering dispatch/parking.
    ///
    /// Previously park called run_command again and relied on the CTAP handlers never
    /// returning NeedsApproval for Denied. Keep their normal protocol errors, but refuse
    /// explicitly if that invariant ever regresses; no handler outcome can recurse here.
    fn deny_presence_command(
        &mut self,
        cid: u32,
        cmd: CtapHidCommand,
        data: &[u8],
    ) -> Vec<Vec<u8>> {
        let response = match cmd {
            CtapHidCommand::Msg => match self.u2f.process_command(data, UserPresence::Denied) {
                U2fOutcome::Response(bytes) => bytes,
                U2fOutcome::NeedsApproval(_) => {
                    error!("U2F requested approval after denial; refusing without replay");
                    u2f::U2fResponse::error(u2f::SW_CONDITIONS_NOT_SATISFIED).to_bytes()
                }
            },
            CtapHidCommand::Cbor => match self.ctap2.process_command(data, UserPresence::Denied) {
                Ctap2Outcome::Response(bytes) => bytes,
                Ctap2Outcome::NeedsApproval(_) => {
                    error!("CTAP2 requested approval after denial; refusing without replay");
                    ctap2::Ctap2Response::error(ctap2::Ctap2Status::OperationDenied).to_bytes()
                }
            },
            _ => {
                return vec![CtapHidPacket::build_error(
                    cid,
                    ctaphid::CtapHidError::InvalidCmd,
                )];
            }
        };
        self.ctaphid.fragment_response(cid, cmd, &response)
    }
}

#[cfg(all(unix, feature = "libusb"))]
/// Opaque on purpose.
///
/// `usbip::UsbInterfaceHandler` requires `Debug` as of 0.9. Deriving it would pull the CTAPHID,
/// U2F and CTAP2 handlers into the output, and those hold credential and key material for a
/// security key -- exactly the thing that must not reach a log line. The type name alone
/// satisfies the bound and says nothing it should not.
impl std::fmt::Debug for Fido2HidHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fido2HidHandler { .. }")
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl usbip::UsbInterfaceHandler for Fido2HidHandler {
    fn handle_urb(
        &mut self,
        _interface: &usbip::UsbInterface,
        endpoint: usbip::UsbEndpoint,
        // usbip 0.9 passes the host's declared transfer length. CTAPHID frames are a fixed
        // 64 bytes, so this handler derives its lengths from the frame and not from here.
        _transfer_buffer_length: u32,
        setup: usbip::SetupPacket,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        use crate::server::usb::common::{descriptor_type, hid_request, request, request_type};

        // Control transfers arrive on endpoint 0 in either direction; the crate's control IN
        // endpoint is 0x80, so testing `address == 0` alone misroutes it (the bug MSC had).
        if endpoint.is_ep0() {
            debug!(
                "FIDO2 control request: type={:#04x}, request={:#04x}, value={:#06x}",
                setup.request_type, setup.request, setup.value
            );

            match (setup.request_type, setup.request) {
                // Get HID Report Descriptor
                (
                    request_type::DEVICE_TO_HOST | request_type::STANDARD | request_type::INTERFACE,
                    request::GET_DESCRIPTOR,
                ) => {
                    let desc_type = (setup.value >> 8) as u8;
                    if desc_type == descriptor_type::HID_REPORT {
                        debug!(
                            "GET_DESCRIPTOR: HID Report ({}bytes)",
                            FIDO_HID_REPORT_DESCRIPTOR.len()
                        );
                        Ok(FIDO_HID_REPORT_DESCRIPTOR.to_vec())
                    } else {
                        warn!("Unsupported descriptor type: {:#04x}", desc_type);
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Unsupported descriptor",
                        ))
                    }
                }

                // Get/Set Idle
                (
                    request_type::DEVICE_TO_HOST | request_type::CLASS | request_type::INTERFACE,
                    hid_request::GET_IDLE,
                ) => {
                    debug!("GET_IDLE");
                    Ok(vec![0])
                }
                (
                    request_type::HOST_TO_DEVICE | request_type::CLASS | request_type::INTERFACE,
                    hid_request::SET_IDLE,
                ) => {
                    debug!("SET_IDLE");
                    Ok(vec![])
                }

                // Get/Set Protocol
                (
                    request_type::DEVICE_TO_HOST | request_type::CLASS | request_type::INTERFACE,
                    hid_request::GET_PROTOCOL,
                ) => {
                    debug!("GET_PROTOCOL");
                    Ok(vec![0]) // Report protocol
                }
                (
                    request_type::HOST_TO_DEVICE | request_type::CLASS | request_type::INTERFACE,
                    hid_request::SET_PROTOCOL,
                ) => {
                    debug!("SET_PROTOCOL");
                    Ok(vec![])
                }

                _ => {
                    warn!(
                        "Unsupported FIDO2 control request: type={:#04x}, request={:#04x}",
                        setup.request_type, setup.request
                    );
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Unsupported control request",
                    ))
                }
            }
        } else if endpoint.address & 0x80 == 0 {
            // Interrupt OUT endpoint (host to device)
            debug!(
                "FIDO2 OUT: ep={:#04x}, {} bytes",
                endpoint.address,
                data.len()
            );

            match self.ctaphid.process_packet(data) {
                Ok(Some(message)) => {
                    let (cid, cmd) = (message.cid, message.cmd);
                    let payload = message.into_data();
                    // A second command while one is parked is CTAPHID's channel-busy case. It
                    // must not silently replace the parked one, or a decision meant for the
                    // first request would be applied to the second.
                    if self.parked.is_some() && cmd != CtapHidCommand::Cancel {
                        warn!(
                            "CTAPHID command {:?} on cid {:#010x} while a command is awaiting \
                             user presence; answering CHANNEL_BUSY",
                            cmd, cid
                        );
                        self.response_packets = vec![CtapHidPacket::build_error(
                            cid,
                            ctaphid::CtapHidError::ChannelBusy,
                        )];
                    } else {
                        self.response_packets =
                            self.run_command(cid, cmd, &payload, UserPresence::Ask);
                    }
                }
                Ok(None) => {
                    debug!("CTAPHID: waiting for continuation packets");
                }
                Err(e) => {
                    // Answer on the channel the host used, with the code the refusal names.
                    // Every error used to become INVALID_SEQ on the broadcast channel, so a
                    // host that had declared an unframeable BCNT, or opened one channel too
                    // many, was told its sequence number was wrong on a channel it was not
                    // listening to.
                    let rejection = ctaphid::rejection_of(&e);
                    warn!("CTAPHID packet error: {:#}", e);
                    self.response_packets =
                        vec![CtapHidPacket::build_error(rejection.cid, rejection.error)];
                }
            }

            Ok(vec![])
        } else {
            // Interrupt IN endpoint (device to host)
            if !self.response_packets.is_empty() {
                let packet = self.response_packets.remove(0);
                debug!(
                    "FIDO2 IN: ep={:#04x}, sending {} bytes",
                    endpoint.address,
                    packet.len()
                );
                Ok(packet)
            } else if let Some(ref parked) = self.parked {
                // Still waiting on the model. Say so rather than going silent.
                Ok(CtapHidPacket::build_keepalive(
                    parked.cid,
                    KeepaliveStatus::UpNeeded,
                ))
            } else {
                Ok(vec![])
            }
        }
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        // HID descriptor is returned via GET_DESCRIPTOR on the control endpoint.
        vec![]
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Everything an action needs to reach a *running* FIDO2 server.
///
/// Registered with `AppState::register_server_handle` and looked up by `server_id` in
/// `execute_action_with_state`. This replaces a `LazyLock` global map of approval managers whose
/// lookup was "first value in the map" — with two FIDO2 servers running, actions aimed at one
/// resolved approvals on the other, and the map was never cleaned up.
/// The handler `usbip` holds for one attached host, as this module shares it.
#[cfg(all(unix, feature = "libusb"))]
type SharedHandler = Arc<Mutex<Box<dyn usbip::UsbInterfaceHandler + Send>>>;

#[cfg(all(unix, feature = "libusb"))]
pub struct Fido2ServerHandle {
    pub approvals: Arc<ApprovalManager>,
    handlers: Mutex<HashMap<ConnectionId, SharedHandler>>,
}

#[cfg(all(unix, feature = "libusb"))]
impl Fido2ServerHandle {
    fn new(approvals: Arc<ApprovalManager>) -> Self {
        Self {
            approvals,
            handlers: Mutex::new(HashMap::new()),
        }
    }

    fn set_handler(&self, id: ConnectionId, handler: SharedHandler) {
        self.lock_handlers().insert(id, handler);
    }

    fn remove_handler(&self, id: ConnectionId) {
        self.lock_handlers().remove(&id);
    }

    /// Run `f` against every attached device's handler, collecting the results.
    ///
    /// Credentials live per USB/IP session, so `list_credentials` and `delete_credential` are
    /// answered across all attached hosts rather than picking one arbitrarily.
    pub fn with_each_handler<T>(&self, mut f: impl FnMut(&mut Fido2HidHandler) -> T) -> Vec<T> {
        let handlers: Vec<_> = self.lock_handlers().values().cloned().collect();
        handlers
            .iter()
            .filter_map(|h| {
                let mut guard = h.lock().unwrap_or_else(|p| p.into_inner());
                guard.as_any().downcast_mut::<Fido2HidHandler>().map(&mut f)
            })
            .collect()
    }

    fn lock_handlers(&self) -> std::sync::MutexGuard<'_, HashMap<ConnectionId, SharedHandler>> {
        self.handlers.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbFido2Server {
    /// Spawn the USB FIDO2 server with LLM integration.
    ///
    /// Binds before returning, so a port conflict is an `Err` and the server never reports
    /// `Running` on a listener it does not have.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        support_u2f: Option<bool>,
        support_fido2: Option<bool>,
        auto_approve: Option<bool>,
        approval_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        let support_u2f = support_u2f.unwrap_or(true);
        let support_fido2 = support_fido2.unwrap_or(true);
        if !support_u2f && !support_fido2 {
            anyhow::bail!(
                "usb-fido2 needs at least one of support_u2f / support_fido2; with both false \
                 the device would answer nothing but CTAPHID INIT"
            );
        }

        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let auto_approve = auto_approve.unwrap_or(false);
        let approvals = Arc::new(ApprovalManager::new(ApprovalConfig {
            auto_approve,
            timeout: std::time::Duration::from_secs(approval_timeout_secs.unwrap_or(30)),
            timeout_decision: ApprovalDecision::Denied,
        }));

        let handle = Arc::new(Fido2ServerHandle::new(approvals.clone()));
        app_state
            .register_server_handle(server_id, handle.clone())
            .await;

        info!(
            "USB FIDO2/U2F security key listening on {} (u2f={}, fido2={}, auto_approve={})",
            local_addr, support_u2f, support_fido2, auto_approve
        );
        let _ = status_tx.send(format!(
            "USB FIDO2/U2F security key listening on {} - run: sudo usbip attach -r {} -b 0-0-0",
            local_addr,
            local_addr.ip()
        ));

        let protocol = Arc::new(UsbFido2Protocol::new());
        let task_registrar = app_state.clone();

        // One emulated device per connection, so the cap is small and lives with the screen.
        let limiter = ConnectionLimiter::new(MAX_USBIP_CONNECTIONS);

        let accept_handle = tokio::spawn(async move {
            loop {
                match accept_bounded(
                    &listener,
                    &limiter,
                    USBIP_NO_REFUSAL,
                    "USB FIDO2",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "USB/IP connection {} from {} (FIDO2 security key)",
                            connection_id, remote_addr
                        );

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
                                "supports_u2f": support_u2f,
                                "supports_fido2": support_fido2,
                                "auto_approve": auto_approve,
                            })),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_client = llm_client.clone();
                        let app_state = app_state.clone();
                        let status_tx = status_tx.clone();
                        let protocol = protocol.clone();
                        let handle = handle.clone();

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
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    protocol,
                                    handle,
                                    server_id,
                                    support_u2f,
                                    support_fido2,
                                )
                                .await
                                {
                                    error!("USB FIDO2 connection {} error: {}", connection_id, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error recurs immediately, so continuing spins a
                        // hot loop on an unbounded status channel. Give up the listener.
                        error!("USB FIDO2 accept failed, stopping accept loop: {}", e);
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

    /// Drive one USB/IP session and the approval round trips that hang off it.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<UsbFido2Protocol>,
        handle: Arc<Fido2ServerHandle>,
        server_id: crate::state::ServerId,
        support_u2f: bool,
        support_fido2: bool,
    ) -> Result<()> {
        // The handler asks; this task answers. `handle_urb` is synchronous, so the channel is
        // the seam — the same shape as `usb/msc`'s io_tx.
        let (approval_tx, mut approval_rx) = mpsc::unbounded_channel::<ApprovalDetails>();

        let hid_handler = Arc::new(Mutex::new(Box::new(
            Fido2HidHandler::new(support_u2f, support_fido2).with_approvals(approval_tx),
        )
            as Box<dyn usbip::UsbInterfaceHandler + Send>));

        handle.set_handler(connection_id, hid_handler.clone());

        let device = usbip::UsbDevice::new(0).with_interface(
            0x03, // HID class
            0x00, // No subclass
            0x00, // No protocol
            Some("NetGet FIDO2 Security Key"),
            vec![
                usbip::UsbEndpoint {
                    address: 0x81,       // EP1 IN (interrupt)
                    attributes: 0x03,    // Interrupt transfer
                    max_packet_size: 64, // CTAPHID frame size
                    interval: 5,
                },
                usbip::UsbEndpoint {
                    address: 0x01,    // EP1 OUT (interrupt)
                    attributes: 0x03, // Interrupt transfer
                    max_packet_size: 64,
                    interval: 5,
                },
            ],
            hid_handler.clone(),
        );

        let usbip_server = Arc::new(usbip::UsbIpServer::new_simulated(vec![device]));

        // Run the USB/IP session on the socket netget already accepted. Calling
        // `usbip::server(addr, ...)` here would try to *bind* a second listener and drop this
        // socket, which is what the previous version did.
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
                "USB FIDO2",
                connection_id.to_string(),
                guard_status_tx,
                Some(import_tx),
                // The defaults, argued in `src/server/usb/guard.rs`. The other five USB servers
                // expose them as `first_byte_timeout_secs` / `idle_timeout_secs`; FIDO2 has not
                // declared those startup parameters, so it takes the shipped numbers. Its peer
                // is the same USB/IP client, so the same argument applies to it unchanged.
                crate::server::usb::guard::UsbIpDeadlines::default(),
            )
            .await
            {
                Ok(()) => debug!(
                    "USB/IP session ended for FIDO2 connection {}",
                    connection_id
                ),
                Err(e) => debug!(
                    "USB/IP session for FIDO2 connection {} ended with error: {}",
                    connection_id, e
                ),
            }
        });

        // The attach event is raised in the loop below rather than here. USB/IP authenticates
        // nothing, so a bare TCP connect must cost nothing: `import_rx` fires only once the
        // screen has admitted an `OP_REQ_IMPORT`, which is the first moment the peer has asked
        // for the key. `import_pending` is the select! guard — a `oneshot::Receiver` must not be
        // polled again once it has resolved — and `imported` is the record, because the detach
        // event is the other half of an attachment and must not fire without one.
        let mut import_pending = true;
        let mut imported = false;
        loop {
            tokio::select! {
                attached = &mut import_rx, if import_pending => {
                    import_pending = false;
                    if attached.is_ok() {
                        imported = true;
                        Self::raise(
                            &llm_client,
                            &app_state,
                            &protocol,
                            &status_tx,
                            server_id,
                            connection_id,
                            Event::new(
                                &FIDO2_DEVICE_ATTACHED_EVENT,
                                serde_json::json!({
                                    "connection_id": connection_id.to_string(),
                                    "remote_addr": remote_addr.to_string(),
                                    "supports_u2f": support_u2f,
                                    "supports_fido2": support_fido2,
                                }),
                            ),
                            "attach",
                        )
                        .await;
                    }
                }
                asked = approval_rx.recv() => {
                    let Some(details) = asked else { break };
                    Self::decide(
                        &llm_client,
                        &app_state,
                        &protocol,
                        &handle,
                        &hid_handler,
                        &status_tx,
                        server_id,
                        connection_id,
                        details,
                    )
                    .await;
                }
                _ = &mut usbip_task => break,
            }
        }

        info!(
            "USB FIDO2 host detached on connection {} from {}",
            connection_id, remote_addr
        );

        // Only for a host that actually attached: a peer that opened a socket and closed it
        // again detached nothing.
        if imported {
            Self::raise(
                &llm_client,
                &app_state,
                &protocol,
                &status_tx,
                server_id,
                connection_id,
                Event::new(
                    &FIDO2_DEVICE_DETACHED_EVENT,
                    serde_json::json!({ "connection_id": connection_id.to_string() }),
                ),
                "detach",
            )
            .await;
        }

        handle.remove_handler(connection_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        Ok(())
    }

    /// Ask the model about one request, then feed its decision back into the handler.
    #[allow(clippy::too_many_arguments)]
    async fn decide(
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        protocol: &Arc<UsbFido2Protocol>,
        handle: &Arc<Fido2ServerHandle>,
        hid_handler: &SharedHandler,
        status_tx: &mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        details: ApprovalDetails,
    ) {
        // Open first, so the event can quote the id the model must answer with.
        let (approval_id, rx) = handle
            .approvals
            .open(details.clone(), Some(connection_id.to_string()));

        let event_type = match details.operation {
            OperationType::Register => &FIDO2_REGISTER_REQUEST_EVENT,
            OperationType::Authenticate => &FIDO2_AUTHENTICATE_REQUEST_EVENT,
        };

        let event = Event::new(
            event_type,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
                "approval_id": approval_id,
                "rp_id": details.rp_id,
                "user_name": details.user_name,
                "credential_count": details.credential_count,
            }),
        );

        let what = match details.operation {
            OperationType::Register => "register",
            OperationType::Authenticate => "authenticate",
        };

        let answered = Self::raise(
            llm_client,
            app_state,
            protocol,
            status_tx,
            server_id,
            connection_id,
            event,
            what,
        )
        .await;

        // The LLM call itself failed — an outage, an overload, an unparseable reply. Waiting
        // out `approval_timeout_secs` would get to the same denial, but only after the host has
        // sat on KEEPALIVE(UPNEEDED) for up to 30s for an answer that is never coming. Say it
        // now, in CTAP2's own vocabulary: the parked command is refused and the handler replies
        // `CTAP2_ERR_OPERATION_DENIED` (0x27), or U2F `SW_CONDITIONS_NOT_SATISFIED`.
        //
        // There is deliberately no other branch here. A failed call must never become an
        // approval: nothing below can synthesise an assertion or an attestation, and the
        // denial is the same one an explicit `deny_request` produces. `auto_approve` still
        // wins, because `wait()` short-circuits before reading the channel — that mode is an
        // explicit development opt-in that never consults the model in the first place.
        if !answered {
            match handle.approvals.deny(approval_id) {
                Ok(()) => console_error!(
                    status_tx,
                    "USB FIDO2 {} request {} on connection {} DENIED (fail closed): the model \
                     could not be reached, so the host gets CTAP2_ERR_OPERATION_DENIED rather \
                     than waiting out the approval window",
                    what,
                    approval_id,
                    connection_id
                ),
                // Already resolved (the TUI, or a racing action). Its decision stands.
                Err(e) => debug!(
                    "FIDO2 approval {} was already resolved when the LLM failure path ran: {}",
                    approval_id, e
                ),
            }
        }

        // If the model answered inline, the decision is already on the channel and this
        // returns immediately. Otherwise it waits out the configured window — a user can still
        // approve from the TUI — and denies when it expires.
        let decision = handle.approvals.wait(approval_id, rx).await;

        // `decision=` tags, as `src/server/radius/` does. CTAP2 answers
        // CTAP2_ERR_OPERATION_DENIED whether the model refused, said nothing, or could not be
        // reached, so the wire cannot carry the distinction and the log must -- and on an
        // authenticator that distinction is the difference between a policy decision and an
        // outage that looked like one.
        let tag = match (decision, answered) {
            (ApprovalDecision::Approved, _) => "model_approve",
            (ApprovalDecision::Denied, false) => "fail_closed_llm_error",
            (ApprovalDecision::Denied, true) => "model_reject_or_silent",
        };

        info!(
            "FIDO2 {} request {} on connection {} decision={} ({:?})",
            what, approval_id, connection_id, tag, decision
        );

        let mut guard = hid_handler.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(fido2) = guard.as_any().downcast_mut::<Fido2HidHandler>() {
            fido2.resolve_approval(decision);
        } else {
            error!(
                "FIDO2 handler for connection {} is not a Fido2HidHandler; the decision is lost",
                connection_id
            );
        }
    }

    /// Raise one event with the LLM. Returns whether the call produced an answer at all.
    ///
    /// Unlike the MSC server there is no Idle/Processing gate: a parked command blocks the
    /// device at the CTAPHID layer (a second command gets CHANNEL_BUSY), so overlapping calls
    /// on one connection cannot arise.
    ///
    /// `false` means the *call* failed, which is not the same as the model declining: a
    /// decision the model made arrives as an action and is invisible here. Only `decide` acts
    /// on the return value, and only ever by denying.
    #[allow(clippy::too_many_arguments)]
    async fn raise(
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        protocol: &Arc<UsbFido2Protocol>,
        status_tx: &mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        event: Event,
        what: &str,
    ) -> bool {
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
            // Event kind before the id, so a test can wait on one specific event with a
            // substring match.
            Ok(_) => {
                info!(
                    "USB FIDO2 LLM call completed ({}) for connection {}",
                    what, connection_id
                );
                true
            }
            Err(e) => {
                console_error!(
                    status_tx,
                    "LLM call failed for USB FIDO2 connection {} ({}): {}",
                    connection_id,
                    what,
                    e
                );
                false
            }
        }
    }
}
