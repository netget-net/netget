//! User-presence approval for FIDO2/U2F operations.
//!
//! A security key does not decide anything by itself: a credential is created, or an assertion
//! is signed, only when a human touches the button. This module is where that human is replaced
//! by the model, and it is the one genuinely LLM-shaped decision in the protocol — *should this
//! relying party get a credential / an assertion, right now?*
//!
//! # Why none of this is a `block_on` bridge any more
//!
//! It used to be described as a "sync/async bridge": `handle_urb` is synchronous and is called
//! by `usbip` from a tokio worker, so the CTAP2 handler reached the async approval manager with
//! `tokio::runtime::Handle::current().block_on(...)`. That panics —
//! *"Cannot block the current thread from within a runtime"* — so **every** MakeCredential and
//! GetAssertion killed the connection task, and so did `execute_action("approve_request")` from
//! the model. The same defect is documented for `usb/msc/handler.rs`; this is the second
//! instance of it.
//!
//! There is no bridge now. The seam is CTAPHID itself, which is asynchronous by design: a real
//! authenticator answers the host with `KEEPALIVE(UPNEEDED)` while it waits for the button.
//! So the handler *asks* (returns [`UserPresence::Ask`] as an [`ApprovalDetails`]), the
//! connection task raises the event and awaits the model, and the decision is fed back into the
//! handler, which replays the command. Nothing blocks, and every lock in here is a
//! `std::sync` lock that the synchronous handler and the async connection task can both take.
//!
//! # Fail-closed
//!
//! `timeout_decision` is [`ApprovalDecision::Denied`] and there is no code path that turns a
//! missing answer into an approval. A model that says nothing, a model that errors, and a model
//! that is unreachable all produce a denial — and the model's *explicit* denial is a distinct
//! action (`deny_request`) rather than the absence of one. `auto_approve` exists, is off by
//! default, and has to be asked for by name in `startup_params`.

#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(unix, feature = "libusb"))]
use std::sync::{Arc, Mutex, RwLock};
#[cfg(all(unix, feature = "libusb"))]
use std::time::Duration;
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::oneshot;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{info, warn};

/// Unique ID for an approval request
#[cfg(all(unix, feature = "libusb"))]
pub type ApprovalId = u64;

/// Approval decision
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

/// Type of FIDO2 operation
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Register,
    Authenticate,
}

#[cfg(all(unix, feature = "libusb"))]
impl OperationType {
    /// The event id this operation raises.
    pub fn event_id(&self) -> &'static str {
        match self {
            OperationType::Register => "fido2_register_request",
            OperationType::Authenticate => "fido2_authenticate_request",
        }
    }
}

/// What the model is being asked to decide, in structured fields.
///
/// Deliberately no bytes: no client data hash, no challenge, no credential id. A model cannot
/// reason about those and cannot produce them, and the project rule is that action and event
/// payloads carry structured fields only.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDetails {
    pub operation: OperationType,
    /// Relying party the request is for. CTAP2 carries this as a real domain; U2F only has the
    /// SHA-256 of the origin, so U2F reports `u2f-app:<first 8 hex>` and says so.
    pub rp_id: String,
    /// User name, when the request carries one (CTAP2 MakeCredential does; nothing else does).
    pub user_name: Option<String>,
    /// How many stored credentials already match this relying party.
    pub credential_count: usize,
}

/// Whether a command that needs user presence may proceed.
///
/// The handler is called once with [`Ask`](UserPresence::Ask); if the command needs presence it
/// answers [`ApprovalDetails`] instead of a response, and is called again with the decision.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPresence {
    /// No decision yet. A command requiring presence must ask rather than act.
    Ask,
    /// The model approved this specific request.
    Approved,
    /// The model denied it, or nothing answered in time.
    Denied,
}

/// Pending approval request
#[cfg(all(unix, feature = "libusb"))]
struct PendingApproval {
    id: ApprovalId,
    details: ApprovalDetails,
    connection_id: Option<String>,
    response_tx: oneshot::Sender<ApprovalDecision>,
}

/// Configuration for approval behavior
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// Automatically approve all requests (dev mode). Off unless asked for by name.
    pub auto_approve: bool,
    /// How long to wait for the model's decision.
    pub timeout: Duration,
    /// What an unanswered request becomes. Denied; there is no reason to make this settable
    /// to Approved and every reason not to.
    pub timeout_decision: ApprovalDecision,
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            auto_approve: false,
            timeout: Duration::from_secs(30),
            timeout_decision: ApprovalDecision::Denied,
        }
    }
}

/// Manager for approval requests
#[cfg(all(unix, feature = "libusb"))]
pub struct ApprovalManager {
    config: Arc<RwLock<ApprovalConfig>>,
    pending: Arc<Mutex<HashMap<ApprovalId, PendingApproval>>>,
    next_id: Arc<AtomicU64>,
}

#[cfg(all(unix, feature = "libusb"))]
impl ApprovalManager {
    pub fn new(config: ApprovalConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Whether every request is approved without asking.
    pub fn auto_approve(&self) -> bool {
        self.read_config().auto_approve
    }

    /// Register a request and hand back the id to quote to the model plus the channel its
    /// decision will arrive on.
    ///
    /// Synchronous on purpose: the caller is the connection task, but `approve`/`deny` are
    /// reached from the action executor, and neither may need a runtime handle.
    pub fn open(
        &self,
        details: ApprovalDetails,
        connection_id: Option<String>,
    ) -> (ApprovalId, oneshot::Receiver<ApprovalDecision>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.lock_pending().insert(
            id,
            PendingApproval {
                id,
                details: details.clone(),
                connection_id,
                response_tx: tx,
            },
        );

        info!(
            "FIDO2 approval {} opened: {:?} for RP '{}' (user: {:?})",
            id, details.operation, details.rp_id, details.user_name
        );

        (id, rx)
    }

    /// Wait for the decision on a request opened by [`Self::open`].
    ///
    /// Returns `Approved` immediately in auto-approve mode. Otherwise waits up to the configured
    /// timeout and **denies** on expiry, on a dropped channel, and on anything else that is not
    /// an explicit approval.
    pub async fn wait(
        &self,
        id: ApprovalId,
        rx: oneshot::Receiver<ApprovalDecision>,
    ) -> ApprovalDecision {
        let (auto_approve, timeout, timeout_decision) = {
            let cfg = self.read_config();
            (cfg.auto_approve, cfg.timeout, cfg.timeout_decision)
        };

        if auto_approve {
            self.lock_pending().remove(&id);
            info!("FIDO2 approval {} auto-approved (auto_approve=true)", id);
            return ApprovalDecision::Approved;
        }

        let decision = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("FIDO2 approval {} decided: {:?}", id, decision);
                decision
            }
            Ok(Err(_)) => {
                warn!(
                    "FIDO2 approval {} channel closed without a decision, denying",
                    id
                );
                timeout_decision
            }
            Err(_) => {
                warn!(
                    "FIDO2 approval {} unanswered after {:?}, denying",
                    id, timeout
                );
                timeout_decision
            }
        };

        self.lock_pending().remove(&id);
        decision
    }

    /// Open a request and wait for it in one call.
    ///
    /// Convenience for callers that have nothing to do in between; the connection task uses
    /// `open` + `wait` around it so it can raise the event with the id already allocated.
    pub async fn request_approval(
        &self,
        details: ApprovalDetails,
        connection_id: Option<String>,
    ) -> (ApprovalId, ApprovalDecision) {
        let (id, rx) = self.open(details, connection_id);
        let decision = self.wait(id, rx).await;
        (id, decision)
    }

    /// Approve a pending request.
    pub fn approve(&self, id: ApprovalId) -> Result<(), String> {
        self.resolve(id, ApprovalDecision::Approved)
    }

    /// Deny a pending request.
    pub fn deny(&self, id: ApprovalId) -> Result<(), String> {
        self.resolve(id, ApprovalDecision::Denied)
    }

    fn resolve(&self, id: ApprovalId, decision: ApprovalDecision) -> Result<(), String> {
        let request = self.lock_pending().remove(&id);
        match request {
            Some(request) => {
                info!(
                    "FIDO2 approval {} resolved {:?} ({:?} for RP '{}')",
                    id, decision, request.details.operation, request.details.rp_id
                );
                let _ = request.response_tx.send(decision);
                Ok(())
            }
            None => {
                let open = self.list_pending();
                warn!("FIDO2 approval {} not found or already resolved", id);
                if open.is_empty() {
                    Err(format!(
                        "no FIDO2 approval with id {} is pending (none are)",
                        id
                    ))
                } else {
                    Err(format!(
                        "no FIDO2 approval with id {} is pending; open ids are {:?}",
                        id,
                        open.iter().map(|p| p.id).collect::<Vec<_>>()
                    ))
                }
            }
        }
    }

    /// Every request currently awaiting a decision.
    pub fn list_pending(&self) -> Vec<PendingApprovalInfo> {
        let mut open: Vec<PendingApprovalInfo> = self
            .lock_pending()
            .values()
            .map(|req| PendingApprovalInfo {
                id: req.id,
                details: req.details.clone(),
                connection_id: req.connection_id.clone(),
            })
            .collect();
        open.sort_by_key(|p| p.id);
        open
    }

    /// Replace the configuration (used by `set_approval_mode`).
    pub fn set_config(&self, new_config: ApprovalConfig) {
        *self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_config.clone();
        info!("FIDO2 approval config updated: {:?}", new_config);
    }

    pub fn get_config(&self) -> ApprovalConfig {
        self.read_config()
    }

    fn read_config(&self) -> ApprovalConfig {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<ApprovalId, PendingApproval>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A pending request, as reported to the model by `list_pending_approvals`.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone)]
pub struct PendingApprovalInfo {
    pub id: ApprovalId,
    pub details: ApprovalDetails,
    pub connection_id: Option<String>,
}

#[cfg(all(unix, feature = "libusb"))]
impl Clone for ApprovalManager {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            pending: Arc::clone(&self.pending),
            next_id: Arc::clone(&self.next_id),
        }
    }
}
