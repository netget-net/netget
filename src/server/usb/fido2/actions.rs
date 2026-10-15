//! USB FIDO2/U2F security key protocol actions.
//!
//! The model's job here is one decision, repeated: **approve or deny** a registration or an
//! authentication. That is a genuinely good fit for an LLM — it is a policy call about a named
//! relying party, not a byte-level transformation — and it is the only thing a real security key
//! asks a human for.
//!
//! Everything on this surface used to be broken:
//!
//! * `get_sync_actions()` returned `vec![]` and the protocol did not delegate, so the model had
//!   no vocabulary for any event.
//! * All three events were declared and never emitted.
//! * `execute_action` reached the approval manager with
//!   `tokio::runtime::Handle::current().block_on(...)` and **panicked** —
//!   *"Cannot block the current thread from within a runtime"* — while the events' own examples
//!   taught the model to answer with exactly that action.
//! * Four of the seven actions (`save_credentials`, `load_credentials`, and the credential
//!   listing/deletion pair) logged a line and returned `NoAction`; they were advertised
//!   capability that did nothing.
//!
//! The approval manager is now synchronous throughout (`std::sync` locks, `oneshot::send`), so
//! nothing needs a runtime handle, and every action reaches the *running* server through
//! `execute_action_with_state` + `AppState::server_handle` rather than a global map whose lookup
//! was "first value".

#[cfg(all(unix, feature = "libusb"))]
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::log_template::LogTemplate;
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::EventType;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::fido2::Fido2ServerHandle;
#[cfg(all(unix, feature = "libusb"))]
use crate::state::app_state::AppState;
#[cfg(all(unix, feature = "libusb"))]
use anyhow::{anyhow, Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use serde_json::json;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::LazyLock;
#[cfg(all(unix, feature = "libusb"))]
use tracing::info;

/// Approve the request the event named. Sync action: it answers an event.
#[cfg(all(unix, feature = "libusb"))]
fn approve_action() -> ActionDefinition {
    ActionDefinition {
        name: "approve_request".to_string(),
        description: "Approve the pending FIDO2/U2F request. Quote the approval_id from the \
                      event. The credential is created (or the assertion signed) only after \
                      this."
            .to_string(),
        parameters: vec![Parameter {
            name: "approval_id".to_string(),
            type_hint: "number".to_string(),
            description: "The approval_id carried by the event being answered".to_string(),
            required: true,
        }],
        example: json!({"type": "approve_request", "approval_id": 1}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FIDO2 approve request #{approval_id}")
                .with_debug("USB-FIDO2 approve_request: approval_id={approval_id}"),
        ),
    }
}

/// Deny the request the event named.
///
/// Structurally distinct from saying nothing: silence also denies (after the timeout), but a
/// `deny_request` denies *now* and is recorded as a decision rather than an absence.
#[cfg(all(unix, feature = "libusb"))]
fn deny_action() -> ActionDefinition {
    ActionDefinition {
        name: "deny_request".to_string(),
        description: "Deny the pending FIDO2/U2F request. Quote the approval_id from the event. \
                      The host is told the operation was refused; nothing is created or signed."
            .to_string(),
        parameters: vec![Parameter {
            name: "approval_id".to_string(),
            type_hint: "number".to_string(),
            description: "The approval_id carried by the event being answered".to_string(),
            required: true,
        }],
        example: json!({"type": "deny_request", "approval_id": 1}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FIDO2 deny request #{approval_id}")
                .with_debug("USB-FIDO2 deny_request: approval_id={approval_id}"),
        ),
    }
}

/// The two actions that answer an approval event.
#[cfg(all(unix, feature = "libusb"))]
fn decision_actions() -> Vec<ActionDefinition> {
    vec![approve_action(), deny_action()]
}

// Event type definitions

#[cfg(all(unix, feature = "libusb"))]
pub static FIDO2_DEVICE_ATTACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fido2_device_attached",
        "A host imported the virtual security key over USB/IP. Nothing has been requested yet.",
        json!({"type": "set_memory", "key": "fido2_host", "value": "attached"}),
    )
    // Informational: there is no request to approve yet, so the only sensible answers are the
    // common actions.
    .with_no_actions()
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID of the USB/IP session".to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address of the host that attached".to_string(),
            required: true,
        },
        Parameter {
            name: "supports_u2f".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether CTAP1/U2F is enabled on this device".to_string(),
            required: true,
        },
        Parameter {
            name: "supports_fido2".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether CTAP2/FIDO2 is enabled on this device".to_string(),
            required: true,
        },
    ])
});

#[cfg(all(unix, feature = "libusb"))]
pub static FIDO2_REGISTER_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fido2_register_request",
        "A relying party is asking the key to create a new credential. The key is holding the \
         host on CTAPHID KEEPALIVE until you answer; nothing is created unless you approve.",
        json!({"type": "approve_request", "approval_id": 1}),
    )
    .with_actions(decision_actions())
    .with_alternative_example(json!({"type": "deny_request", "approval_id": 1}))
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID".to_string(),
            required: true,
        },
        Parameter {
            name: "approval_id".to_string(),
            type_hint: "number".to_string(),
            description: "Quote this back in approve_request / deny_request".to_string(),
            required: true,
        },
        Parameter {
            name: "rp_id".to_string(),
            type_hint: "string".to_string(),
            description: "Relying party. CTAP2 gives a real domain; U2F only has the SHA-256 of \
                          the origin, and reports 'u2f-app:<hex prefix>'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "user_name".to_string(),
            type_hint: "string".to_string(),
            description: "User name the credential is for, when the request carries one"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "credential_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many credentials this key already holds for that relying party"
                .to_string(),
            required: true,
        },
    ])
});

#[cfg(all(unix, feature = "libusb"))]
pub static FIDO2_AUTHENTICATE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fido2_authenticate_request",
        "A relying party is asking the key to sign an assertion with an existing credential. \
         The key is holding the host on CTAPHID KEEPALIVE until you answer; nothing is signed \
         unless you approve.",
        json!({"type": "approve_request", "approval_id": 1}),
    )
    .with_actions(decision_actions())
    .with_alternative_example(json!({"type": "deny_request", "approval_id": 1}))
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID".to_string(),
            required: true,
        },
        Parameter {
            name: "approval_id".to_string(),
            type_hint: "number".to_string(),
            description: "Quote this back in approve_request / deny_request".to_string(),
            required: true,
        },
        Parameter {
            name: "rp_id".to_string(),
            type_hint: "string".to_string(),
            description: "Relying party asking for the assertion".to_string(),
            required: true,
        },
        Parameter {
            name: "user_name".to_string(),
            type_hint: "string".to_string(),
            description: "User name on the stored credential, if the key knows one".to_string(),
            required: false,
        },
        Parameter {
            name: "credential_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many stored credentials match this relying party".to_string(),
            required: true,
        },
    ])
});

#[cfg(all(unix, feature = "libusb"))]
pub static FIDO2_DEVICE_DETACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fido2_device_detached",
        "The USB/IP session ended. Credentials are held per session and are gone with it.",
        json!({"type": "show_message", "message": "Security key detached"}),
    )
    .with_no_actions()
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID of the session that ended".to_string(),
        required: true,
    }])
});

/// USB FIDO2 protocol action handler.
///
/// Stateless, like every other entry in the registry: the running server is reached through
/// `AppState::server_handle::<Fido2ServerHandle>()`.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Default)]
pub struct UsbFido2Protocol;

#[cfg(all(unix, feature = "libusb"))]
impl UsbFido2Protocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait
#[cfg(all(unix, feature = "libusb"))]
impl Protocol for UsbFido2Protocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "support_u2f".to_string(),
                type_hint: "boolean".to_string(),
                description: "Answer CTAP1/U2F (CTAPHID MSG). Default true. With this false the \
                              device sets the NMSG capability bit and refuses MSG."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "support_fido2".to_string(),
                type_hint: "boolean".to_string(),
                description: "Answer CTAP2/FIDO2 (CTAPHID CBOR). Default true. With this false \
                              the device clears the CBOR capability bit and refuses CBOR."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "auto_approve".to_string(),
                type_hint: "boolean".to_string(),
                description: "Approve every request without asking (development only). Default \
                              false; leave it false to have the model decide."
                    .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "approval_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "How long a request waits for a decision before being DENIED. \
                              Default 30, matching a real key's user-presence window."
                    .to_string(),
                required: false,
                example: json!(30),
                default: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "usb-fido2"
    }

    fn stack_name(&self) -> &'static str {
        "USB FIDO2/U2F Security Key"
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        let mut actions = decision_actions();
        actions.extend(vec![
            ActionDefinition {
                name: "list_pending_approvals".to_string(),
                description: "List FIDO2/U2F requests currently waiting for a decision".to_string(),
                parameters: vec![],
                example: json!({"type": "list_pending_approvals"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> FIDO2 list pending approvals")
                        .with_debug("USB-FIDO2 list_pending_approvals"),
                ),
            },
            ActionDefinition {
                name: "list_credentials".to_string(),
                description: "List the credentials this key holds, across every attached host. \
                              Reports relying party, user name and signature counter — never \
                              key material."
                    .to_string(),
                parameters: vec![],
                example: json!({"type": "list_credentials"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> FIDO2 list credentials")
                        .with_debug("USB-FIDO2 list_credentials"),
                ),
            },
            ActionDefinition {
                name: "delete_credential".to_string(),
                description: "Forget every credential for a relying party".to_string(),
                parameters: vec![Parameter {
                    name: "rp_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Relying party id, exactly as list_credentials reports it"
                        .to_string(),
                    required: true,
                }],
                example: json!({"type": "delete_credential", "rp_id": "example.com"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> FIDO2 delete credentials for '{rp_id}'")
                        .with_debug("USB-FIDO2 delete_credential: rp_id='{rp_id}'"),
                ),
            },
        ]);
        actions
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        decision_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            FIDO2_DEVICE_ATTACHED_EVENT.clone(),
            FIDO2_REGISTER_REQUEST_EVENT.clone(),
            FIDO2_AUTHENTICATE_REQUEST_EVENT.clone(),
            FIDO2_DEVICE_DETACHED_EVENT.clone(),
        ]
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["fido2", "u2f", "webauthn", "security key", "yubikey"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Virtual FIDO2/U2F security key over USB/IP: CTAPHID transport, CTAP1 (U2F \
                 REGISTER/AUTHENTICATE/VERSION) and CTAP2 (MakeCredential, GetAssertion, \
                 GetInfo, ClientPIN, Reset), ECDSA P-256 via ring. Credentials are in memory \
                 and per USB/IP session.",
            )
            .llm_control(
                "The user-presence decision: approve_request / deny_request answer \
                 fido2_register_request and fido2_authenticate_request. Nothing is created or \
                 signed before the model answers, and an unanswered request is DENIED.",
            )
            .e2e_testing(
                "USB/IP spoken directly over TCP by tests/helpers/usbip_client.rs, driving real \
                 CTAPHID frames: INIT, PING, CBOR GetInfo, CBOR MakeCredential and CBOR \
                 GetAssertion, with the CBOR decoded independently by serde_cbor and the ECDSA \
                 signature verified against the credential's own COSE public key.",
            )
            .notes(
                "Verified against an in-test USB/IP + CTAPHID client only. NOT verified against \
                 a real Linux `usbip attach` + vhci-hcd host, libfido2's fido2-token, or a \
                 browser's WebAuthn implementation — macOS has no USB/IP client. Attestation is \
                 a fixed zero signature ('packed' format with a dummy attStmt), so a relying \
                 party that verifies attestation will reject the credential; only 'none' \
                 attestation flows work. ClientPIN is development-grade: PINs are compared as \
                 SHA-256 of the plaintext, with none of PIN protocol v1's ECDH shared secret. \
                 Credentials do not survive the USB/IP session.",
            )
            // The USB/IP screen in `src/server/usb/guard.rs` refuses a `USBIP_CMD_SUBMIT`
            // declaring more than this, before the crate allocates from the number.
            .max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)
            .build()
    }

    fn description(&self) -> &'static str {
        "Virtual FIDO2/U2F security key where the LLM decides each approval"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a FIDO2 security key on port 3240 that approves logins to example.com and denies \
         everything else"
    }

    fn group_name(&self) -> &'static str {
        "USB"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model decides every approval.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-fido2",
                "instruction": "Be a FIDO2 security key. Approve registrations and logins for \
                                example.com; deny every other relying party.",
                "startup_params": {
                    "support_u2f": true,
                    "support_fido2": true,
                    "auto_approve": false
                }
            }),
            // Script mode: deterministic policy, no LLM round trip.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-fido2",
                "startup_params": { "auto_approve": false },
                "event_handlers": [{
                    "event_pattern": "fido2_authenticate_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "approved = event['rp_id'] == 'example.com'\nactions = [{'type': 'approve_request' if approved else 'deny_request', 'approval_id': event['approval_id']}]"
                    }
                }]
            }),
            // Static mode: a fixed answer. Note it cannot quote the event's approval_id, so it
            // only makes sense with a single request in flight, which is the normal case.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-fido2",
                "startup_params": { "auto_approve": false },
                "event_handlers": [{
                    "event_pattern": "fido2_register_request",
                    "handler": {
                        "type": "static",
                        "actions": [{ "type": "deny_request", "approval_id": 1 }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait
#[cfg(all(unix, feature = "libusb"))]
impl Server for UsbFido2Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Every one of these is optional, so they must be read with the `get_optional_*`
            // accessors. `get_bool` *errors* on a missing key, and mapping it over
            // `startup_params` turned "the caller did not mention support_u2f" into
            // "Required boolean parameter 'support_u2f' is missing", refusing to start a server
            // whose parameters were all legal.
            let params = ctx.startup_params.as_ref();
            let support_u2f = params
                .map(|p| p.get_optional_bool("support_u2f"))
                .transpose()?
                .flatten();
            let support_fido2 = params
                .map(|p| p.get_optional_bool("support_fido2"))
                .transpose()?
                .flatten();
            let auto_approve = params
                .map(|p| p.get_optional_bool("auto_approve"))
                .transpose()?
                .flatten();
            let approval_timeout_secs = params
                .map(|p| p.get_optional_u64("approval_timeout_secs"))
                .transpose()?
                .flatten();

            crate::server::usb::fido2::UsbFido2Server::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                support_u2f,
                support_fido2,
                auto_approve,
                approval_timeout_secs,
            )
            .await
        })
    }

    /// Never reached: [`Self::execute_action_with_state`] is overridden and does not delegate.
    ///
    /// Fails closed. Every FIDO2 action needs the running server's approval manager or its
    /// per-connection credential store, and this stateless object has neither, so if the
    /// executor ever stopped calling the state-aware variant the failure would be loud rather
    /// than a silent "approved".
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action["type"].as_str().context("Missing action type")?;
        Err(anyhow!(
            "usb-fido2 action '{}' needs the running server's approval state and must be \
             dispatched through execute_action_with_state",
            action_type
        ))
    }

    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        Box::pin(async move {
            let action_type = action["type"]
                .as_str()
                .context("Missing action type")?
                .to_string();

            let server_id = server_id.context(
                "usb-fido2 actions are server-scoped and cannot run without a server id",
            )?;
            let handle: std::sync::Arc<Fido2ServerHandle> = state
                .server_handle(server_id)
                .await
                .ok_or_else(|| anyhow!("no running usb-fido2 server for id {server_id:?}"))?;

            match action_type.as_str() {
                "approve_request" | "deny_request" => {
                    let approval_id = approval_id_of(&action)?;
                    let approved = action_type == "approve_request";

                    if approved {
                        handle.approvals.approve(approval_id)
                    } else {
                        handle.approvals.deny(approval_id)
                    }
                    .map_err(|e| anyhow!("{}", e))?;

                    info!(
                        "FIDO2 request {} {} by the model",
                        approval_id,
                        if approved { "approved" } else { "denied" }
                    );
                    Ok(ActionResult::Custom {
                        name: "fido2_decision".to_string(),
                        data: json!({
                            "approval_id": approval_id,
                            "decision": if approved { "approved" } else { "denied" },
                        }),
                    })
                }

                "list_pending_approvals" => {
                    let pending: Vec<serde_json::Value> = handle
                        .approvals
                        .list_pending()
                        .into_iter()
                        .map(|p| {
                            json!({
                                "approval_id": p.id,
                                "operation": p.details.operation.event_id(),
                                "rp_id": p.details.rp_id,
                                "user_name": p.details.user_name,
                                "credential_count": p.details.credential_count,
                                "connection_id": p.connection_id,
                            })
                        })
                        .collect();

                    info!("FIDO2 pending approvals: {}", pending.len());
                    Ok(ActionResult::Custom {
                        name: "fido2_pending_approvals".to_string(),
                        data: json!({ "pending": pending }),
                    })
                }

                "list_credentials" => {
                    let credentials: Vec<serde_json::Value> = handle
                        .with_each_handler(|h| h.describe_credentials())
                        .into_iter()
                        .flatten()
                        .collect();

                    info!("FIDO2 credentials held: {}", credentials.len());
                    Ok(ActionResult::Custom {
                        name: "fido2_credentials".to_string(),
                        data: json!({ "credentials": credentials }),
                    })
                }

                "delete_credential" => {
                    let rp_id = action["rp_id"]
                        .as_str()
                        .context("delete_credential needs an rp_id")?
                        .to_string();
                    let removed: usize = handle
                        .with_each_handler(|h| h.delete_credentials(&rp_id))
                        .into_iter()
                        .sum();

                    info!("FIDO2 deleted {} credential(s) for '{}'", removed, rp_id);
                    Ok(ActionResult::Custom {
                        name: "fido2_credentials_deleted".to_string(),
                        data: json!({ "rp_id": rp_id, "removed": removed }),
                    })
                }

                other => Err(anyhow!(
                    "unknown usb-fido2 action '{}'; expected one of approve_request, \
                     deny_request, list_pending_approvals, list_credentials, delete_credential",
                    other
                )),
            }
        })
    }
}

/// Read `approval_id` from an action, accepting the number and the string form.
///
/// Small models routinely quote a numeric field as a string; rejecting `"1"` here would turn a
/// correct decision into a failed action, and — because an unanswered request denies — silently
/// convert an approval into a denial.
#[cfg(all(unix, feature = "libusb"))]
fn approval_id_of(action: &serde_json::Value) -> Result<u64> {
    match &action["approval_id"] {
        serde_json::Value::Number(n) => n
            .as_u64()
            .context("approval_id must be a non-negative integer"),
        serde_json::Value::String(s) => s
            .trim()
            .parse::<u64>()
            .with_context(|| format!("approval_id '{}' is not a number", s)),
        serde_json::Value::Null => Err(anyhow!(
            "approve_request/deny_request need the approval_id carried by the event"
        )),
        other => Err(anyhow!("approval_id must be a number, got {}", other)),
    }
}
