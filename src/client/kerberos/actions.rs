//! Kerberos client actions, events and metadata.
//!
//! The model decides which tickets to get — a TGT, then service tickets for the services it
//! chooses — and with what lifetime and flags. The password is a startup parameter the
//! transport uses to derive keys; it is in no action, no event and no log line, and the model
//! never sees a key.

use std::sync::LazyLock;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::kerberos::codec::Principal;
use crate::state::app_state::AppState;

use super::wire::Request;

/// The `ClientActionResult::Custom` name every exchange travels as.
pub const EXCHANGE_RESULT: &str = "kerberos_exchange";

/// Milliseconds to wait for a reply before retransmitting (UDP) or giving up (TCP).
pub const DEFAULT_TIMEOUT_MS: u64 = 3000;
/// Retransmissions of an unanswered UDP request.
pub const DEFAULT_RETRIES: u64 = 2;
/// Transport used unless the operator names another; MIT's and Heimdal's default.
pub const DEFAULT_TRANSPORT: &str = "udp";
/// Lifetime requested when the model names none: ten hours, MIT's default.
pub const DEFAULT_LIFETIME_SECS: u64 = 10 * 3600;
/// Longest lifetime the model may request (the KDC clamps further).
pub const MAX_REQUEST_LIFETIME_SECS: u64 = 365 * 24 * 3600;

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn credential_params() -> Vec<Parameter> {
    vec![
        param("client", "string", "Client principal with realm", true),
        param("service", "string", "Service principal with realm", true),
        param(
            "authtime",
            "string",
            "When the client authenticated (RFC 3339)",
            true,
        ),
        param("starttime", "string", "When the ticket became valid", true),
        param("endtime", "string", "When the ticket expires", true),
        param(
            "lifetime_secs",
            "number",
            "endtime - starttime, as the KDC granted it",
            true,
        ),
        param(
            "expires_in_secs",
            "number",
            "Seconds from now until it expires",
            true,
        ),
        param("renew_till", "string", "Renewable until, or null", false),
        param(
            "flags",
            "array",
            "Ticket flags the KDC set: forwardable, proxiable, renewable, initial, pre_authent, …",
            true,
        ),
        param("session_etype", "string", "Session key enctype", true),
        param(
            "ticket_etype",
            "string",
            "Enctype the service's ticket is encrypted with",
            true,
        ),
    ]
}

pub static KERBEROS_CLIENT_READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kerberos_client_ready",
        "Ready to talk to the KDC (nothing has been sent yet). Usually: request a TGT",
        json!({"type": "kerberos_request_tgt", "lifetime_secs": 36000}),
    )
    .with_parameters(vec![
        param("kdc", "string", "The KDC's address", true),
        param(
            "principal",
            "string",
            "The client principal, with realm",
            true,
        ),
        param(
            "transport",
            "string",
            "How requests reach the KDC: udp, or tcp with a 4-byte length prefix",
            true,
        ),
    ])
    .with_actions(all_actions())
});

pub static KERBEROS_TGT_OBTAINED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kerberos_tgt_obtained",
        "The KDC issued a TGT, verified: its reply decrypted with the key derived from the \
         password and echoed this client's nonce. Next, usually: request service tickets",
        json!({"type": "kerberos_request_service_ticket", "service": "host/web.netget.test"}),
    )
    .with_parameters(credential_params())
    .with_actions(all_actions())
});

pub static KERBEROS_SERVICE_TICKET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kerberos_service_ticket_obtained",
        "The KDC issued a service ticket, verified with the TGT's session key and this \
         request's subkey",
        json!({"type": "disconnect"}),
    )
    .with_parameters(credential_params())
    .with_actions(all_actions())
});

pub static KERBEROS_REQUEST_FAILED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "kerberos_request_failed",
        "A ticket request failed: the KDC refused it with a Kerberos error, or its reply did not \
         verify, or it did not answer",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![
        param("stage", "string", "as (TGT) or tgs (service ticket)", true),
        param("service", "string", "The service requested", true),
        param(
            "kind",
            "string",
            "kdc_error (see error), integrity (the reply did not decrypt or verify: wrong \
             password or forged reply), timeout, transport, malformed, oversize or no_tgt",
            true,
        ),
        param("error", "string", "Kerberos error name, for kind=kdc_error", false),
        param("code", "number", "Kerberos error code, for kind=kdc_error", false),
        param("text", "string", "The KDC's e-text, if any", false),
        param("message", "string", "What went wrong, for the other kinds", false),
    ])
    .with_actions(all_actions())
    });

fn lifetime_params() -> Vec<Parameter> {
    vec![
        param(
            "lifetime_secs",
            "number",
            "Lifetime to request (default 36000); the KDC may grant less",
            false,
        ),
        param(
            "renewable_lifetime_secs",
            "number",
            "Ask for a renewable ticket with this renewable lifetime",
            false,
        ),
        param(
            "forwardable",
            "boolean",
            "Ask for a forwardable ticket",
            false,
        ),
        param("proxiable", "boolean", "Ask for a proxiable ticket", false),
    ]
}

pub fn all_actions() -> Vec<ActionDefinition> {
    let mut service_params = vec![param(
        "service",
        "string",
        "Service principal, e.g. host/web.netget.test or HTTP/www.netget.test (same realm)",
        true,
    )];
    service_params.extend(lifetime_params());
    vec![
        ActionDefinition {
            name: "kerberos_request_tgt".to_string(),
            description: "Get a TGT for the configured principal (AS exchange): pre-authenticates \
                          with the configured password when the KDC asks"
                .to_string(),
            parameters: lifetime_params(),
            example: json!({"type": "kerberos_request_tgt", "lifetime_secs": 36000, "forwardable": true}),
            log_template: Some(LogTemplate::new().with_info("-> Kerberos AS-REQ")),
        },
        ActionDefinition {
            name: "kerberos_request_service_ticket".to_string(),
            description: "Get a service ticket with the TGT (TGS exchange). Needs a TGT first"
                .to_string(),
            parameters: service_params,
            example: json!({"type": "kerberos_request_service_ticket", "service": "host/web.netget.test"}),
            log_template: Some(LogTemplate::new().with_info("-> Kerberos TGS-REQ")),
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Stop the client".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: Some(LogTemplate::new().with_info("-> Kerberos client stopped")),
        },
    ]
}

/// What one action asks the transport to do.
pub enum Exchange {
    Tgt(Request),
    Service(Principal, Request),
}

fn seconds(action: &Value, key: &str) -> Result<Option<i64>> {
    match action.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("'{key}' must be a positive number of seconds"))?;
            if n == 0 || n > MAX_REQUEST_LIFETIME_SECS {
                return Err(anyhow!(
                    "'{key}' must be between 1 and {MAX_REQUEST_LIFETIME_SECS}"
                ));
            }
            Ok(Some(n as i64))
        }
    }
}

fn boolean(action: &Value, key: &str) -> Result<bool> {
    match action.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(anyhow!("'{key}' must be true or false")),
    }
}

fn request_of(action: &Value) -> Result<Request> {
    Ok(Request {
        lifetime_secs: seconds(action, "lifetime_secs")?.unwrap_or(DEFAULT_LIFETIME_SECS as i64),
        renewable_lifetime_secs: seconds(action, "renewable_lifetime_secs")?,
        forwardable: boolean(action, "forwardable")?,
        proxiable: boolean(action, "proxiable")?,
        addresses: Vec::new(),
    })
}

/// Validate an action into the exchange it asks for; `None` for `disconnect`. Every refusal
/// happens here, before anything is sent.
pub fn exchange_from_action(action: &Value) -> Result<Option<Exchange>> {
    let kind = action
        .get("type")
        .and_then(Value::as_str)
        .context("action has no 'type'")?;
    match kind {
        "kerberos_request_tgt" => Ok(Some(Exchange::Tgt(request_of(action)?))),
        "kerberos_request_service_ticket" => {
            let text = action
                .get("service")
                .and_then(Value::as_str)
                .context("kerberos_request_service_ticket requires 'service'")?;
            let (service, realm) = Principal::parse(text)?;
            if realm.is_some() {
                return Err(anyhow!(
                    "name the service without a realm: this client asks its own realm's KDC \
                     only (no cross-realm)"
                ));
            }
            Ok(Some(Exchange::Service(service, request_of(action)?)))
        }
        "disconnect" => Ok(None),
        other => Err(anyhow!("Unknown Kerberos client action: {other}")),
    }
}

/// Kerberos client protocol handler.
#[derive(Default)]
pub struct KerberosClientProtocol;

impl KerberosClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for KerberosClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "principal".to_string(),
                type_hint: "string".to_string(),
                description: "Client principal, e.g. alice or alice@NETGET.TEST".to_string(),
                required: true,
                example: json!("alice@NETGET.TEST"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "The principal's password. Used only to derive keys; never shown \
                              in events or logs"
                    .to_string(),
                required: true,
                example: json!("wonderland"),
                default: None,
            },
            ParameterDefinition {
                name: "realm".to_string(),
                type_hint: "string".to_string(),
                description: "Realm, when the principal does not name one".to_string(),
                required: false,
                example: json!("NETGET.TEST"),
                default: None,
            },
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description: "udp or tcp (a UDP reply too big for a datagram is retried over \
                              TCP automatically)"
                    .to_string(),
                required: false,
                example: json!("tcp"),
                default: Some(json!(DEFAULT_TRANSPORT)),
            },
            ParameterDefinition {
                name: "timeout_ms".to_string(),
                type_hint: "integer".to_string(),
                description: "Milliseconds to wait for each reply (100-60000)".to_string(),
                required: false,
                example: json!(3000),
                default: Some(json!(DEFAULT_TIMEOUT_MS)),
            },
            ParameterDefinition {
                name: "retries".to_string(),
                type_hint: "integer".to_string(),
                description: "UDP retransmissions before a request times out (0-5)".to_string(),
                required: false,
                example: json!(2),
                default: Some(json!(DEFAULT_RETRIES)),
            },
            ParameterDefinition {
                name: "ccache_path".to_string(),
                type_hint: "string".to_string(),
                description: "Write every ticket obtained to this MIT FILE credential cache \
                              (mode 0600), which klist and kvno can use. It holds the session \
                              keys, as any ccache does"
                    .to_string(),
                required: false,
                example: json!("/tmp/krb5cc_netget"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "Kerberos"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            KERBEROS_CLIENT_READY_EVENT.clone(),
            KERBEROS_TGT_OBTAINED_EVENT.clone(),
            KERBEROS_SERVICE_TICKET_EVENT.clone(),
            KERBEROS_REQUEST_FAILED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>KERBEROS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["kerberos", "kinit", "kerberos client", "krb5", "tgt"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Kerberos V5 client (RFC 4120) over UDP or TCP. AS exchange as MIT kinit does it: \
                 an unauthenticated AS-REQ, then on KDC_ERR_PREAUTH_REQUIRED the key derived \
                 with the ETYPE-INFO2 salt (PBKDF2, RFC 3962) and PA-ENC-TIMESTAMP. TGS \
                 exchange with an AP-REQ whose authenticator carries a keyed checksum over the \
                 request body and a fresh subkey. Every reply is bounded (64 KiB, DER depth 24) \
                 and verified before it is believed: the encrypted part must decrypt (constant \
                 time HMAC check), echo the nonce and name the client and service asked for. \
                 aes256/aes128-cts-hmac-sha1-96 only. Optionally writes an MIT FILE ccache (v4).",
            )
            .llm_control(
                "Which tickets to get (a TGT, then service tickets for the services it names) \
                 and with what lifetime, renewable lifetime and flags; it is told what the KDC \
                 granted or why it refused. It never sees the password or a key.",
            )
            .e2e_testing(
                "tests/client/kerberos/real_server_test.rs against two independent KDCs, each \
                 in a temporary realm built with its own admin tool: MIT krb5kdc (kdb5_util, \
                 kadmin.local) and Heimdal's kdc (kadmin -l). With a python chain as the model: \
                 a TGT with the model's lifetime and flags, a service ticket, and a refused \
                 unknown service. MIT klist and Heimdal klist read the ccache NetGet wrote; MIT \
                 kvno -k decrypts the service ticket with the keytab each KDC's database \
                 exported; MIT kvno and Heimdal kgetcred use NetGet's TGT and session key for a \
                 ticket NetGet never asked for; krb5kdc's log shows the AS_REQ and TGS_REQ it \
                 issued. A wrong password is refused by the KDC (pre-authentication) or by \
                 NetGet (an AS-REP it cannot decrypt). Traffic to MIT is dissected by tshark. \
                 Fails, not skips, without the KDCs. bounds_test.rs: oversize, deeply nested \
                 and wrong-nonce replies, a service ticket before a TGT, and the follow-up depth.",
            )
            .notes(
                "Experimental: two independent KDCs complete real sessions with it, but nobody \
                 has reviewed it beyond its tests and the pair job has not run in CI. No FAST, \
                 PKINIT, renewal, cross-realm, AP exchange or RFC 8009 enctypes.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Kerberos V5 client that gets TGTs and service tickets from a KDC"
    }

    fn example_prompt(&self) -> &'static str {
        "Get a TGT for alice@NETGET.TEST (password wonderland) from the KDC at localhost:88, \
         then a ticket for host/web.netget.test"
    }

    fn group_name(&self) -> &'static str {
        "Authentication"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let params = json!({"principal": "alice@NETGET.TEST", "password": "wonderland"});
        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:88",
                "base_stack": "kerberos",
                "startup_params": params,
                "instruction": "Get a TGT, then a service ticket for host/web.netget.test"
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:88",
                "base_stack": "kerberos",
                "startup_params": params,
                "event_handlers": [{
                    "event_pattern": "kerberos_tgt_obtained",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'kerberos_request_service_ticket', 'service': 'host/web.netget.test'}])"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:88",
                "base_stack": "kerberos",
                "startup_params": params,
                "event_handlers": [
                    {
                        "event_pattern": "kerberos_client_ready",
                        "handler": {"type": "static", "actions": [{"type": "kerberos_request_tgt"}]}
                    },
                    {
                        "event_pattern": "kerberos_tgt_obtained",
                        "handler": {"type": "static", "actions": [{"type": "disconnect"}]}
                    }
                ]
            }),
        )
    }
}

impl Client for KerberosClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(super::connect(ctx))
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match exchange_from_action(&action)? {
            None => Ok(ClientActionResult::Disconnect),
            Some(_) => Ok(ClientActionResult::Custom {
                name: EXCHANGE_RESULT.to_string(),
                data: action,
            }),
        }
    }
}
