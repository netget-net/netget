//! Kerberos KDC actions, events and metadata.
//!
//! The model decides **policy** and nothing else: whether a principal is admitted, which
//! refusal to give, and the lifetime, renewability and flags of what it admits. It never sees
//! a key, a password or a nonce, and nothing it can say produces one. Three actions:
//!
//! - `kerberos_issue_ticket` — issue the ticket. Rust builds it, encrypts it and still refuses
//!   where what is missing is not policy (no configured key, missing pre-authentication), and
//!   clamps every time to the configured ceiling, the client's request and the TGT.
//! - `kerberos_require_preauth` — AS only: KDC_ERR_PREAUTH_REQUIRED with ETYPE-INFO2.
//! - `kerberos_refuse` — a KRB-ERROR with a code from the model's vocabulary
//!   ([`codec::MODEL_REFUSALS`]), which excludes the two codes the server uses when nobody
//!   decided, so "the model refused" and "the server failed closed" stay apart on the wire.
//!
//! The registry's instance is context-free and can answer nothing; `mod.rs` builds one per
//! request with [`KerberosProtocol::for_request`], carrying that request's established facts.

use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use super::codec;
use super::kdc::{Exchange, Grant, Issued, Kdc, Pending};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;

/// Default ceiling on a ticket's lifetime: ten hours, MIT's and Heimdal's default.
pub const DEFAULT_MAX_TICKET_LIFETIME_SECS: u64 = 10 * 3600;
/// Default ceiling on a ticket's renewable lifetime: seven days.
pub const DEFAULT_MAX_RENEWABLE_LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// Default tolerated clock difference for pre-authentication and authenticators (RFC 4120's
/// recommended five minutes).
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Default requests a single source address may make per minute.
pub const DEFAULT_MAX_REQUESTS_PER_MINUTE: u64 = 600;
/// Default realm when none is given.
pub const DEFAULT_REALM: &str = "NETGET.TEST";

/// Upper bounds on the operator's own limits, so a configuration cannot ask for absurdities.
pub const MAX_TICKET_LIFETIME_LIMIT_SECS: u64 = 365 * 24 * 3600;
pub const MAX_CLOCK_SKEW_LIMIT_SECS: u64 = 3600;

/// What one executed action decided, and the reply it built, in execution order. Replies
/// travel here rather than as raw executor output: one request gets exactly one reply, and
/// `mod.rs` sends the first record's and logs its decision. Nothing the model can trigger
/// writes to a socket by any other path.
#[derive(Debug, Clone)]
pub struct Record {
    pub decision: &'static str,
    pub detail: String,
    pub reply: Vec<u8>,
}

/// The facts of the request being answered.
#[derive(Clone)]
pub struct RequestContext {
    pub kdc: Arc<Kdc>,
    pub pending: Arc<Pending>,
    pub records: Arc<Mutex<Vec<Record>>>,
}

/// Kerberos KDC protocol handler.
pub struct KerberosProtocol {
    request: Option<RequestContext>,
}

impl Default for KerberosProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl KerberosProtocol {
    pub fn new() -> Self {
        Self { request: None }
    }

    pub fn for_request(ctx: RequestContext) -> Self {
        Self { request: Some(ctx) }
    }

    fn ctx(&self) -> Result<&RequestContext> {
        self.request.as_ref().context(
            "Kerberos action executed without a request context: a reply can only be built for \
             a request this KDC received and analysed",
        )
    }

    fn record(
        &self,
        ctx: &RequestContext,
        decision: &'static str,
        detail: String,
        reply: Vec<u8>,
    ) -> Result<ActionResult> {
        let mut r = ctx
            .records
            .lock()
            .map_err(|_| anyhow!("the request's record is unavailable"))?;
        r.push(Record {
            decision,
            detail,
            reply,
        });
        Ok(ActionResult::NoAction)
    }
}

fn p(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: false,
    }
}

fn common_parameters() -> Vec<Parameter> {
    vec![
        p(
            "client",
            "string",
            "Client principal name without the realm (alice, host/x)",
        ),
        p("client_realm", "string", "The client's realm"),
        p(
            "client_known",
            "boolean",
            "Whether a key is configured for the client. Without one no ticket can be issued, \
             whatever you decide",
        ),
        p(
            "service",
            "string",
            "Service principal requested (krbtgt/REALM for a TGT)",
        ),
        p(
            "service_known",
            "boolean",
            "Whether a key is configured for the service",
        ),
        p(
            "service_is_tgs",
            "boolean",
            "True when the client is asking for a TGT",
        ),
        p(
            "requested_lifetime_secs",
            "number",
            "Lifetime the client asked for, or null for 'as long as allowed'",
        ),
        p(
            "requested_renewable_lifetime_secs",
            "number",
            "Renewable lifetime the client asked for, or null",
        ),
        p(
            "options",
            "array",
            "KDC options the client set: forwardable, proxiable, renewable, renewable_ok, \
             canonicalize",
        ),
        p(
            "etypes",
            "array",
            "Enctypes the client offered, in its order",
        ),
        p(
            "addresses",
            "array",
            "Client addresses in the request, usually empty",
        ),
        p("source_addr", "string", "Where the request came from"),
        p(
            "transport",
            "string",
            "How the request arrived: udp, or tcp with a 4-byte length prefix",
        ),
        p(
            "max_ticket_lifetime_secs",
            "number",
            "The configured ceiling; a longer lifetime is clamped to it",
        ),
        p(
            "max_renewable_lifetime_secs",
            "number",
            "The configured renewable ceiling",
        ),
    ]
}

pub static KERBEROS_AS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_parameters();
    params.push(p(
        "preauth",
        "string",
        "'verified': the client proved it knows the password (PA-ENC-TIMESTAMP decrypted with \
         its key, inside the clock skew, not replayed). 'none': no pre-authentication was sent. \
         A failed pre-authentication never reaches you; the KDC refuses it itself",
    ));
    params.push(p(
        "preauth_required_by_config",
        "boolean",
        "Whether this principal must pre-authenticate before a ticket can be issued",
    ));
    EventType::new(
        "kerberos_as_request",
        "A client asked for an initial ticket (AS-REQ), usually a TGT. Decide: issue it (with \
         lifetime and flags), require pre-authentication, or refuse with a Kerberos error. \
         There is no default: if you return nothing the KDC refuses.",
        json!({"type": "kerberos_require_preauth"}),
    )
    .with_parameters(params)
    .with_actions(vec![
        issue_ticket_action(),
        require_preauth_action(),
        refuse_action(),
    ])
});

pub static KERBEROS_TGS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_parameters();
    params.push(p(
        "tgt_flags",
        "array",
        "Flags of the TGT the client presented (verified: it decrypted with this KDC's key)",
    ));
    params.push(p(
        "tgt_expires_in_secs",
        "number",
        "Seconds until the TGT expires",
    ));
    params.push(p(
        "tgt_authtime",
        "string",
        "When the client originally authenticated",
    ));
    params.push(p(
        "tgt_renew_till",
        "string",
        "The TGT's renewable end, or null",
    ));
    EventType::new(
        "kerberos_tgs_request",
        "An authenticated client (its TGT and authenticator verified) asked for a ticket to a \
         service (TGS-REQ). Decide: issue it, or refuse (S_PRINCIPAL_UNKNOWN, POLICY, …). \
         There is no default: if you return nothing the KDC refuses.",
        json!({"type": "kerberos_issue_ticket", "lifetime_secs": 3600}),
    )
    .with_parameters(params)
    .with_actions(vec![issue_ticket_action(), refuse_action()])
});

fn issue_ticket_action() -> ActionDefinition {
    ActionDefinition {
        name: "kerberos_issue_ticket".to_string(),
        description: "ADMIT the client: issue the requested ticket. The KDC builds and encrypts \
                      it. Lifetimes are clamped to the configured ceilings, the client's own \
                      request and (for a service ticket) its TGT; a flag is granted only when \
                      you set it AND the client asked for it. Flags you do not set are not \
                      granted. Refused anyway, with the right error, when the client or service \
                      has no configured key or pre-authentication is required but missing."
            .to_string(),
        parameters: vec![
            p(
                "lifetime_secs",
                "number",
                "Ticket lifetime in seconds (default and maximum: max_ticket_lifetime_secs)",
            ),
            p(
                "renewable",
                "boolean",
                "Make the ticket renewable, if the client asked (default false)",
            ),
            p(
                "renewable_lifetime_secs",
                "number",
                "Renewable lifetime in seconds (default and maximum: \
                 max_renewable_lifetime_secs)",
            ),
            p(
                "forwardable",
                "boolean",
                "Make the ticket forwardable, if the client asked (default false)",
            ),
            p(
                "proxiable",
                "boolean",
                "Make the ticket proxiable, if the client asked (default false)",
            ),
            p(
                "ok_as_delegate",
                "boolean",
                "Mark the service as trusted for delegation (service tickets only)",
            ),
        ],
        example: json!({
            "type": "kerberos_issue_ticket",
            "lifetime_secs": 28800,
            "forwardable": true
        }),
        log_template: Some(LogTemplate::new().with_info("-> Kerberos ticket issued")),
    }
}

fn require_preauth_action() -> ActionDefinition {
    ActionDefinition {
        name: "kerberos_require_preauth".to_string(),
        description: "Answer KDC_ERR_PREAUTH_REQUIRED: the client must prove it knows the \
                      password before a ticket is issued. The KDC adds the salt and enctypes. \
                      Also usable for an unknown principal, to avoid revealing which \
                      principals exist."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "kerberos_require_preauth"}),
        log_template: Some(LogTemplate::new().with_info("-> Kerberos pre-authentication required")),
    }
}

fn refuse_action() -> ActionDefinition {
    let names: Vec<String> = codec::MODEL_REFUSALS
        .iter()
        .map(|c| {
            codec::error_name(*c)
                .trim_start_matches("KDC_ERR_")
                .to_string()
        })
        .collect();
    ActionDefinition {
        name: "kerberos_refuse".to_string(),
        description: format!(
            "REFUSE the request with a Kerberos error. 'error' is one of: {}.",
            names.join(", ")
        ),
        parameters: vec![
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "The error, e.g. C_PRINCIPAL_UNKNOWN, S_PRINCIPAL_UNKNOWN, POLICY, \
                              CLIENT_REVOKED, KEY_EXPIRED"
                    .to_string(),
                required: true,
            },
            p("text", "string", "Optional e-text shown to the client"),
        ],
        example: json!({"type": "kerberos_refuse", "error": "C_PRINCIPAL_UNKNOWN"}),
        log_template: Some(LogTemplate::new().with_info("-> Kerberos refused")),
    }
}

/// A non-negative integer field, or `None` when absent.
fn secs(action: &Value, key: &str) -> Result<Option<i64>> {
    match action.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("'{key}' must be a non-negative number of seconds"))?;
            if n == 0 {
                return Err(anyhow!("'{key}' must be greater than zero"));
            }
            Ok(Some(i64::try_from(n).unwrap_or(i64::MAX)))
        }
    }
}

fn flag(action: &Value, key: &str) -> Result<bool> {
    match action.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(anyhow!("'{key}' must be true or false")),
    }
}

impl Protocol for KerberosProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            issue_ticket_action(),
            require_preauth_action(),
            refuse_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Kerberos"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            KERBEROS_AS_REQUEST_EVENT.clone(),
            KERBEROS_TGS_REQUEST_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>KERBEROS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "kerberos",
            "kdc",
            "kerberos kdc",
            "krb5",
            "key distribution center",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .connectionless()
            // Every undecided request gets a KRB-ERROR: KRB_ERR_GENERIC, with e-text saying
            // whether the model could not be reached or answered nothing usable. Never a
            // ticket; the model's own refusals cannot use the code.
            .answers_on_failure()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(88))
            .well_known_udp_port(88)
            .request_only("A KDC only answers AS-REQ and TGS-REQ; it never writes first")
            .max_inbound_bytes(codec::MAX_MESSAGE_LEN)
            .implementation(
                "Kerberos V5 KDC (RFC 4120) on UDP and TCP (4-octet length prefix) on one port. \
                 ASN.1 types from picky-krb, decoded only after an iterative DER walk bounds \
                 depth (24), element count (4096) and length (64 KiB). AS exchange with \
                 PA-ENC-TIMESTAMP pre-authentication verified in Rust (clock skew, replay \
                 cache) and KDC_ERR_PREAUTH_REQUIRED with PA-ETYPE-INFO2; TGS exchange with the \
                 TGT, authenticator and its keyed checksum over the request body verified, \
                 reply under the authenticator subkey when present. aes256- and \
                 aes128-cts-hmac-sha1-96 (RFC 3962), keys from configured passwords with \
                 PBKDF2; the TGS key is random per start. No DES, RC4, RFC 8009, FAST, PKINIT, \
                 PAC, cross-realm, renewal, validation, S4U or user-to-user. Per-source rate \
                 limit, lookaside cache for retransmissions, KRB_ERR_RESPONSE_TOO_BIG over \
                 UDP, KRB_ERR_FIELD_TOOLONG over TCP.",
            )
            .llm_control(
                "Policy only: whether a principal is admitted, which Kerberos error a refusal \
                 carries, whether to demand pre-authentication (including of principals that \
                 do not exist), and the lifetime, renewable lifetime and flags (forwardable, \
                 proxiable, renewable, ok-as-delegate) of each ticket within the configured \
                 ceilings. The model never sees or chooses a key, password, nonce or salt.",
            )
            .e2e_testing(
                "tests/server/kerberos/real_client_test.rs: MIT krb5 kinit/klist/kvno and \
                 Heimdal kinit/klist/kgetcred each get a TGT from NetGet with a password \
                 (pre-authenticated), see the model's lifetime and flags in klist, and get a \
                 service ticket that MIT kvno verifies against a keytab ktutil derived from \
                 the service's password; a wrong password is refused with \
                 PREAUTH_FAILED, an unknown principal with the model's error, and an \
                 unreachable model gives an error, never a ticket. Traffic from both is \
                 relayed and dissected by tshark's kerberos dissector over UDP and TCP. \
                 e2e_test.rs and codec_test.rs cover every mechanical refusal, the bounds and \
                 the fail-closed paths with NetGet's own client codec. Both peers are required: \
                 the tests fail, not skip, without them.",
            )
            .notes(
                "Experimental: two independent clients complete real sessions against it, but \
                 nobody has reviewed it beyond its tests and the pair job has not run in CI. \
                 FAILS CLOSED: an unreachable model, no usable answer or an action that could \
                 not be executed all produce a KRB-ERROR (decision=fail_closed_*). Passwords \
                 come only from the principal_passwords startup parameter, which is redacted \
                 wherever parameters are printed, and appear in no event.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Kerberos V5 KDC (AS and TGS exchanges) with model-decided admission and ticket policy"
    }

    fn example_prompt(&self) -> &'static str {
        "Run a Kerberos KDC for realm NETGET.TEST with alice (password wonderland) and \
         host/web.netget.test; give alice 8 hour forwardable tickets and refuse everyone else"
    }

    fn group_name(&self) -> &'static str {
        "Authentication"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "realm".to_string(),
                type_hint: "string".to_string(),
                description: "The realm this KDC serves, conventionally upper case".to_string(),
                required: false,
                example: json!("NETGET.TEST"),
                default: Some(json!(DEFAULT_REALM)),
            },
            ParameterDefinition {
                name: "principal_passwords".to_string(),
                type_hint: "object".to_string(),
                description: "Principal name -> password, for every user and service this KDC \
                              knows (e.g. {\"alice\": \"...\", \"host/web.netget.test\": \
                              \"...\"}). Keys are derived from these at startup; the passwords \
                              are never shown in events or logs. Required."
                    .to_string(),
                required: true,
                example: json!({"alice": "wonderland", "host/web.netget.test": "s3rvice-key"}),
                default: None,
            },
            ParameterDefinition {
                name: "no_preauth_principals".to_string(),
                type_hint: "array".to_string(),
                description: "Principals that may be issued a ticket without \
                              pre-authentication (every other principal must pre-authenticate)"
                    .to_string(),
                required: false,
                example: json!(["legacy-user"]),
                default: None,
            },
            ParameterDefinition {
                name: "max_ticket_lifetime_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Ceiling on any ticket's lifetime; longer grants are clamped"
                    .to_string(),
                required: false,
                example: json!(36000),
                default: Some(json!(DEFAULT_MAX_TICKET_LIFETIME_SECS)),
            },
            ParameterDefinition {
                name: "max_renewable_lifetime_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Ceiling on any ticket's renewable lifetime".to_string(),
                required: false,
                example: json!(604800),
                default: Some(json!(DEFAULT_MAX_RENEWABLE_LIFETIME_SECS)),
            },
            ParameterDefinition {
                name: "max_clock_skew_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Largest tolerated difference between a client's clock and this \
                              KDC's for pre-authentication and authenticators"
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(json!(DEFAULT_MAX_CLOCK_SKEW_SECS)),
            },
            ParameterDefinition {
                name: "max_requests_per_minute_per_source".to_string(),
                type_hint: "integer".to_string(),
                description: "Requests one source address may make per minute; the rest are \
                              dropped (UDP) or the connection closed (TCP)"
                    .to_string(),
                required: false,
                example: json!(600),
                default: Some(json!(DEFAULT_MAX_REQUESTS_PER_MINUTE)),
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let params = json!({
            "realm": "NETGET.TEST",
            "principal_passwords": {"alice": "wonderland", "host/web.netget.test": "s3rvice-key"}
        });
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 88,
                "base_stack": "kerberos",
                "startup_params": params,
                "instruction": "Require pre-authentication. Issue alice 8 hour forwardable \
                                tickets and service tickets for host/web.netget.test; refuse \
                                every other principal with C_PRINCIPAL_UNKNOWN."
            }),
            json!({
                "type": "open_server",
                "port": 88,
                "base_stack": "kerberos",
                "startup_params": params,
                "event_handlers": [{
                    "event_pattern": "kerberos_as_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'kerberos_issue_ticket', 'lifetime_secs': 28800}] if event['preauth'] == 'verified' and event['client'] == 'alice' else [{'type': 'kerberos_require_preauth'}] if event['client'] == 'alice' else [{'type': 'kerberos_refuse', 'error': 'C_PRINCIPAL_UNKNOWN'}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 88,
                "base_stack": "kerberos",
                "startup_params": params,
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "kerberos_refuse", "error": "POLICY", "text": "KDC closed"}]
                    }
                }]
            }),
        )
    }
}

impl Server for KerberosProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::KerberosServer::spawn(ctx).await })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        let ctx = self.ctx()?;
        let pending = ctx.pending.as_ref();
        let kdc = ctx.kdc.as_ref();
        match action_type {
            "kerberos_issue_ticket" => {
                let grant = Grant {
                    lifetime_secs: secs(&action, "lifetime_secs")?,
                    renewable_lifetime_secs: secs(&action, "renewable_lifetime_secs")?,
                    renewable: flag(&action, "renewable")?,
                    forwardable: flag(&action, "forwardable")?,
                    proxiable: flag(&action, "proxiable")?,
                    ok_as_delegate: flag(&action, "ok_as_delegate")?,
                };
                match kdc.issue(pending, &grant)? {
                    Issued::Ticket {
                        reply,
                        summary,
                        clamped,
                    } => self.record(
                        ctx,
                        if clamped {
                            "model_issue_clamped"
                        } else {
                            "model_issue"
                        },
                        summary.to_string(),
                        reply,
                    ),
                    Issued::Enforced {
                        reply,
                        decision,
                        detail,
                    } => self.record(ctx, decision, detail, reply),
                }
            }
            "kerberos_require_preauth" => {
                if pending.exchange != Exchange::As {
                    return Err(anyhow!(
                        "kerberos_require_preauth applies to AS requests only; refuse a TGS \
                         request with kerberos_refuse"
                    ));
                }
                let reply = kdc.preauth_required(pending)?;
                self.record(
                    ctx,
                    "model_require_preauth",
                    format!("{}: pre-authentication required", pending.client),
                    reply,
                )
            }
            "kerberos_refuse" => {
                let code = codec::model_refusal_code(
                    action
                        .get("error")
                        .context("kerberos_refuse requires 'error'")?,
                )?;
                let text = action.get("text").and_then(|v| v.as_str());
                if let Some(t) = text {
                    if t.len() > 256 {
                        return Err(anyhow!("'text' is limited to 256 bytes"));
                    }
                    if !t.is_ascii() {
                        return Err(anyhow!("'text' must be ASCII (KerberosString is IA5)"));
                    }
                }
                let reply = kdc.refuse(pending, code, text);
                self.record(
                    ctx,
                    "model_reject",
                    format!("{}: {}", pending.client, codec::error_name(code)),
                    reply,
                )
            }
            other => Err(anyhow!("Unknown Kerberos KDC action: {other}")),
        }
    }
}
