use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct AcmeProtocol;
impl AcmeProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> ACME {name}"))),
    }
}

/// RFC 8555 §6.7 error types a handler may refuse with, and the HTTP status each carries.
pub const REJECT_ERRORS: &[(&str, u16)] = &[
    ("rejectedIdentifier", 400),
    ("unsupportedIdentifier", 400),
    ("unauthorized", 403),
    ("caa", 403),
    ("badCSR", 400),
    ("invalidContact", 400),
    ("unsupportedContact", 400),
    ("incorrectResponse", 403),
    ("userActionRequired", 403),
    ("rateLimited", 429),
];

fn accept() -> ActionDefinition {
    action(
        "acme_accept",
        "Approve the request: register the account, create the order, mark the challenge valid, issue the certificate or revoke it. Rust builds every ACME object, URL, nonce and certificate.",
        vec![],
        json!({"type": "acme_accept"}),
    )
}
fn reject() -> ActionDefinition {
    action(
        "acme_reject",
        "Refuse the request with an RFC 8555 problem document. For a challenge this marks it (and its authorization and order) invalid.",
        vec![
            parameter("error", "string", "rejectedIdentifier, unsupportedIdentifier, unauthorized, caa, badCSR, invalidContact, unsupportedContact, incorrectResponse, userActionRequired or rateLimited", true),
            parameter("detail", "string", "Human-readable detail, up to 256 characters", true),
        ],
        json!({"type": "acme_reject", "error": "rejectedIdentifier", "detail": "this CA does not issue for that domain"}),
    )
}

pub static NEW_ACCOUNT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("acme_new_account", "A new key asks to register an account. The JWS signature, nonce and URL were checked by Rust.", accept().example.clone())
        .with_parameters(vec![
            parameter("contact", "array", "Contact URLs, e.g. [\"mailto:admin@example.org\"]", true),
            parameter("terms_of_service_agreed", "boolean", "Whether the client agreed to the terms of service", true),
            parameter("key_type", "string", "P-256, P-384, RSA or Ed25519", true),
            parameter("thumbprint", "string", "RFC 7638 thumbprint of the account key", true),
        ])
        .with_actions(vec![accept(), reject()])
});
pub static NEW_ORDER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "acme_new_order",
        "An account asks for a certificate for these identifiers",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter("account", "string", "The account URL", true),
        parameter("contact", "array", "The account's contact URLs", true),
        parameter(
            "identifiers",
            "array",
            "DNS names requested, lower-cased (wildcards as *.example.org)",
            true,
        ),
        parameter(
            "not_before",
            "string",
            "Requested notBefore, when given",
            false,
        ),
        parameter(
            "not_after",
            "string",
            "Requested notAfter, when given",
            false,
        ),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static VALIDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("acme_validate", "The client asks for a challenge to be validated. When Rust could check (http-01 with http01_target) it reports what it fetched; a mismatch is refused before this event.", accept().example.clone())
        .with_parameters(vec![
            parameter("account", "string", "The account URL", true),
            parameter("identifier", "string", "The DNS name being proven", true),
            parameter("challenge_type", "string", "http-01 or dns-01", true),
            parameter("token", "string", "The challenge token", true),
            parameter("key_authorization", "string", "The expected key authorization (token.thumbprint); for dns-01 the TXT value is its SHA-256, base64url", true),
            parameter("verified", "boolean", "true when Rust fetched the expected key authorization; null when Rust did not check", true),
        ])
        .with_actions(vec![accept(), reject()])
});
pub static FINALIZE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("acme_finalize", "A ready order submits its CSR. Rust verified the CSR signature and that it names exactly the order's identifiers.", accept().example.clone())
        .with_parameters(vec![
            parameter("account", "string", "The account URL", true),
            parameter("order", "string", "The URL of the order being finalized on this CA, e.g. https://ca.example/order/AbC123", true),
            parameter("identifiers", "array", "The names the certificate will carry", true),
            parameter("validity_days", "number", "Days the certificate will be valid", true),
        ])
        .with_actions(vec![accept(), reject()])
});
pub static REVOKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "acme_revoke",
        "An account asks to revoke a certificate it holds",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter("account", "string", "The account URL", true),
        parameter(
            "serial",
            "string",
            "The certificate serial number, hex",
            true,
        ),
        parameter("identifiers", "array", "The names on the certificate", true),
        parameter(
            "reason",
            "number",
            "RFC 5280 reason code, when given",
            false,
        ),
    ])
    .with_actions(vec![accept(), reject()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for AcmeProtocol {
    fn protocol_name(&self) -> &'static str {
        "ACME"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>ACME"
    }
    fn description(&self) -> &'static str {
        "ACME (RFC 8555) certificate authority: accounts, orders, http-01 and dns-01 challenges, finalization, certificates and revocation"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "acme",
            "rfc 8555",
            "certificate authority",
            "lets encrypt",
            "certbot",
            "lego",
            "pebble",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NEW_ACCOUNT_EVENT.clone(),
            NEW_ORDER_EVENT.clone(),
            VALIDATE_EVENT.clone(),
            FINALIZE_EVENT.clone(),
            REVOKE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("ca_name", "string", "Common name of the CA generated at startup", json!("Example Test CA"), Some(json!(super::DEFAULT_CA_NAME))),
            startup("validity_days", "integer", "Lifetime of issued certificates in days (1 to 397)", json!(30), Some(json!(super::DEFAULT_VALIDITY_DAYS))),
            startup("challenge_types", "array", "Challenge types offered for each identifier: http-01 and/or dns-01", json!(["http-01"]), Some(json!(super::DEFAULT_CHALLENGES))),
            startup("http01_target", "string", "host:port Rust connects to for http-01 validation, sending the identifier as Host; without it Rust does not fetch and the handler decides alone", json!("127.0.0.1:5002"), None),
            startup("terms_of_service", "string", "Terms-of-service URL announced in the directory; when set, new accounts must agree", json!("https://example.org/tos"), None),
            startup("tls_cert_file", "string", "PEM certificate chain to serve HTTPS with (with tls_key_file); plain HTTP without", json!("/etc/netget/acme.pem"), None),
            startup("tls_key_file", "string", "PEM private key for tls_cert_file", json!("/etc/netget/acme.key"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1 (optional rustls); RFC 8555 directory, nonces, flattened JWS verified with ring (ES256, ES384, RS256, EdDSA), RFC 7638 thumbprints, account/order/authorization/challenge state, http-01 fetching, CSR checks and issuance from a P-256 CA generated at startup with rcgen")
            .llm_control("Which accounts, orders, challenge validations, issuances and revocations to approve")
            .e2e_testing("tests/server/acme: lego 4.35.2 and certbot 5.8.0 (independent) register, order, answer http-01 (verified by Rust) and dns-01, finalize, download and revoke; refusals and JWS/nonce errors from the wire")
            .notes("In-memory protocol state (accounts by key, orders, authorizations, nonces, issued certificates), bounded and lost on stop. No keyChange, external account binding, pre-authorization, tls-alpn-01, OCSP, CRLs, ARI or profiles; dns-01 is never checked by Rust. Use only as a test CA.")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_BODY)
            .request_only("ACME answers each HTTP request; the CA pushes nothing")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Test ACME CA on port 14000 that issues for *.test names and refuses everything else"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"acme","port":14000,"instruction":"Issue certificates only for names under .test","startup_params":{"validity_days":30}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"acme_accept"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"acme_new_order","handler":{"type":"script","language":"python","code":"import json,sys\nd=json.load(sys.stdin)\nok=all(i.endswith('.test') for i in d['event']['identifiers'])\nprint(json.dumps({'actions':[{'type':'acme_accept'} if ok else {'type':'acme_reject','error':'rejectedIdentifier','detail':'only .test names'}]}))"}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"acme_accept"}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Security"
    }
}

impl Server for AcmeProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

pub fn check_answer(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("acme_accept") => {}
        Some("acme_reject") => {
            let e = v["error"].as_str().unwrap_or_default();
            ensure!(
                REJECT_ERRORS.iter().any(|(n, _)| *n == e),
                "unknown ACME error type {e:?}"
            );
            ensure!(
                v["detail"].as_str().is_some_and(|d| !d.is_empty()
                    && d.len() <= 256
                    && !crate::utils::sanitize::has_controls(&d)),
                "detail is 1 to 256 printable characters"
            );
        }
        _ => bail!("Unknown ACME server action"),
    }
    Ok(())
}
