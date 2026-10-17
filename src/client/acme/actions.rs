use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::acme::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct AcmeClientProtocol;
impl AcmeClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn register() -> ActionDefinition {
    action(
        "acme_register",
        "Create (or find) the account for this client's key with newAccount",
        vec![
            parameter(
                "contact",
                "array",
                "mailto: contact URLs, e.g. [\"mailto:ops@example.org\"]",
                false,
            ),
            parameter(
                "agree_tos",
                "boolean",
                "Agree to the CA's terms of service",
                true,
            ),
        ],
        json!({"type": "acme_register", "contact": ["mailto:ops@example.org"], "agree_tos": true}),
    )
}
fn order() -> ActionDefinition {
    action(
        "acme_order",
        "Open an order for DNS names and fetch its authorizations (challenge types, tokens, and the dns-01 TXT record each would need)",
        vec![parameter("identifiers", "array", "DNS names, e.g. [\"www.example.test\", \"*.example.test\"]", true)],
        json!({"type": "acme_order", "identifiers": ["www.example.test"]}),
    )
}
fn validate() -> ActionDefinition {
    action(
        "acme_validate",
        "Answer one authorization's challenge and wait for the CA's verdict. http-01 is served by this client's responder (http01_listen); for dns-01 the TXT record from acme_order must already be published.",
        vec![
            parameter("identifier", "string", "The DNS name whose authorization to answer (as in the order)", true),
            parameter("challenge_type", "string", "http-01 or dns-01", true),
        ],
        json!({"type": "acme_validate", "identifier": "www.example.test", "challenge_type": "http-01"}),
    )
}
fn finalize() -> ActionDefinition {
    action(
        "acme_finalize",
        "Generate a P-256 key and a CSR for the order's names, finalize, wait for issuance and download the certificate chain",
        vec![parameter("key_file", "string", "Path to write the new private key to (PEM, mode 0600); the key is discarded without it", false)],
        json!({"type": "acme_finalize"}),
    )
}
fn revoke() -> ActionDefinition {
    action(
        "acme_revoke",
        "Revoke the last certificate this client obtained",
        vec![parameter("reason", "number", "RFC 5280 reason code (0 unspecified, 1 keyCompromise, 4 superseded, 5 cessationOfOperation)", false)],
        json!({"type": "acme_revoke", "reason": 4}),
    )
}
fn deactivate() -> ActionDefinition {
    action(
        "acme_deactivate",
        "Deactivate the account (it cannot be used again)",
        vec![],
        json!({"type": "acme_deactivate"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this client",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        register(),
        order(),
        validate(),
        finalize(),
        revoke(),
        deactivate(),
        disconnect(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "acme_connected",
        "The CA's directory was read and an account key generated",
        register().example.clone(),
    )
    .with_parameters(vec![
        parameter("directory", "string", "The directory URL", true),
        parameter(
            "terms_of_service",
            "string",
            "Terms-of-service URL, when the CA has one",
            false,
        ),
        parameter(
            "external_account_required",
            "boolean",
            "Whether the CA requires external account binding (not supported here)",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("acme_response", "The CA's answer to the last action", disconnect().example.clone())
        .with_parameters(vec![
            parameter("operation", "string", "register, order, validate, finalize, revoke or deactivate", true),
            parameter("status", "number", "HTTP status of the final request", true),
            parameter("problem", "object", "The CA's problem document ({type, detail}) when it refused", false),
            parameter("account", "string", "register: the account URL", false),
            parameter("order_status", "string", "order and finalize: the order's status", false),
            parameter("authorizations", "array", "order: [{identifier, status, wildcard, challenges: [{type, status, token, dns_txt_name, dns_txt_value}]}]", false),
            parameter("challenge_status", "string", "validate: valid, invalid or pending", false),
            parameter("certificate", "string", "finalize: the PEM certificate chain", false),
        ])
        .with_actions(actions())
});

impl Protocol for AcmeClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ACME"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>ACME"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["acme", "rfc 8555", "certificate", "lets encrypt", "pebble"]
    }
    fn description(&self) -> &'static str {
        "ACME (RFC 8555) client: account, order, http-01 / dns-01 validation, finalization, download and revocation"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p("scheme", "string", "https (default) or http", json!("https"), Some(json!(super::DEFAULT_SCHEME))),
            p("directory_path", "string", "Path of the directory on the server", json!("/dir"), Some(json!(super::DEFAULT_DIRECTORY_PATH))),
            p("ca_file", "string", "PEM certificate(s) to trust for the CA's HTTPS endpoint, in addition to the system roots", json!("/etc/ssl/pebble.minica.pem"), None),
            p("http01_listen", "string", "host:port where this client serves http-01 key authorizations", json!("127.0.0.1:5002"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("reqwest; flattened JWS signed ES256 with ring, nonce handling with badNonce retry, an http-01 responder on hyper, CSRs from rcgen")
            .llm_control("Which names to order, which challenges to answer, and when to finalize, revoke or deactivate")
            .e2e_testing("tests/client/acme: Pebble 2.10.1 (independent) with pebble-challtestsrv as its DNS: register, order, http-01 validated by Pebble against this client's responder, dns-01 with the TXT record published through challtestsrv, finalize, download, revoke")
            .notes("ES256 account keys only; no keyChange, external account binding, pre-authorization, tls-alpn-01, profiles or ARI.")
            .max_inbound_bytes(super::MAX_RESPONSE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Get a certificate for www.example.test from the ACME server at localhost:14000 using http-01 on port 5002"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"acme","remote_addr":"localhost:14000","instruction":"Get a certificate for www.example.test","startup_params":{"directory_path":"/dir","http01_listen":"127.0.0.1:5002"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"acme_connected","handler":{"type":"static","actions":[register().example]}},
            {"event_pattern":"acme_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\nd=json.load(sys.stdin)['event']\nnext={'register':{'type':'acme_order','identifiers':['www.example.test']},'order':{'type':'acme_validate','identifier':'www.example.test','challenge_type':'http-01'},'validate':{'type':'acme_finalize'}}.get(d['operation'])\nprint(json.dumps({'actions':[next] if next and d['status']<300 else []}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Security"
    }
}

impl Client for AcmeClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 64 * 1024, 2_000, 8),
            "action exceeds the ACME bounds"
        );
        match v["type"].as_str() {
            Some("acme_register") => {
                ensure!(v["agree_tos"].is_boolean(), "agree_tos is true or false");
                if let Some(c) = v.get("contact").filter(|c| !c.is_null()) {
                    ensure!(
                        c.as_array().is_some_and(|l| l.len() <= 10
                            && l.iter().all(|u| u.as_str().is_some_and(
                                |u| u.len() <= 256 && !crate::utils::sanitize::has_controls(&u)
                            ))),
                        "contact is up to 10 URLs"
                    );
                }
            }
            Some("acme_order") => ensure!(
                v["identifiers"].as_array().is_some_and(|l| !l.is_empty()
                    && l.len() <= 100
                    && l.iter().all(|i| i.as_str().is_some_and(|i| !i.is_empty()
                        && i.len() <= 253
                        && i.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-*".contains(&b))))),
                "identifiers is 1 to 100 DNS names"
            ),
            Some("acme_validate") => {
                ensure!(
                    v["identifier"]
                        .as_str()
                        .is_some_and(|i| !i.is_empty() && i.len() <= 253),
                    "identifier is a DNS name from the order"
                );
                ensure!(
                    matches!(v["challenge_type"].as_str(), Some("http-01" | "dns-01")),
                    "challenge_type is http-01 or dns-01"
                );
            }
            Some("acme_finalize") => {
                if let Some(k) = v.get("key_file").filter(|k| !k.is_null()) {
                    ensure!(
                        k.as_str().is_some_and(|k| !k.is_empty()
                            && k.len() <= 1024
                            && !crate::utils::sanitize::has_controls(&k)),
                        "key_file is a path"
                    );
                }
            }
            Some("acme_revoke") => {
                if let Some(r) = v.get("reason").filter(|r| !r.is_null()) {
                    ensure!(
                        r.as_u64().is_some_and(|r| r <= 10 && r != 7),
                        "reason is an RFC 5280 code 0 to 10, not 7"
                    );
                }
            }
            Some("acme_deactivate") => {}
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown ACME client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
