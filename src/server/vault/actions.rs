//! Vault KV v2 actions.
//!
//! Three events — read (data or metadata), write, list — and four actions. The model answers
//! with key/value maps, key names and version numbers; NetGet wraps them in the envelope the
//! Vault client decodes (`request_id`, `lease_*`, the KV v2 `data`/`metadata` split).
//!
//! The token is never an event field. The model sees `token_present`,
//! `token_matches_configured` and `token_configured`, which is enough to refuse with a 403 and
//! never enough to leak the credential into a prompt, a log or a script's stdin.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::api;

const TOKEN_NOTE: &str = "token_present / token_matches_configured / token_configured describe \
     the X-Vault-Token header without revealing it; refuse with send_vault_error status 403 \
     errors [\"permission denied\"] when a configured token does not match. With no token \
     configured any non-empty token counts as matching.";

/// `GET <mount>/data/<path>` (what = "data") or `GET <mount>/metadata/<path>` (what =
/// "metadata").
pub static VAULT_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vault_read",
        format!(
            "A Vault client (vault kv get, vault kv metadata get, an SDK) read the secret at \
             `path` in the KV v2 mount `mount`. Answer with send_vault_secret: its data for \
             what=\"data\" (version, when present, is the version asked for), or just version \
             and created_time for what=\"metadata\". Use send_vault_error status 404 with no \
             errors if no such secret exists. {TOKEN_NOTE}"
        ),
        json!({
            "type": "send_vault_secret",
            "data": {"username": "app", "password": "s3cr3t"},
            "version": 3
        }),
    )
    .with_actions(vec![send_vault_secret_action(), send_vault_error_action()])
});

/// `PUT`/`POST <mount>/data/<path>`.
pub static VAULT_WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vault_write",
        format!(
            "A Vault client (vault kv put) wrote `data` to `path` in the KV v2 mount `mount`. \
             Remember it if later reads should return it, then answer send_vault_write_ok with \
             the new version number (one more than the previous version of this path, 1 for a \
             new path). `cas`, when present, is the version the client expects to replace. \
             {TOKEN_NOTE}"
        ),
        json!({"type": "send_vault_write_ok", "version": 1}),
    )
    .with_actions(vec![
        send_vault_write_ok_action(),
        send_vault_error_action(),
    ])
});

/// `LIST <mount>/metadata/<path>` (or `GET …?list=true`).
pub static VAULT_LIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vault_list",
        format!(
            "A Vault client (vault kv list) listed the keys under `path` in the KV v2 mount \
             `mount` (an empty path is the mount's root). Answer send_vault_list with the \
             names directly under it, folders ending in '/'. Use send_vault_error status 404 \
             with no errors if nothing is there. {TOKEN_NOTE}"
        ),
        json!({"type": "send_vault_list", "keys": ["db", "api-keys/"]}),
    )
    .with_actions(vec![send_vault_list_action(), send_vault_error_action()])
});

/// Vault protocol handler.
pub struct VaultProtocol;

impl VaultProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for VaultProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for VaultProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_vault_secret_action(),
            send_vault_write_ok_action(),
            send_vault_list_action(),
            send_vault_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Vault"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            VAULT_READ_EVENT.clone(),
            VAULT_WRITE_EVENT.clone(),
            VAULT_LIST_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>VAULT"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "vault",
            "hashicorp vault",
            "openbao",
            "secrets engine",
            "kv v2",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta on evidence: tests/server/vault/real_client_test.rs drives HashiCorp's own
            // vault CLI through status, kv put/get/list/metadata get, a 404, a 403 and a 405,
            // asserting it prints exactly the handler's values, and hard-fails when the binary
            // is absent. Not Stable: one client, no fuzz target, no pcap-oracle test, KV v2 only.
            .state(DevelopmentState::Beta)
            .well_known_port(8200)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "hyper HTTP/1.1, plain HTTP. sys/seal-status, sys/health, sys/leader and the \
                 CLI's KV-version preflight (sys/internal/ui/mounts/<path>, answering KV v2 for \
                 every configured mount) are served deterministically; KV v2 data reads, \
                 metadata reads, writes and lists (LIST or GET ?list=true) raise vault_read / \
                 vault_write / vault_list and the model's answer is wrapped in Vault's \
                 envelope by NetGet.",
            )
            .llm_control(
                "Every secret, key listing and version number. NetGet stores nothing: the model \
                 keeps what was written (memory or the SQLite facility) if later reads should \
                 return it. The token is shown to the model only as booleans.",
            )
            .e2e_testing(
                "tests/server/vault/real_client_test.rs - the real vault CLI (VAULT_ADDR at \
                 NetGet, HOME a temp dir so no token helper is read) runs status, kv put, kv \
                 get (-field and -format=json), kv list and kv metadata get against a script \
                 handler and must print exactly its values. HARD FAILS when vault is absent. \
                 e2e_test.rs covers the mocked model, including a token mismatch refused 403.",
            )
            .notes(
                "KV version 2 only, on the mounts named by kv_mounts (default: secret). Not \
                 implemented: KV v1, delete / undelete / destroy / patch / metadata writes \
                 (405), every other secrets engine and auth method, sys/mounts, token lookup, \
                 policies, leases, TLS. Authentication is the model's decision: with a token \
                 startup parameter the event says whether the presented token matches; with \
                 none, any token is accepted and the event says so (token_configured false).",
            )
            .max_inbound_bytes(super::MAX_REQUEST_BODY_BYTES)
            // LLM failure: 503 + Retry-After (overloaded) or 500, each as Vault's
            // {"errors": [category]} - the CLI prints it after "Error making API request".
            .answers_on_failure()
            .request_only("The Vault API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "HashiCorp Vault (KV v2) whose secrets the model keeps"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a Vault server on port 8200 whose secret mount holds database credentials at \
         app/db and an API key at app/stripe"
    }

    fn group_name(&self) -> &'static str {
        "AI & API"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "token".to_string(),
                type_hint: "string".to_string(),
                description: "The token clients must present in X-Vault-Token. Events report \
                              whether it matched (never the token). Without it, any non-empty \
                              token counts as matching."
                    .to_string(),
                required: false,
                example: json!("hvs.netget-dev-token"),
                default: None,
            },
            ParameterDefinition {
                name: "kv_mounts".to_string(),
                type_hint: "array".to_string(),
                description: "KV version 2 mount paths, e.g. [\"secret\", \"kv/prod\"] \
                              (default [\"secret\"]). Paths under any other mount are 404."
                    .to_string(),
                required: false,
                example: json!(["secret"]),
                default: None,
            },
            ParameterDefinition {
                name: "vault_version".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Version reported by vault status and sys/health (default {}).",
                    super::DEFAULT_VAULT_VERSION
                ),
                required: false,
                example: json!("1.18.3"),
                default: Some(serde_json::json!(super::DEFAULT_VAULT_VERSION)),
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8200,
                "base_stack": "vault",
                "instruction": "Vault for a payments service. secret/app/db holds username \
                                payments and password Tr0ub4dor&3 (version 4); secret/app/stripe \
                                holds api_key sk_test_123. Keep anything written in memory and \
                                return it on later reads with the version incremented. Refuse \
                                with 403 permission denied when the token does not match.",
                "startup_params": {"token": "hvs.netget-dev-token"}
            }),
            json!({
                "type": "open_server",
                "port": 8200,
                "base_stack": "vault",
                "event_handlers": [
                    {
                        "event_pattern": "vault_read",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "import json, sys\nevent = json.load(sys.stdin)['event']\nsecrets = {'app/db': {'username': 'app', 'password': 's3cr3t'}}\nif not event.get('token_matches_configured'):\n    act = {'type': 'send_vault_error', 'status': 403, 'errors': ['permission denied']}\nelif event['path'] in secrets:\n    act = {'type': 'send_vault_secret', 'data': secrets[event['path']], 'version': 2}\nelse:\n    act = {'type': 'send_vault_error', 'status': 404, 'errors': []}\nprint(json.dumps({'actions': [act]}))"
                        }
                    },
                    {
                        "event_pattern": "vault_list",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "import json, sys\nevent = json.load(sys.stdin)['event']\nkeys = {'': ['app/'], 'app': ['db']}.get(event['path'].strip('/'))\nact = {'type': 'send_vault_list', 'keys': keys} if keys else {'type': 'send_vault_error', 'status': 404, 'errors': []}\nprint(json.dumps({'actions': [act]}))"
                        }
                    },
                    {
                        "event_pattern": "vault_write",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "import json, sys\nevent = json.load(sys.stdin)['event']\nprint(json.dumps({'actions': [{'type': 'send_vault_write_ok', 'version': event.get('cas', 0) + 1}]}))"
                        }
                    }
                ]
            }),
            json!({
                "type": "open_server",
                "port": 8200,
                "base_stack": "vault",
                "event_handlers": [{
                    "event_pattern": "vault_read",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_vault_secret",
                            "data": {"username": "app", "password": "s3cr3t"},
                            "version": 1
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for VaultProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let mut token = None;
            let mut mounts = vec!["secret".to_string()];
            let mut version = super::DEFAULT_VAULT_VERSION.to_string();
            if let Some(params) = ctx.startup_params.as_ref() {
                token = params
                    .get_optional_string("token")?
                    .filter(|t| !t.is_empty());
                if let Some(list) = params.get_optional_array("kv_mounts")? {
                    let mut parsed = Vec::with_capacity(list.len());
                    for m in list {
                        let m = m
                            .as_str()
                            .map(|s| s.trim_matches('/').to_string())
                            .filter(|s| {
                                !s.is_empty()
                                    && !s.starts_with("sys")
                                    && s.split('/').all(|seg| {
                                        !seg.is_empty()
                                            && seg.chars().all(|c| {
                                                c.is_ascii_alphanumeric()
                                                    || matches!(c, '-' | '_' | '.')
                                            })
                                    })
                            })
                            .with_context(|| {
                                format!(
                                    "kv_mounts entry {m} must be a mount path like \"secret\" \
                                     or \"kv/prod\" (and not under sys/)"
                                )
                            })?;
                        parsed.push(m);
                    }
                    if parsed.is_empty() {
                        anyhow::bail!("kv_mounts must name at least one mount");
                    }
                    mounts = parsed;
                }
                if let Some(v) = params.get_optional_string("vault_version")? {
                    version = v;
                }
            }
            super::VaultServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                super::VaultConfig {
                    identity: api::VaultIdentity {
                        version,
                        cluster_name: "vault-cluster-netget".to_string(),
                    },
                    kv_mounts: mounts,
                    token,
                },
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        let refuse = |reason: String| anyhow::anyhow!("{action_type} refused: {reason}");
        let mut data = action.clone();
        if let Some(obj) = data.as_object_mut() {
            obj.remove("type");
        }
        match action_type {
            "send_vault_secret" => {
                api::render_secret(&data).map_err(refuse)?;
            }
            "send_vault_write_ok" => {
                api::render_write_ok(&data).map_err(refuse)?;
            }
            "send_vault_list" => {
                api::render_list(&data).map_err(refuse)?;
            }
            "send_vault_error" => {
                api::render_error(&data).map_err(refuse)?;
            }
            other => return Err(anyhow::anyhow!("Unknown Vault action: {other}")),
        }
        Ok(ActionResult::Custom {
            name: action_type.to_string(),
            data,
        })
    }
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn send_vault_secret_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_vault_secret".to_string(),
        description: "Answer a vault_read with the secret. For what=\"data\" give its key/value \
                      pairs; for what=\"metadata\" only version and created_time matter."
            .to_string(),
        parameters: vec![
            param(
                "data",
                "object",
                "The secret's key/value pairs, e.g. {\"username\": \"app\", \"password\": \"...\"}",
                false,
            ),
            param(
                "version",
                "number",
                "The secret's version, a positive integer (default 1)",
                false,
            ),
            param(
                "created_time",
                "string",
                "When this version was written, RFC 3339 (default: now)",
                false,
            ),
            param(
                "custom_metadata",
                "object",
                "Optional string key/value metadata attached to the secret",
                false,
            ),
        ],
        example: json!({
            "type": "send_vault_secret",
            "data": {"username": "app", "password": "s3cr3t"},
            "version": 3,
            "created_time": "2026-09-01T10:00:00Z"
        }),
        log_template: Some(LogTemplate::new().with_info("-> Vault secret v{version}")),
    }
}

fn send_vault_write_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_vault_write_ok".to_string(),
        description: "Acknowledge a vault_write: the secret is stored as this version.".to_string(),
        parameters: vec![
            param(
                "version",
                "number",
                "The version the write created: previous version + 1, or 1 for a new path",
                false,
            ),
            param(
                "created_time",
                "string",
                "When the write happened, RFC 3339 (default: now)",
                false,
            ),
        ],
        example: json!({"type": "send_vault_write_ok", "version": 2}),
        log_template: Some(LogTemplate::new().with_info("-> Vault write v{version}")),
    }
}

fn send_vault_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_vault_list".to_string(),
        description: "Answer a vault_list with the names directly under the path.".to_string(),
        parameters: vec![param(
            "keys",
            "array",
            "Names directly under the listed path; a folder ends with '/', e.g. [\"db\", \"keys/\"]",
            true,
        )],
        example: json!({"type": "send_vault_list", "keys": ["db", "stripe", "keys/"]}),
        log_template: Some(LogTemplate::new().with_info("-> Vault list")),
    }
}

fn send_vault_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_vault_error".to_string(),
        description: "Refuse a request in Vault's error shape. 404 with no errors is 'no value \
                      found'; 403 [\"permission denied\"] is a bad or missing token."
            .to_string(),
        parameters: vec![
            param(
                "status",
                "number",
                "HTTP status: 404 not found, 403 permission denied, 400 bad request",
                false,
            ),
            param(
                "errors",
                "array",
                "Error strings the client prints, e.g. [\"permission denied\"]; empty for a 404",
                false,
            ),
        ],
        example: json!({"type": "send_vault_error", "status": 403, "errors": ["permission denied"]}),
        log_template: Some(LogTemplate::new().with_info("-> Vault error {status}")),
    }
}
