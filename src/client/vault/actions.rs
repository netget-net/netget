use crate::protocol::log_template::LogTemplate;
use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, Parameter, ParameterDefinition,
    },
    protocol::{ConnectContext, EventType},
    state::AppState,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct VaultClientProtocol;
impl VaultClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn request() -> ActionDefinition {
    ActionDefinition{name:"vault_request".into(),description:"Selected Vault system reads and KV v2 read/write/list/metadata operations. No raw HTTP routes, dynamic-secret engines or administration.".into(),parameters:vec![p("operation","string","seal_status, health, leader, read, write, list, or metadata",true),p("mount","string","KV v2 mount override; default startup kv_mount",false),p("path","string","KV relative ASCII name segments; list accepts a folder slash; empty only for mount-root list",false),p("version","integer","read: nonnegative version; omitted/0 reads latest",false),p("data","object","write: secret object, encoded into native KV v2 data envelope",false),p("cas","integer","write: expected current version;0 creates only when no versions exist",false)],example:json!({"type":"vault_request","operation":"read","path":"fixture/app","version":1}),log_template:Some(LogTemplate::new().with_info("Vault {operation} request queued"))}
}
fn login() -> ActionDefinition {
    ActionDefinition{name:"vault_userpass_login".into(),description:"Authenticate selected userpass credentials. A new attempt discards the previous session token; only a complete validated success installs one token. Login password and returned token are omitted from events and incidental diagnostics.".into(),parameters:vec![p("username","string","Bounded ASCII userpass username",true),p("password","string","Userpass password; not included in result metadata",true),p("auth_mount","string","Userpass mount override; default startup auth_mount",false)],example:json!({"type":"vault_userpass_login","username":"fixture-reader","password":"fixture-password"}),log_template:Some(LogTemplate::new().with_info("Vault userpass authentication queued"))}
}
fn clear() -> ActionDefinition {
    ActionDefinition{name:"vault_clear_token".into(),description:"Forget this client's credential locally. Does not revoke a Vault token or end any backend lease.".into(),parameters:vec![],example:json!({"type":"vault_clear_token"}),log_template:Some(LogTemplate::new().with_info("Vault local credential cleared"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel pending I/O and stop this logical client".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("Vault client disconnected")),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![request(), login(), clear(), disconnect()]
}
fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, request().example)
        .with_parameters(params)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "vault_connected",
        "Public seal status succeeded; configured token has not been verified",
        vec![
            p(
                "origin",
                "string",
                "Vault service HTTP or HTTPS origin",
                true,
            ),
            p("kv_mount", "string", "Default KV v2 mount", true),
            p("auth_mount", "string", "Default userpass mount", true),
            p(
                "token_present",
                "boolean",
                "Credential configured, not proof that Vault accepts it",
                true,
            ),
            p(
                "authentication_verified",
                "boolean",
                "False: startup seal probe is public",
                true,
            ),
            p(
                "seal",
                "object",
                "Typed seal status, including initialized/sealed/threshold/progress",
                true,
            ),
        ],
    )
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("vault_response","Complete selected Vault response; legitimate health status codes preserve their native meaning",vec![p("request","object","Originating typed action with credentials omitted",true),p("operation","string","Selected operation",true),p("status","integer","HTTP status; health may return200/429/472/473/474/501/503/530",true),p("data","object","Typed system body or KV v2 envelope. Reads keep data and version metadata distinct; writes return positive version acknowledgement; lists return keys with folder suffixes; metadata retains versions, deletion/destruction state and RFC3339 times. No secret store is created.",true)])
});
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("vault_authentication","Validated userpass success or explicit local credential clear",vec![p("request","object","Login receipt excludes password; clear receipt has no credential",true),p("operation","string","login or clear_token",true),p("status","integer|null","HTTP200 for login;null for local clear",true),p("token_present","boolean","One ephemeral credential currently retained",true),p("authentication_verified","boolean","True only after complete validated login auth; false for clear",true),p("auth","object|null","Token accessor, policies, metadata, lease_duration seconds, renewable, entity_id, service/batch token_type and optional orphan/num_uses. client_token and MFA challenge are never exposed; MFA continuation is refused.",true),p("request_id","string","Native login request identifier; absent for local clear",false),p("warnings","array|null","Credential-redacted login warnings; absent for local clear",false)])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "vault_request_error",
        "Request refused or failed; no partial success, session remains available",
        vec![
            p(
                "request",
                "object",
                "Originating action with password omitted",
                true,
            ),
            p(
                "status",
                "integer|null",
                "Native HTTP status when received",
                true,
            ),
            p("category", "string", "http, schema, or transport", true),
            p(
                "errors",
                "array",
                "Credential-redacted native/validation/deadline diagnostics",
                true,
            ),
            p(
                "token_present",
                "boolean",
                "Current credential presence; failed login leaves it false",
                true,
            ),
        ],
    )
});
impl Protocol for VaultClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Vault"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Vault"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["vault", "hashicorp", "kv v2"]
    }
    fn description(&self) -> &'static str {
        "Selected typed Vault authentication and KV v2 operations"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn example_prompt(&self) -> &'static str {
        "Read version1 of fixture/app from Vault at localhost:8200"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            AUTH_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition{name:"token".into(),type_hint:"string".into(),description:"Optional bounded Vault token; syntax checked, never authenticated by the public startup probe. Ephemeral header only, no credential file.".into(),required:false,example:json!("hvs.fixture-token"),default:None},
        ParameterDefinition{name:"kv_mount".into(),type_hint:"string".into(),description:"Default KV v2 mount of bounded ASCII segments; sys is refused".into(),required:false,example:json!("secret"),default:Some(json!(super::DEFAULT_KV_MOUNT))},
        ParameterDefinition{name:"auth_mount".into(),type_hint:"string".into(),description:"Default selected userpass mount, excluding sys".into(),required:false,example:json!("userpass"),default:Some(json!(super::DEFAULT_AUTH_MOUNT))},
        ParameterDefinition{name:"request_timeout_secs".into(),type_hint:"integer".into(),description:"Whole request connect/head/body deadline1..30 seconds".into(),required:false,example:json!(10),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))},
    ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(8200).implementation("Bounded HTTP(S), typed public system probes, KV v2 version/CAS/metadata and selected userpass login").llm_control("Selected native authentication and secret operations, redacted auth metadata, event routing/injection and shared memory").e2e_testing("tests/client/vault: native isolated Vault daemon and CLI, programmable NetGet pair, handler paths, schema/bounds/deadlines/cancellation; existing server native CLI tests").notes("One ephemeral token and one latest bounded password for reflection redaction, no protocol secret database. Body1MiB, arrays10000, object fields256, strings16KiB, depth32/nodes65536; in-memory actions preflight retained content8MiB before copying; one request, queues8,4 followups. HTTP(S) native with certificate verification; browser HTTP only. No custom trust, client certificates, namespaces, redirects, proxies, cookie state, token helpers/files, automatic auth/renewal/retry, response wrapping, MFA, OAuth/OIDC/AppRole, dynamic-secret engines, deletion/patch/undelete/destroy or administration. Clear is local, never backend revocation. Public seal probe does not verify startup tokens. Existing programmable KV v2 server auth/login refusal remains.").max_inbound_bytes(super::api::MAX_BODY).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","base_stack":"vault","protocol":"vault","remote_addr":"127.0.0.1:8200","instruction":"Read Vault health, then explain initialized, sealed and standby status"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"vault_connected","handler":{"type":"static","actions":[{"type":"vault_request","operation":"health"}]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\njson.dump({'actions':[{'type':'vault_request','operation':'health'}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for VaultClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        if !super::api::action_within_budget(&value) {
            crate::utils::json_budget::drop_iteratively(value);
            bail!("Vault action depth/node/retained-content limit");
        }
        match value["type"].as_str() {
            Some("vault_request" | "vault_userpass_login" | "vault_clear_token") => {
                super::api::request(&value, super::DEFAULT_KV_MOUNT, super::DEFAULT_AUTH_MOUNT)?;
                Ok(ClientActionResult::Custom {
                    name: "vault_request".into(),
                    data: value,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown Vault client action"),
        }
    }
}
