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
pub struct OciRegistryClientProtocol;
impl OciRegistryClientProtocol {
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
fn a(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let intent = match name {
        "oci_request" => "request one read-only registry response; await validation",
        "oci_authenticate" => {
            "request a token for the last challenge; await token-service response"
        }
        "oci_set_token" => {
            "set a transient token for later requests; authorization remains unverified"
        }
        "oci_clear_token" => "stop sending Authorization; server revocation remains unverified",
        "disconnect" => "cancel the pending request and stop owned client tasks",
        _ => unreachable!("only declared OCI actions receive a log template"),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_debug(format!("OCI {name}: {intent}")),
        ),
    }
}
pub fn actions() -> Vec<ActionDefinition> {
    vec![
    a("oci_request","Selected read-only Distribution v2 probe/catalog/tags/manifest/manifest_head/blob/blob_head. One request at a time; no automatic paging, auth retries or redirects. Blob downloads verify exact bytes and omit binary content from events.",vec![p("operation","string","Selected operation",true),p("repository","string","Lowercase OCI repository, up to255bytes; required except probe/catalog",false),p("reference","string","Manifest tag or lowercase sha256 digest; blob requires sha256 digest",false),p("n","integer","Catalog/tags page count1..1000, default100",false),p("last","string","Explicit catalog/tags cursor from prior next_last",false),p("expected_size","integer","Optional blob descriptor size to verify; download cap4MiB",false)],json!({"type":"oci_request","operation":"manifest","repository":"library/demo","reference":"latest"})),
    a("oci_authenticate","GET a Bearer token from the last native401 challenge. The token realm must match the registry or explicit startup trusted_token_origin. Optional basic credentials must appear together; otherwise request anonymously. Token issuance does not prove registry authorization, and the original pull is not replayed.",vec![p("username","string","Token-service basic principal, up to256bytes",false),p("password","string","Token-service password, up to16KiB",false)],json!({"type":"oci_authenticate","username":"reader","password":"fixture-password"})),
    a("oci_set_token","Set a transient opaque Bearer token for subsequent requests. No authentication success inferred. Requires verified HTTPS or numeric loopback HTTP.",vec![p("token","string","Bounded Bearer token, up to16KiB; never exposed in events",true)],json!({"type":"oci_set_token","token":"fixture-token"})),
    a("oci_clear_token","Stop sending Authorization; no server revocation implied",vec![],json!({"type":"oci_clear_token"})),
    a("disconnect","Cancel owned pending request and stop both client tasks",vec![],json!({"type":"disconnect"})),
]
}
fn event(name: &str, description: &str, parameters: Vec<Parameter>, example: Value) -> EventType {
    EventType::new(name, description, example)
        .with_parameters(parameters)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("oci_connected","Completed native unauthenticated v2 probe:200 or selected401 challenge. Startup token presence is not authentication proof.",vec![p("origin","string","Direct registry origin",true),p("data","object","Native probe result/challenge",true),p("token_present","boolean","Transient token configured",true),p("authentication_verified","boolean","False: public probe does not verify credentials",true)],json!({"type":"oci_request","operation":"tags","repository":"library/demo"}))
});
pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("oci_result","Complete validated native read response. GET manifest/blob digest_verified means exact raw response bytes were hashed; HEAD never proves content integrity.",vec![p("operation","string","Selected operation",true),p("status","integer","Native HTTP status",true),p("repository","string|null","Requested repository",true),p("reference","string|null","Requested tag/digest",true),p("data","object","Typed list/continuation, validated manifest or blob metadata/text; binary/large text content omitted",true)],json!({"type":"disconnect"}))
});
pub static CHALLENGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("oci_auth_challenge","Native401 with selected Bearer realm/service/pull scopes. Credentials/tokens excluded. Exchange requires trusted token origin; pull not replayed.",vec![p("operation","string","Challenged operation",true),p("status","integer","Native unauthorized HTTP401 response status",true),p("errors","array|null","Native OCI errors if supplied",true),p("challenge","object","Parsed Bearer realm/service/scopes",true)],json!({"type":"oci_authenticate"}))
});
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("oci_authentication","Local token set/clear or native token-service issuance. Never claims backend authorization without a registry response.",vec![p("operation","string","set_token, clear_token or authenticate",true),p("data","object","On exchange: token_received, registry_authorization_verified=false, native optional expiry/issue time and effective transient lifetime",false),p("token_present","boolean","On local token operations only",false),p("authentication_verified","boolean","False for local token operations",false)],json!({"type":"oci_request","operation":"tags","repository":"library/demo"}))
});
pub static FAILURE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "oci_failure",
        "Native HTTP error with validated OCI error envelope; no retry or invented success",
        vec![
            p("operation", "string", "Selected operation", true),
            p("status", "integer", "Native HTTP400..599 status", true),
            p(
                "errors",
                "array|null",
                "Native codes/messages/details, credential reflections omitted",
                true,
            ),
            p(
                "retry_after",
                "string|null",
                "Optional native Retry-After; no automatic sleep/retry",
                true,
            ),
        ],
        json!({"type":"disconnect"}),
    )
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "oci_request_error",
        "Local action/transport/schema/deadline refusal; native success not inferred",
        vec![
            p("category", "string", "action or transport_or_schema", true),
            p(
                "error",
                "string",
                "Fixed bounded refusal text, no peer payload or credentials",
                true,
            ),
        ],
        json!({"type":"disconnect"}),
    )
});
impl Protocol for OciRegistryClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "oci-registry"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OCI"
    }
    fn description(&self) -> &'static str {
        "Selected OCI registry pulls, raw-byte digests and trusted Bearer token exchange"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["oci", "registry", "container", "manifest", "blob"]
    }
    fn group_name(&self) -> &'static str {
        "Package Management"
    }
    fn example_prompt(&self) -> &'static str {
        "Read OCI manifest/blob metadata, verify native digests and handle trusted token challenges"
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
            RESULT_EVENT.clone(),
            CHALLENGE_EVENT.clone(),
            AUTH_EVENT.clone(),
            FAILURE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition{name:"request_timeout_secs".into(),type_hint:"integer".into(),description:"Whole startup/operation deadline1..30seconds, default15".into(),required:false,example:json!(15),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))},
        ParameterDefinition{name:"trusted_token_origin".into(),type_hint:"string".into(),description:"Optional explicit token-service HTTP(S) origin. Credentials only over verified HTTPS or numeric loopback HTTP; default trusts the registry origin only".into(),required:false,example:json!("https://auth.example"),default:None},
        ParameterDefinition{name:"token".into(),type_hint:"string".into(),description:"Optional transient Bearer token for later requests, up to16KiB; public startup probe sends none".into(),required:false,example:json!("fixture-token"),default:None},
    ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(5000).implementation("Direct Distribution v2 selected GET/HEAD pulls, OCI/Docker schema2 manifests/indexes, SHA256 exact-byte verification, explicit Bearer challenge/token exchange").llm_control("Typed operations/native results/errors, common memory, handlers and injection; no content or credentials database").e2e_testing("tests/client/oci_registry: independent unmodified crane registry and SDK CLI, existing server pair, authentication fixture, handlers/model paths, bounds and owned cancellation").notes("Native HTTP and verified HTTPS; browser HTTP only. Message4MiB, manifest1MiB, JSONdepth32/nodes65536/retained8MiB, strings64KiB, list/descriptors1000, action/event queues8/injection16/followups4, whole deadline1..30seconds. Only sha256, OCI and Docker v2 schema2 manifest/index media types. Binary or over64KiB text blobs expose verified size/digest and content_omitted, without files. Legacy Docker headers optional. HEAD exposes unverified native metadata. Pagination is explicit validated relative same-route continuation; full pages without Link require a cursor request to establish completion. Token origins explicitly trusted; credentials never forwarded on redirect, HTTPS verification uses reqwest configured trust roots, no trust overrides. Latest bounded token/password/basic credential retained only transiently for reflection redaction. Token issuance never claims registry authorization. No uploads/deletes, referrers/fallback, Docker schema1, embedded descriptor data, foreign-layer URL following, redirect following, Range/resume, artifact platform resolution, recursive image pulling, credentials files/helpers, JWT validation, OAuth POST/refresh/offline tokens, automatic auth replay/retry/paging, browser HTTPS, or conformance/capture claim.").max_inbound_bytes(super::api::MAX_BODY).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"oci-registry","base_stack":"oci-registry","remote_addr":"http://127.0.0.1:5000","instruction":"List library/demo tags and stop after one validated page"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{ "event_pattern":"oci_connected","handler":{"type":"static","actions":[{"type":"oci_request","operation":"tags","repository":"library/demo"}]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\njson.dump({'actions':[{'type':'oci_request','operation':'tags','repository':'library/demo'}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for OciRegistryClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        if !super::api::within_budget(&value) {
            crate::utils::json_budget::drop_iteratively(value);
            bail!("OCI action depth/node/retained-content limit");
        }
        match super::api::action(&value)? {
            super::api::Action::Disconnect => Ok(ClientActionResult::Disconnect),
            _ => Ok(ClientActionResult::Custom {
                name: "oci-registry".into(),
                data: value,
            }),
        }
    }
}
