use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct JmapProtocol;
impl JmapProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("JMAP {name}"))),
    }
}

/// RFC 8620 §3.6.2 and RFC 8621 method error types a handler may answer with.
pub const METHOD_ERRORS: &[&str] = &[
    "serverFail",
    "serverUnavailable",
    "unknownMethod",
    "invalidArguments",
    "forbidden",
    "accountNotFound",
    "accountNotSupportedByMethod",
    "accountReadOnly",
    "cannotCalculateChanges",
    "stateMismatch",
    "anchorNotFound",
    "unsupportedSort",
    "unsupportedFilter",
    "tooManyChanges",
    "fromAccountNotFound",
    "fromAccountNotSupportedByMethod",
];

fn response() -> ActionDefinition {
    action(
        "jmap_response",
        "Answer the method call with its response arguments, shaped as RFC 8620/8621 define for that method (e.g. Mailbox/get: accountId, state, list, notFound). State strings are yours: change them when the data changes",
        vec![
            parameter("arguments", "object", "The response arguments, e.g. {\"state\": \"s1\", \"list\": [...], \"notFound\": []}; accountId is filled in when omitted", true),
            parameter("method", "string", "Response name when it differs from the call's (rare, e.g. an implicit Email/set after EmailSubmission/set); the call's name otherwise", false),
        ],
        json!({"type": "jmap_response", "arguments": {"state": "s1", "list": [{"id": "inbox", "name": "Inbox", "role": "inbox"}], "notFound": []}}),
    )
}

fn method_error() -> ActionDefinition {
    action(
        "jmap_method_error",
        "Answer the method call with a method-level error instead of a response",
        vec![
            parameter("error_type", "string", "One of serverFail, serverUnavailable, invalidArguments, forbidden, accountReadOnly, cannotCalculateChanges, stateMismatch, anchorNotFound, unsupportedSort, unsupportedFilter, tooManyChanges, unknownMethod, accountNotFound", true),
            parameter("description", "string", "A sentence for the client, e.g. sinceState is too old", false),
        ],
        json!({"type": "jmap_method_error", "error_type": "cannotCalculateChanges", "description": "sinceState is too old"}),
    )
}

pub static METHOD_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jmap_method_call",
        "One method call of a JMAP request (result references and creation ids already resolved); answer with its response or an error",
        response().example,
    )
    .with_parameters(vec![
        parameter("method", "string", "The method, e.g. Email/query", true),
        parameter("account_id", "string", "The accountId argument, when the method takes one", false),
        parameter("arguments", "object", "The call's arguments as resolved", true),
        parameter("call_id", "string", "The client's method call id", true),
        parameter("username", "string", "The authenticated user", true),
    ])
    .with_actions(vec![response(), method_error()])
});

pub fn validate(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("jmap_response") => {
            let args = v["arguments"]
                .as_object()
                .context("arguments is an object")?;
            ensure!(
                super::request::depth(&Value::Object(args.clone())) <= super::request::MAX_DEPTH,
                "arguments nest too deeply"
            );
            if let Some(m) = v.get("method").filter(|m| !m.is_null()) {
                let m = m.as_str().context("method is a string")?;
                ensure!(m.contains('/') && m.len() <= 64, "method names a Type/verb");
            }
        }
        Some("jmap_method_error") => ensure!(
            v["error_type"]
                .as_str()
                .is_some_and(|t| METHOD_ERRORS.contains(&t)),
            "error_type is one of {}",
            METHOD_ERRORS.join(", ")
        ),
        Some(other) => bail!("Unknown JMAP action {other}"),
        None => bail!("an action names its type"),
    }
    Ok(())
}

impl Protocol for JmapProtocol {
    fn protocol_name(&self) -> &'static str {
        "JMAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>JMAP"
    }
    fn description(&self) -> &'static str {
        "JMAP (RFC 8620 core, RFC 8621 mail) server: session discovery and batched method calls; the handler is the mail store and answers every method"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "jmap",
            "jmap server",
            "jmap mail",
            "json meta application protocol",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response(), method_error()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![METHOD_CALL_EVENT.clone()]
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
            p("accounts", "array", "The accounts the session lists, [{\"id\", \"name\"}]; the first is primary", json!([{"id": "a1", "name": "alice@example.com"}]), None),
            p("users", "object", "Basic authentication: {username: password}. Without users or api_tokens every request is accepted", json!({"alice@example.com": "secret"}), None),
            p("api_tokens", "object", "Bearer authentication: {token: username}", json!({"t0k3n": "alice@example.com"}), None),
            p("tls", "boolean", "Serve HTTPS (JMAP requires it); false serves plain HTTP", json!(true), Some(json!(true))),
            p("tls_cert_file", "string", "PEM certificate; without it and tls_key_file a self-signed one for localhost is generated and published as protocol_data.certificate_pem", json!("cert.pem"), None),
            p("tls_key_file", "string", "PEM private key for tls_cert_file", json!("key.pem"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1 (rustls for HTTPS): the session resource, Basic/Bearer authentication, request validation and limits, capability and account checks, Core/echo, result references and creation ids in Rust")
            .llm_control("Every other method call: Mailbox, Email, Thread, SearchSnippet, Identity, EmailSubmission and VacationResponse objects, their states and errors")
            .e2e_testing("tests/server/jmap: jmapc 0.3.0 (independent, Python) discovers the session, queries mailboxes and emails with result references, sets and reads changes")
            .notes("No blob upload/download, EventSource push or WebSocket (501); state strings and object storage are the handler's. 16 calls per request, 256 ids per get, 128 objects per set, 1 MiB requests.")
            .request_only("JMAP is HTTP request/response; with no EventSource or WebSocket push there is nothing a server can send outside an answer")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "JMAP mail server on port 8443 for alice@example.com with an Inbox holding two messages"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"jmap","port":8443,"instruction":"Be a mailbox for alice@example.com with an Inbox holding two messages","startup_params":{"accounts":[{"id":"a1","name":"alice@example.com"}],"users":{"alice@example.com":"secret"}}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"jmap_method_call","handler":{"type":"static","actions":[{"type":"jmap_method_error","error_type":"forbidden"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"jmap_method_call","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['method']=='Mailbox/get':\n    print(json.dumps({'actions':[{'type':'jmap_response','arguments':{'state':'s1','list':[{'id':'inbox','name':'Inbox','role':'inbox'}],'notFound':[]}}]}))\nelse:\n    print(json.dumps({'actions':[{'type':'jmap_method_error','error_type':'forbidden'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for JmapProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        validate(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
