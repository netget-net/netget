use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::jmap::actions::{action, parameter};
use crate::server::jmap::request;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct JmapClientProtocol;
impl JmapClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn jmap_request() -> ActionDefinition {
    action(
        "jmap_request",
        "Send one JMAP request: method calls run in order on the server and may reference earlier results (\"#ids\": {\"resultOf\": \"0\", \"name\": \"Email/query\", \"path\": \"/ids\"}). The answer raises jmap_response",
        vec![
            parameter("calls", "array", "Method calls as [name, arguments, id], e.g. [[\"Mailbox/get\", {}, \"0\"]]; accountId defaults to the primary account", true),
            parameter("using", "array", "Capability URIs; derived from the method names when omitted", false),
        ],
        json!({"type": "jmap_request", "calls": [["Mailbox/get", {"ids": null}, "0"]]}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Stop the client",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jmap_connected",
        "The JMAP session was fetched; send requests against its accounts",
        jmap_request().example,
    )
    .with_parameters(vec![
        parameter(
            "username",
            "string",
            "The user the server authenticated",
            true,
        ),
        parameter("accounts", "array", "[{id, name, capabilities}]", true),
        parameter(
            "primary_accounts",
            "object",
            "Capability URI → account id",
            true,
        ),
        parameter(
            "capabilities",
            "array",
            "The capability URIs the server supports",
            true,
        ),
        parameter("state", "string", "The session state", true),
    ])
    .with_actions(vec![jmap_request(), disconnect()])
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jmap_response",
        "The server answered a jmap_request: one entry per method response, or a request-level problem",
        json!({"type": "jmap_request", "calls": [["Email/get", {"ids": ["e1"]}, "0"]]}),
    )
    .with_parameters(vec![
        parameter("status", "number", "The HTTP status", true),
        parameter("method_responses", "array", "[name, arguments, call id] per response; name is \"error\" for a method error", false),
        parameter("session_state", "string", "The server's session state", false),
        parameter("session_changed", "boolean", "Whether the session state moved since the session was fetched", false),
        parameter("problem", "object", "A request-level error (type, detail, limit)", false),
    ])
    .with_actions(vec![jmap_request(), disconnect()])
});

/// Check a jmap_request and return (using, calls) with the defaults filled in.
pub fn prepare(
    v: &Value,
    primary: &serde_json::Map<String, Value>,
) -> Result<(Vec<String>, Vec<Value>)> {
    let calls = v["calls"].as_array().context("calls is an array")?;
    ensure!(
        (1..=request::MAX_CALLS).contains(&calls.len()),
        "1 to {} calls",
        request::MAX_CALLS
    );
    ensure!(
        request::depth(&v["calls"]) <= request::MAX_DEPTH,
        "calls nest too deeply"
    );
    let mut using = vec![request::CORE.to_owned()];
    let mut out = Vec::new();
    for c in calls {
        let c = c
            .as_array()
            .filter(|c| c.len() == 3)
            .context("each call is [name, arguments, id]")?;
        let name = c[0]
            .as_str()
            .filter(|n| n.contains('/') && n.len() <= 64)
            .context("a call names Type/verb")?;
        let mut args = c[1].as_object().context("arguments is an object")?.clone();
        let id = c[2]
            .as_str()
            .filter(|i| !i.is_empty() && i.len() <= 64)
            .context("a call id is a short string")?;
        if let Some(cap) = request::capability(name) {
            if !using.iter().any(|u| u == cap) {
                using.push(cap.to_owned());
            }
            if cap != request::CORE && !args.contains_key("accountId") {
                if let Some(a) = primary.get(cap).or_else(|| primary.get(request::MAIL)) {
                    args.insert("accountId".into(), a.clone());
                }
            }
        }
        out.push(json!([name, args, id]));
    }
    if let Some(u) = v.get("using").filter(|u| !u.is_null()) {
        using = u
            .as_array()
            .context("using is an array")?
            .iter()
            .map(|x| x.as_str().map(str::to_owned).context("using lists URIs"))
            .collect::<Result<_>>()?;
    }
    Ok((using, out))
}

impl Protocol for JmapClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "JMAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>JMAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["jmap", "jmap client", "jmap mail client"]
    }
    fn description(&self) -> &'static str {
        "JMAP client: discovers the session, then sends batched method calls (mailboxes, emails, threads, submissions) and reports the responses"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        vec![jmap_request(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![jmap_request(), disconnect()]
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
            p("username", "string", "Basic authentication user", json!("alice@example.com"), None),
            p("password", "string", "Basic authentication password", json!("secret"), None),
            p("api_token", "string", "Bearer token instead of username and password", json!("t0k3n"), None),
            p("tls", "boolean", "Use HTTPS (JMAP requires it); false for a plain-HTTP server", json!(true), Some(json!(true))),
            p("ca_cert_path", "string", "PEM certificate to trust instead of the system roots (a private CA or the server's self-signed certificate)", json!("ca.pem"), None),
            p("session_path", "string", "Where the session resource is", json!("/.well-known/jmap"), Some(json!(super::DEFAULT_SESSION_PATH))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("reqwest over HTTP(S): session discovery (redirects followed on the same origin), Basic or Bearer authentication, request validation, default using and accountId")
            .llm_control("Every request: which methods, arguments and result references")
            .e2e_testing("tests/client/jmap: Stalwart 0.16.24 (independent mail server) — mailboxes, email creation, query with result references, changes, updates and errors")
            .notes("No blob upload/download, EventSource push or WebSocket. apiUrl must be on the session's origin.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the JMAP server at mail.example.com:443 as alice and list her mailboxes"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"jmap","remote_addr":"127.0.0.1:8443","instruction":"List the mailboxes and the newest five emails","startup_params":{"username":"alice@example.com","password":"secret"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"jmap_connected","handler":{"type":"static","actions":[{"type":"jmap_request","calls":[["Mailbox/get",{},"0"]]}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"jmap_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'jmap_request','calls':[['Email/query',{'limit':5},'0'],['Email/get',{'#ids':{'resultOf':'0','name':'Email/query','path':'/ids'}},'1']]}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for JmapClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("jmap_request") => {
                prepare(&v, &serde_json::Map::new())?;
            }
            _ => bail!("Unknown JMAP client action"),
        }
        Ok(ClientActionResult::Custom {
            name: "jmap_request".into(),
            data: v,
        })
    }
}
