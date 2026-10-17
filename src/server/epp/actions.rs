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
pub struct EppProtocol;
impl EppProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("EPP {name}"))),
    }
}

fn code_param(default: &str) -> Parameter {
    parameter(
        "code",
        "number",
        &format!("RFC 5730 result code; {default} when omitted"),
        false,
    )
}

fn check_result() -> ActionDefinition {
    action(
        "epp_check_result",
        "Answer a check: whether each name (domain, host) or id (contact) is available",
        vec![parameter("results", "array", "[{name, available, reason}], one per checked object, reason when not available (e.g. In use)", true)],
        json!({"type": "epp_check_result", "results": [{"name": "example.com", "available": false, "reason": "In use"}, {"name": "example.net", "available": true}]}),
    )
}
fn info() -> ActionDefinition {
    action(
        "epp_info",
        "Answer an info command with the object's data",
        vec![parameter("info", "object", "The object's data. Domain: name, roid, status[], registrant, contacts[{type,id}], ns[], cl_id, cr_date, ex_date, auth_info. Host: name, roid, status[], addrs[{ip: v4|v6, addr}], cl_id, cr_date. Contact: id, roid, status[], name, org, street[], city, sp, pc, cc, voice, email, cl_id, cr_date. Dates as 2026-10-04T12:00:00.0Z", true)],
        json!({"type": "epp_info", "info": {"name": "example.com", "roid": "EXAMPLE1-REP", "status": ["ok"], "registrant": "jd1234", "contacts": [{"type": "admin", "id": "sh8013"}], "ns": ["ns1.example.net"], "cl_id": "ClientX", "cr_date": "2024-04-03T22:00:00.0Z", "ex_date": "2027-04-03T22:00:00.0Z"}}),
    )
}
fn created() -> ActionDefinition {
    action(
        "epp_created",
        "Answer a successful create",
        vec![
            parameter(
                "name",
                "string",
                "The created domain or host name (contacts use id)",
                false,
            ),
            parameter("id", "string", "The created contact id", false),
            parameter(
                "cr_date",
                "string",
                "Creation time, e.g. 2026-10-04T12:00:00.0Z",
                true,
            ),
            parameter("ex_date", "string", "Domain expiry time", false),
        ],
        json!({"type": "epp_created", "name": "example.com", "cr_date": "2026-10-04T12:00:00.0Z", "ex_date": "2027-10-04T12:00:00.0Z"}),
    )
}
fn renewed() -> ActionDefinition {
    action(
        "epp_renewed",
        "Answer a successful domain renew with the new expiry",
        vec![
            parameter(
                "name",
                "string",
                "The renewed domain name, e.g. example.com",
                true,
            ),
            parameter("ex_date", "string", "The new expiry time", true),
        ],
        json!({"type": "epp_renewed", "name": "example.com", "ex_date": "2028-04-03T22:00:00.0Z"}),
    )
}
fn transfer_status() -> ActionDefinition {
    action(
        "epp_transfer_status",
        "Answer a transfer request or query with the transfer's state (code 1001 for a request now pending)",
        vec![
            parameter("name", "string", "The domain (contacts use id)", false),
            parameter("id", "string", "The contact id, for a contact transfer", false),
            parameter("tr_status", "string", "pending, clientApproved, clientCancelled, clientRejected, serverApproved or serverCancelled", true),
            parameter("re_id", "string", "Requesting client id", true),
            parameter("re_date", "string", "When the transfer was requested, e.g. 2026-10-04T12:00:00.0Z", true),
            parameter("ac_id", "string", "Client that must act", true),
            parameter("ac_date", "string", "Time by which it must act", true),
            parameter("ex_date", "string", "Domain expiry after the transfer", false),
            code_param("1000"),
        ],
        json!({"type": "epp_transfer_status", "name": "example.com", "tr_status": "pending", "re_id": "ClientX", "re_date": "2026-10-04T12:00:00.0Z", "ac_id": "ClientY", "ac_date": "2026-10-09T12:00:00.0Z", "code": 1001}),
    )
}
fn result() -> ActionDefinition {
    action(
        "epp_result",
        "Answer with a result code alone: success for update, delete or renew/transfer without data, or a refusal (2302 exists, 2303 does not exist, 2201 authorization, 2202 bad authInfo, 2304 status prohibits, 2306 policy, 2400 failed)",
        vec![
            parameter("code", "number", "RFC 5730 result code", true),
            parameter("reason", "string", "A sentence explaining a refusal, e.g. Domain is locked", false),
        ],
        json!({"type": "epp_result", "code": 2303, "reason": "No such domain"}),
    )
}

pub static COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "epp_command",
        "A logged-in registrar sent an object command; answer it as the registry",
        result().example,
    )
    .with_parameters(vec![
        parameter("command", "string", "check, info, create, renew, transfer, update or delete", true),
        parameter("object", "string", "domain, host or contact", true),
        parameter("fields", "object", "The command's content: names for check; name or id (and auth_info) for info and delete; the object's data for create; cur_exp_date and period for renew; op, period and auth_info for transfer; add/rem/chg for update", true),
        parameter("client_id", "string", "The logged-in registrar", true),
        parameter("cl_trid", "string", "The client transaction id", false),
    ])
    .with_actions(vec![check_result(), info(), created(), renewed(), transfer_status(), result()])
});

pub fn validate(v: &Value) -> Result<()> {
    let code_ok = |c: &Value, success_only: bool| -> Result<()> {
        if c.is_null() {
            return Ok(());
        }
        let c = c.as_u64().context("code is a number")? as u16;
        ensure!(
            super::wire::RESULT_CODES.iter().any(|(k, _)| *k == c),
            "{c} is not an RFC 5730 result code"
        );
        ensure!(
            !success_only || c < 2000,
            "a data answer has a success code"
        );
        Ok(())
    };
    match v["type"].as_str() {
        Some("epp_check_result") => {
            let r = v["results"].as_array().context("results is an array")?;
            ensure!(!r.is_empty() && r.len() <= 64, "1 to 64 results");
            for x in r {
                ensure!(
                    x["name"].is_string() && x["available"].is_boolean(),
                    "each result has name and available"
                );
            }
        }
        Some("epp_info") => ensure!(v["info"].is_object(), "info is an object"),
        Some("epp_created") => ensure!(
            v["name"].is_string() || v["id"].is_string(),
            "epp_created names the object"
        ),
        Some("epp_renewed") => ensure!(v["name"].is_string(), "epp_renewed names the domain"),
        Some("epp_transfer_status") => {
            ensure!(
                v["name"].is_string() || v["id"].is_string(),
                "the transfer names its object"
            );
            ensure!(v["tr_status"].is_string(), "tr_status is required");
            code_ok(&v["code"], true)?;
        }
        Some("epp_result") => {
            ensure!(!v["code"].is_null(), "code is required");
            code_ok(&v["code"], false)?;
            ensure!(
                !matches!(v["code"].as_u64(), Some(1500 | 2500 | 2501 | 2502)),
                "session-ending codes are the server's own"
            );
        }
        Some(other) => bail!("Unknown EPP action {other}"),
        None => bail!("an action names its type"),
    }
    Ok(())
}

impl Protocol for EppProtocol {
    fn protocol_name(&self) -> &'static str {
        "EPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>EPP"
    }
    fn description(&self) -> &'static str {
        "EPP (RFC 5730/5734) registry server: greeting, login sessions and domain, host and contact commands answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "epp",
            "epp server",
            "domain registry",
            "extensible provisioning protocol",
            "registrar",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            check_result(),
            info(),
            created(),
            renewed(),
            transfer_status(),
            result(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![COMMAND_EVENT.clone()]
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
            p("server_id", "string", "The svID in the greeting", json!("NetGet Registry"), Some(json!(super::DEFAULT_SERVER_ID))),
            p("clients", "object", "Registrar logins {clID: password}; without it every login is accepted", json!({"ClientX": "foo-BAR2"}), None),
            p("tls", "boolean", "TLS as RFC 5734 requires; false serves plain TCP", json!(true), Some(json!(true))),
            p("tls_cert_file", "string", "PEM certificate; without it and tls_key_file a self-signed one for localhost is generated and published as protocol_data.certificate_pem", json!("cert.pem"), None),
            p("tls_key_file", "string", "PEM private key for tls_cert_file", json!("key.pem"), None),
            p("idle_timeout_secs", "number", "Close a session idle this long, 1 to 3600 seconds", json!(600), Some(json!(super::IDLE_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(700))
            .well_known_port(700)
            .implementation("tokio-rustls TLS with RFC 5734 framing; RFC 5730 greeting, hello, login/logout, session state and result codes in Rust; domain, host and contact commands parsed into fields and their responses rendered from the handler's answers (quick-xml, bounded, no DTD)")
            .llm_control("Every object command: availability, object data, creations, renewals, transfers, updates, deletions and refusals")
            .e2e_testing("tests/server/epp: pyepp 0.2.0 (independent, InternetNZ's Python client) logs in over TLS and checks, creates, reads, renews and transfers")
            .notes("No extensions (secDNS and others are accepted at login, never acted on), no poll messages (poll answers 1300), no storage: the handler is the registry. 256 KiB frames; three failed logins close the session.")
            .request_only("EPP is command/response: the server never speaks except to answer a command")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_FRAME)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "EPP registry on port 700 where example.com is taken and every other .com is available"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"epp","port":7000,"instruction":"Be a .com registry: example.com is registered to ClientX, everything else is available","startup_params":{"clients":{"ClientX":"foo-BAR2"}}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"epp_command","handler":{"type":"static","actions":[{"type":"epp_result","code":2303,"reason":"No such object"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"epp_command","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['command']=='check':\n    print(json.dumps({'actions':[{'type':'epp_check_result','results':[{'name':n,'available':n!='example.com'} for n in e['fields']['names']]}]}))\nelse:\n    print(json.dumps({'actions':[{'type':'epp_result','code':2101}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for EppProtocol {
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
