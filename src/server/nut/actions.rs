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
pub struct NutProtocol;
impl NutProtocol {
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
    let log_template = match name {
        "nut_reply" => LogTemplate::new().with_info(
            "-> NUT reply: entries={entries_len} value={preview(value,80)} types={preview(types,80)} ok={ok} error={error}",
        ),
        "nut_auth_decision" => {
            LogTemplate::new().with_info("-> NUT authentication allowed={allowed}")
        }
        // The client uses this helper too. Credentials may be in value, so omit it.
        "nut_request" => LogTemplate::new().with_info("-> NUT {operation} {ups} {name}"),
        "disconnect" => LogTemplate::new().with_info("-> NUT disconnect"),
        _ => LogTemplate::new().with_info(format!("-> NUT {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}
fn response_action() -> ActionDefinition {
    action("nut_reply", "Answer the pending request. Rust supplies matching UPS identity and list framing. Supply error OR entries/value/types/ok appropriate to the request.", vec![
        parameter("entries", "array", "For list_ups: [{name,description}]; list_var/list_rw: [{name,value}]; list_cmd: [{name}]; list_enum: [{value}]. All values are strings.", false),
        parameter("value", "string", "Value for get_var/get_desc/get_cmddesc/get_upsdesc", false),
        parameter("types", "array", "get_type tokens: RW, ENUM, RANGE, NUMBER, STRING:n", false),
        parameter("ok", "boolean", "Explicit true only when set_var or instcmd succeeded", false),
        parameter("error", "string", "NUT error token, e.g. UNKNOWN-UPS, VAR-NOT-SUPPORTED, ACCESS-DENIED", false),
    ], json!({"type":"nut_reply","entries":[{"name":"ups","description":"Simulated UPS"}]}))
}
fn auth_action() -> ActionDefinition {
    action(
        "nut_auth_decision",
        "Accept or reject the supplied username/password. No built-in accounts; default denial.",
        vec![parameter(
            "allowed",
            "boolean",
            "True only if these credentials should be allowed",
            true,
        )],
        json!({"type":"nut_auth_decision","allowed":false}),
    )
}
pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("nut_request", "A UPS query or authenticated operation; data and policy come from the handler.", response_action().example.clone()).with_parameters(vec![
    parameter("operation","string","list_ups/list_var/list_rw/list_cmd/list_enum/get_var/get_desc/get_cmddesc/get_upsdesc/get_type/set_var/instcmd",true),
    parameter("ups","string","UPS identifier requested by the peer, such as rack1",false), parameter("name","string","Variable or command name",false), parameter("value","string","Value for set_var",false), parameter("username","string","Authenticated user for write decisions",false),
]).with_actions(vec![response_action()])
});
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("nut_auth", "Authenticate credentials for this connection. Use a deterministic handler for real credentials.", auth_action().example.clone()).with_parameters(vec![parameter("username","string","Username supplied by the peer for authentication",true),parameter("password","string","Password supplied by remote peer",true)]).with_actions(vec![auth_action()])
});
impl Protocol for NutProtocol {
    fn protocol_name(&self) -> &'static str {
        "NUT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NUT"
    }
    fn description(&self) -> &'static str {
        "NUT UPS management server (RFC 9271), programmable UPS data and commands"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nut", "ups", "upsd", "rfc9271"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response_action(), auth_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone(), AUTH_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description:
                "Whole-command deadline in seconds (1..=86400), including first command; does not time out a parked handler"
                    .into(),
            required: false,
            example: json!(300),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().request_only("NUT replies require a pending command and its UPS or variable identity; no unsolicited peer messages").state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(3493)
            .implementation("RFC 9271 ASCII line protocol over Tokio TCP, bounded strict parser and correlated structured replies")
            .llm_control("UPS discovery, variable values/types/descriptions, instant-command lists, authentication and write authorization/results")
            .e2e_testing("tests/server/nut: raw-wire sessions, framing and bounds; independent client evidence is documented in CLAUDE.md")
            .notes("Plain TCP only: STARTTLS returns FEATURE-NOT-SUPPORTED. No built-in UPS storage or accounts. SET/INSTCMD require an accepted nut_auth decision and explicit handler success. ATTACH/LOGIN/PRIMARY/FSD, RANGE and tracking are not supported; unknown commands return UNKNOWN-COMMAND. 256 connections; 8192-byte lines; 4096 entries and 1 MiB replies; 30s write deadline.")
            .request_only("NUT replies require the current parsed request and authenticated session state; unsolicited replies are not part of this protocol.")
            .max_inbound_bytes(super::wire::MAX_LINE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "NUT server on port 3493 simulating UPS rack1 at full battery charge"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"nut","port":3493,"instruction":"Simulate UPS rack1"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"nut_request","handler":{"type":"script","language":"python","code":"respond([{'type':'nut_reply','error':'UNKNOWN-UPS'}])"}},{"event_pattern":"nut_auth","handler":{"type":"static","actions":[{"type":"nut_auth_decision","allowed":false}]}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"nut_request","handler":{"type":"static","actions":[{"type":"nut_reply","error":"UNKNOWN-UPS"}]}},{"event_pattern":"nut_auth","handler":{"type":"static","actions":[{"type":"nut_auth_decision","allowed":false}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Monitoring"
    }
}
impl Server for NutProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("nut_reply") => {
                if let Some(error) = v.get("error") {
                    super::wire::error_reply(
                        error
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("error must be string"))?,
                    )?;
                }
                ensure!(
                    serde_json::to_vec(&v)?.len() <= 2 * super::wire::MAX_RESPONSE_BYTES,
                    "Reply action too large"
                );
                Ok(ActionResult::Custom {
                    name: "nut_reply".into(),
                    data: v,
                })
            }
            Some("nut_auth_decision") => {
                ensure!(v["allowed"].is_boolean(), "allowed must be boolean");
                Ok(ActionResult::Custom {
                    name: "nut_auth_decision".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown NUT server action"),
        }
    }
}
