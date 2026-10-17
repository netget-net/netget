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
pub struct RconProtocol;
impl RconProtocol {
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
        "rcon_auth_decision" => {
            LogTemplate::new().with_info("-> RCON authentication allowed={allowed}")
        }
        "rcon_response" => LogTemplate::new().with_info("-> RCON response {preview(output,80)}"),
        "rcon_command" => LogTemplate::new().with_info("-> RCON command {preview(command,80)}"),
        _ => LogTemplate::new().with_info(format!("-> RCON {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn auth_action() -> ActionDefinition {
    action(
        "rcon_auth_decision",
        "Accept or refuse an RCON login. Used only when no password startup parameter is set; default is refusal.",
        vec![parameter("allowed", "boolean", "True only if this password should be accepted", true)],
        json!({"type":"rcon_auth_decision","allowed":false}),
    )
}

fn response_action() -> ActionDefinition {
    action(
        "rcon_response",
        "Answer an RCON command with its console output. Rust splits long output across packets.",
        vec![parameter(
            "output",
            "string",
            "Console text the command printed; empty when it prints nothing",
            true,
        )],
        json!({"type":"rcon_response","output":"There are 0 of a max of 20 players online:"}),
    )
}

pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rcon_auth",
        "A client sent an RCON login and no password is configured; decide whether it is accepted.",
        auth_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "password",
        "string",
        "Password the client supplied",
        true,
    )])
    .with_actions(vec![auth_action()])
});

pub static COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rcon_command",
        "An authenticated client ran a console command; answer with its output.",
        response_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "command",
        "string",
        "The console command, as typed",
        true,
    )])
    .with_actions(vec![response_action()])
});

impl Protocol for RconProtocol {
    fn protocol_name(&self) -> &'static str {
        "RCON"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RCON"
    }
    fn description(&self) -> &'static str {
        "Source RCON server (also Minecraft's RCON): password login and console commands answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rcon",
            "source rcon",
            "minecraft rcon",
            "game server console",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![auth_action(), response_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![AUTH_EVENT.clone(), COMMAND_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "RCON password checked in Rust; when absent, each login is an rcon_auth event".into(),
                required: false,
                example: json!("changeme"),
                default: None,
            },
            ParameterDefinition {
                name: "dialect".into(),
                type_hint: "string".into(),
                description: "source (an empty response precedes each auth response, as srcds sends) or minecraft".into(),
                required: false,
                example: json!("minecraft"),
                default: Some(json!(super::DEFAULT_DIALECT)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds a connection may stay silent before it is closed (1..=86400)".into(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(27015)
            .implementation("Source RCON framing over Tokio TCP: AUTH with AUTH_RESPONSE (id or -1), EXECCOMMAND answered by RESPONSE_VALUE packets split at 4086 bytes, the empty-packet sentinel mirrored")
            .llm_control("Console output for each command, and login decisions when no password is configured")
            .e2e_testing("tests/server/rcon: raw packets and bounds; gorcon/rcon (Go) and the Python rcon package as independent clients")
            .notes("Plain TCP, as RCON is. A configured password is compared in Rust in constant time and never shown to the handler; without one the handler decides and sees the attempt. Three failed logins close the connection; a command before login closes it. Packets are capped at 4096 bytes and output at 1 MiB. A handler failure on a command closes the connection rather than inventing output.")
            .request_only("RCON answers each packet the client sends; the server never speaks first")
            .max_inbound_bytes(super::wire::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RCON server on port 25575 with password secret that answers like a Minecraft server console"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"rcon","port":25575,"instruction":"Answer like a Minecraft server console","startup_params":{"password":"changeme","dialect":"minecraft"}});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"rcon_command","handler":{"type":"script","language":"python","code":"import json,sys\nc=json.load(sys.stdin)['event']['command']\nout='There are 0 of a max of 20 players online:' if c=='list' else 'Unknown command'\nprint(json.dumps({'actions':[{'type':'rcon_response','output':out}]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"rcon_command","handler":{"type":"static","actions":[{"type":"rcon_response","output":"Unknown command"}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for RconProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("rcon_auth_decision") => {
                ensure!(v["allowed"].is_boolean(), "allowed must be a boolean");
                Ok(ActionResult::Custom {
                    name: "rcon_auth_decision".into(),
                    data: v,
                })
            }
            Some("rcon_response") => {
                let output = v["output"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("output must be a string"))?;
                ensure!(
                    output.len() <= super::wire::MAX_RESPONSE_BYTES,
                    "output exceeds {} bytes",
                    super::wire::MAX_RESPONSE_BYTES
                );
                Ok(ActionResult::Custom {
                    name: "rcon_response".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown RCON server action"),
        }
    }
}
