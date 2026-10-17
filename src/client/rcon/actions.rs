use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::rcon::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RconClientProtocol;
impl RconClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn command_action() -> ActionDefinition {
    action(
        "rcon_command",
        "Run a console command on the server; its output arrives as rcon_response.",
        vec![parameter(
            "command",
            "string",
            "The console command, such as status or list",
            true,
        )],
        json!({"type":"rcon_command","command":"status"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the RCON connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![command_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rcon_connected",
        "Logged in to the RCON server; run a command.",
        command_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Address of the RCON server", true),
        parameter(
            "dialect",
            "string",
            "source or minecraft, from the dialect startup parameter",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rcon_response",
        "The complete output of one command, reassembled from every packet the server sent.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("command", "string", "The command that was run", true),
        parameter("output", "string", "Its console output", true),
        parameter(
            "packets",
            "number",
            "How many response packets carried the output",
            true,
        ),
    ])
    .with_actions(actions())
});

pub fn validate_command(v: &Value) -> Result<String> {
    let command = v["command"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("command must be a string"))?;
    ensure!(
        !command.is_empty() && command.len() <= wire::MAX_BODY_OUT,
        "command must be 1 to {} bytes",
        wire::MAX_BODY_OUT
    );
    ensure!(!command.contains('\0'), "command must not contain NUL");
    Ok(command.to_string())
}

impl Protocol for RconClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RCON"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RCON"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rcon", "source rcon", "minecraft rcon", "mcrcon"]
    }
    fn description(&self) -> &'static str {
        "Source/Minecraft RCON client: logs in and runs console commands"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "RCON password sent at login; the connection fails when the server refuses it".into(),
                required: true,
                example: json!("changeme"),
                default: None,
            },
            ParameterDefinition {
                name: "dialect".into(),
                type_hint: "string".into(),
                description: "source (multi-packet output collected with the empty-packet sentinel) or minecraft (one packet per command)".into(),
                required: false,
                example: json!("minecraft"),
                default: Some(json!(crate::server::rcon::DEFAULT_DIALECT)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(27015)
            .implementation("Tokio TCP with Source RCON framing: login on connect, EXECCOMMAND followed by the empty-packet sentinel to collect multi-packet output")
            .llm_control("Which console commands to run and what to do with their output")
            .e2e_testing("tests/client/rcon: scripted fixture and gorcon/rcon's rcontest server as the independent peer")
            .notes("The password is a startup parameter and is never part of an event. Incoming packets are capped at 4096 bytes and one command's output at 1 MiB; connect, login and reply deadlines are 30 s.")
            .max_inbound_bytes(wire::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to RCON at 127.0.0.1:25575 with password changeme and list the players"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rcon","remote_addr":"127.0.0.1:25575","instruction":"List the players","startup_params":{"password":"changeme","dialect":"minecraft"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"rcon_connected","handler":{"type":"static","actions":[{"type":"rcon_command","command":"list"}]}},
            {"event_pattern":"rcon_response","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'rcon_command','command':'list'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for RconClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("rcon_command") => {
                validate_command(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "rcon_command".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown RCON client action"),
        }
    }
}
