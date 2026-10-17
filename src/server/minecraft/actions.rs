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
pub struct MinecraftProtocol;
impl MinecraftProtocol {
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
        "minecraft_status" => LogTemplate::new()
            .with_info("-> Minecraft status {online_players}/{max_players} {preview(motd,60)}"),
        "minecraft_disconnect" => {
            LogTemplate::new().with_info("-> Minecraft login disconnect {preview(reason,80)}")
        }
        "minecraft_login" => LogTemplate::new().with_info("-> Minecraft login as {username}"),
        _ => LogTemplate::new().with_info(format!("-> Minecraft {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn status_action() -> ActionDefinition {
    action(
        "minecraft_status",
        "Answer a server-list ping with what the server reports. Rust builds the status JSON (or the legacy kick reply) and answers the follow-up ping itself.",
        vec![
            parameter("motd", "string", "Message of the day shown in the server list; § colour codes allowed", true),
            parameter("online_players", "number", "Number of players online now", true),
            parameter("max_players", "number", "Maximum number of player slots", true),
            parameter("version_name", "string", "Version text, default 1.21.1", false),
            parameter("protocol", "number", "Protocol number, default 767 (1.21.1); the string \"echo\" repeats the client's own", false),
            parameter("sample", "array", "Up to 64 players shown on hover: [{name, id?: uuid}]", false),
            parameter("enforces_secure_chat", "boolean", "Whether the server enforces signed chat", false),
        ],
        json!({"type":"minecraft_status","motd":"A NetGet server","online_players":2,"max_players":20,"sample":[{"name":"alice"}]}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "minecraft_disconnect",
        "Refuse a login with the reason the player's client shows on its disconnect screen. NetGet never admits a player into the game.",
        vec![parameter("reason", "string", "Text shown to the player", true)],
        json!({"type":"minecraft_disconnect","reason":"You are not whitelisted on this server!"}),
    )
}

fn refuse_action() -> ActionDefinition {
    action(
        "minecraft_refuse",
        "Close the connection without answering, as an unreachable or hidden server would look",
        vec![],
        json!({"type":"minecraft_refuse"}),
    )
}

pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "minecraft_status_request",
        "A client pinged the server for its server-list entry; report the MOTD, player counts and version.",
        status_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("protocol_version", "number", "Protocol the client speaks (-1 or a low number from ping tools; null for a pre-1.6 legacy ping)", false),
        parameter("server_address", "string", "Host name the client dialled, from its handshake", false),
        parameter("server_port", "number", "Port the client dialled, from its handshake", false),
        parameter("legacy", "boolean", "True for a pre-1.7 (0xFE) ping, answered with the legacy kick format", true),
        parameter("remote_addr", "string", "Client address and port", true),
    ])
    .with_actions(vec![status_action(), refuse_action()])
});

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "minecraft_login",
        "A player tried to join. Answer with the disconnect reason they will see; NetGet does not run a game.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("username", "string", "Player name from Login Start", true),
        parameter("uuid", "string", "Profile UUID the client sent, when its version sends one", false),
        parameter("protocol_version", "number", "Protocol the client speaks", true),
        parameter("server_address", "string", "Host name the client dialled", true),
        parameter("server_port", "number", "Port the client dialled", true),
        parameter("transfer", "boolean", "True when the client arrived through a server transfer", true),
        parameter("remote_addr", "string", "Client address and port", true),
    ])
    .with_actions(vec![disconnect_action(), refuse_action()])
});

pub fn check_status(v: &Value) -> Result<()> {
    ensure!(v["motd"].is_string(), "motd must be a string");
    for key in ["online_players", "max_players"] {
        ensure!(v[key].is_i64(), "{key} must be an integer");
    }
    ensure!(
        v.get("version_name").is_none_or(Value::is_string),
        "version_name must be a string"
    );
    ensure!(
        v.get("enforces_secure_chat").is_none_or(Value::is_boolean),
        "enforces_secure_chat must be a boolean"
    );
    // Builds the JSON once so a sample or size problem is refused here, not on the wire.
    super::wire::status_json(v, 0)?;
    Ok(())
}

impl Protocol for MinecraftProtocol {
    fn protocol_name(&self) -> &'static str {
        "Minecraft"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Minecraft"
    }
    fn description(&self) -> &'static str {
        "Minecraft Java Edition server-list ping (modern and legacy) and login refusal, answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "minecraft",
            "server list ping",
            "slp",
            "minecraft status",
            "motd",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![status_action(), disconnect_action(), refuse_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![STATUS_EVENT.clone(), LOGIN_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds to wait for each packet before closing (1..=300)".into(),
            required: false,
            example: json!(10),
            default: Some(json!(super::wire::IO_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(25565)
            .implementation("Minecraft Java Edition framing over Tokio TCP: handshake, status request/response, ping/pong, Login Start answered by a login Disconnect, and the pre-1.7 0xFE legacy ping in its Beta, 1.4 and 1.6 forms")
            .llm_control("The server-list entry (MOTD, players, version) per ping, and the disconnect reason each joining player sees")
            .e2e_testing("tests/server/minecraft: raw packets and bounds; mcstatus (Python, modern and legacy) and node-minecraft-protocol (ping and a real login attempt) as independent clients")
            .notes("No game: a login is always ended with a Disconnect, so no encryption, compression or play state. No favicon (it is base64 image data). Serverbound packets are capped at 2048 bytes, a handshake address at 255 characters and a name at 16; each read has a 30 s deadline. A handler failure on a ping closes the connection without a fabricated status; on a login it disconnects the player with a generic reason.")
            .request_only("Every reply answers the packet just read; the server never speaks first")
            .max_inbound_bytes(super::wire::MAX_SERVERBOUND_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Minecraft server on port 25565 that shows a busy survival server in the server list and refuses logins as not whitelisted"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"minecraft","port":25565,"instruction":"Look like a busy survival server and refuse logins as not whitelisted"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"minecraft_status_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'minecraft_status','motd':'Hello '+(e.get('server_address') or ''),'online_players':3,'max_players':50}]}))"}},
            {"event_pattern":"minecraft_login","handler":{"type":"static","actions":[{"type":"minecraft_disconnect","reason":"You are not whitelisted on this server!"}]}}
        ]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"minecraft_status_request","handler":{"type":"static","actions":[{"type":"minecraft_status","motd":"A NetGet server","online_players":0,"max_players":20}]}},
            {"event_pattern":"minecraft_login","handler":{"type":"static","actions":[{"type":"minecraft_disconnect","reason":"Server is in maintenance"}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for MinecraftProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("minecraft_status") => {
                check_status(&v)?;
                Ok(ActionResult::Custom {
                    name: "minecraft_status".into(),
                    data: v,
                })
            }
            Some("minecraft_disconnect") => {
                let reason = v["reason"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("reason must be a string"))?;
                super::wire::disconnect_json(reason)?;
                Ok(ActionResult::Custom {
                    name: "minecraft_disconnect".into(),
                    data: v,
                })
            }
            Some("minecraft_refuse") => Ok(ActionResult::Custom {
                name: "minecraft_refuse".into(),
                data: v,
            }),
            _ => bail!("Unknown Minecraft server action"),
        }
    }
}
