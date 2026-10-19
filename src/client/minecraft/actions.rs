use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::minecraft::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct MinecraftClientProtocol;
impl MinecraftClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn status_action() -> ActionDefinition {
    action(
        "minecraft_status",
        "Ping the server for its server-list entry over a fresh connection; the answer arrives as minecraft_status_response.",
        vec![parameter("protocol_version", "number", "Protocol to announce in the handshake, default 767 (1.21.1)", false)],
        json!({"type":"minecraft_status"}),
    )
}

fn legacy_action() -> ActionDefinition {
    action(
        "minecraft_legacy_status",
        "Ping the server the way a 1.6 client does (0xFE 0x01 0xFA MC|PingHost); the answer arrives as minecraft_status_response with legacy true.",
        vec![],
        json!({"type":"minecraft_legacy_status"}),
    )
}

fn login_action() -> ActionDefinition {
    action(
        "minecraft_login",
        "Attempt to join as a player over a fresh connection and report how the server answered (disconnected, encryption required, or accepted). The client never enters the game.",
        vec![
            parameter("username", "string", "Player name, 1 to 16 characters", true),
            parameter("protocol_version", "number", "Protocol to announce, default 767 (1.21.1)", false),
            parameter("uuid", "string", "Profile UUID to send where the version sends one; default all zeros", false),
        ],
        json!({"type":"minecraft_login","username":"alice"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this Minecraft client",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![
        status_action(),
        legacy_action(),
        login_action(),
        disconnect_action(),
    ]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "minecraft_ready",
        "Ready to ping or join the Minecraft server.",
        status_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Address of the Minecraft server",
        true,
    )])
    .with_actions(actions())
});

pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "minecraft_status_response",
        "The server's server-list entry.",
        login_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "legacy",
            "boolean",
            "True when this came from a legacy ping",
            true,
        ),
        parameter(
            "version_name",
            "string",
            "Version text the server reports",
            false,
        ),
        parameter(
            "protocol",
            "number",
            "Protocol number the server reports",
            false,
        ),
        parameter(
            "online_players",
            "number",
            "Number of players online now",
            false,
        ),
        parameter(
            "max_players",
            "number",
            "Maximum number of player slots",
            false,
        ),
        parameter("motd", "string", "Message of the day as plain text", true),
        parameter("sample", "array", "Players listed: [{name, id}]", false),
        parameter(
            "has_favicon",
            "boolean",
            "Whether the server sent an icon (not included)",
            false,
        ),
        parameter(
            "enforces_secure_chat",
            "boolean",
            "Whether the server enforces signed chat",
            false,
        ),
        parameter(
            "latency_ms",
            "number",
            "Ping round trip, when measured",
            false,
        ),
    ])
    .with_actions(actions())
});

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "minecraft_login_result",
        "How the server answered a join attempt.",
        status_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "outcome",
            "string",
            "disconnected, encryption_required (an online-mode server) or accepted",
            true,
        ),
        parameter(
            "reason",
            "string",
            "For disconnected: the reason as plain text",
            false,
        ),
        parameter(
            "username",
            "string",
            "For accepted: the name the server assigned",
            false,
        ),
        parameter(
            "uuid",
            "string",
            "For accepted: the UUID the server assigned",
            false,
        ),
        parameter(
            "compression_threshold",
            "number",
            "Set when the server enabled compression first",
            false,
        ),
    ])
    .with_actions(actions())
});

pub fn protocol_version(v: &Value) -> Result<i32> {
    match &v["protocol_version"] {
        Value::Null => Ok(wire::DEFAULT_PROTOCOL),
        p => {
            let n = p
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("protocol_version must be an integer"))?;
            i32::try_from(n).map_err(|_| anyhow::anyhow!("protocol_version is out of range"))
        }
    }
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("minecraft_status") => {
            protocol_version(v)?;
        }
        Some("minecraft_legacy_status") => {}
        Some("minecraft_login") => {
            protocol_version(v)?;
            let name = v["username"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("username must be a string"))?;
            ensure!(
                (1..=wire::MAX_USERNAME_CHARS).contains(&name.chars().count()),
                "username must be 1 to {} characters",
                wire::MAX_USERNAME_CHARS
            );
            if let Some(uuid) = v.get("uuid").and_then(Value::as_str) {
                wire::parse_uuid(uuid)?;
            }
        }
        _ => bail!("Unknown Minecraft client action"),
    }
    Ok(())
}

impl Protocol for MinecraftClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Minecraft"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Minecraft"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["minecraft", "server list ping", "minecraft status", "slp"]
    }
    fn description(&self) -> &'static str {
        "Minecraft Java Edition client: server-list ping (modern and legacy) and login probing"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            STATUS_EVENT.clone(),
            LOGIN_EVENT.clone(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(25565)
            .implementation("Tokio TCP, one connection per action: handshake, status and ping/pong; the 1.6 legacy ping; handshake and Login Start read through Set Compression, plugin and cookie requests to Disconnect, Encryption Request or Login Success")
            .llm_control("Which servers to ping or join, as whom, and what to do with each answer")
            .e2e_testing("tests/client/minecraft: NetGet's own server for every path; node-minecraft-protocol's createServer as the independent peer for status, a login it accepts and one it kicks")
            .notes("Offline probing only: no Mojang authentication or encryption, so an online-mode server is reported as encryption_required, and an accepted login is reported and closed before play. Status responses are bounded to 32767 characters and decompressed packets to the same size; each read has a 30 s deadline.")
            .max_inbound_bytes(wire::MAX_CLIENTBOUND_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Every event is the result of the model's own ping or login probe, run one at a
            // time on a fresh connection; the server never pushes anything to batch.
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ping the Minecraft server at 127.0.0.1:25565 and report its MOTD and player count"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"minecraft","remote_addr":"127.0.0.1:25565","instruction":"Report the server's MOTD and player count"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"minecraft_ready","handler":{"type":"static","actions":[{"type":"minecraft_status"}]}},
            {"event_pattern":"minecraft_status_response","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'minecraft_login','username':'alice'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for MinecraftClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
