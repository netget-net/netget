use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct A2sProtocol;
impl A2sProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> A2S {name}"))),
    }
}

fn info_action() -> ActionDefinition {
    action(
        "a2s_info",
        "Answer an info query. Rust encodes the Source A2S_INFO response.",
        vec![
            parameter("name", "string", "Server name shown in the browser", true),
            parameter(
                "map",
                "string",
                "Map currently loaded, such as de_dust2",
                true,
            ),
            parameter("folder", "string", "Game folder, such as csgo or tf", true),
            parameter(
                "game",
                "string",
                "Full game name, such as Counter-Strike",
                true,
            ),
            parameter(
                "app_id",
                "number",
                "Steam application id (low 16 bits), such as 730",
                false,
            ),
            parameter(
                "players",
                "number",
                "Players currently connected, 0 to 255",
                false,
            ),
            parameter("max_players", "number", "Player slots, 0 to 255", false),
            parameter("bots", "number", "Bots among the players, 0 to 255", false),
            parameter(
                "server_type",
                "string",
                "dedicated (default), listen or proxy",
                false,
            ),
            parameter(
                "environment",
                "string",
                "linux (default), windows or mac",
                false,
            ),
            parameter(
                "private",
                "boolean",
                "True when a password is needed to join",
                false,
            ),
            parameter(
                "vac",
                "boolean",
                "True when Valve Anti-Cheat is enabled",
                false,
            ),
            parameter(
                "version",
                "string",
                "Game version string, default 1.0.0.0",
                false,
            ),
            parameter("port", "number", "Game port, sent in the extra data", false),
            parameter(
                "steam_id",
                "number",
                "Server SteamID, sent in the extra data",
                false,
            ),
            parameter(
                "keywords",
                "string",
                "Comma-separated server tags, sent in the extra data",
                false,
            ),
            parameter(
                "game_id",
                "number",
                "64-bit game id, sent in the extra data",
                false,
            ),
        ],
        json!({"type":"a2s_info","name":"NetGet Arena","map":"de_dust2","folder":"csgo","game":"Counter-Strike","app_id":730,"players":3,"max_players":16}),
    )
}
fn players_action() -> ActionDefinition {
    action(
        "a2s_players",
        "Answer a players query with the connected players.",
        vec![parameter(
            "players",
            "array",
            "[{name, score, duration_secs}] for each connected player",
            true,
        )],
        json!({"type":"a2s_players","players":[{"name":"alice","score":12,"duration_secs":330.5}]}),
    )
}
fn rules_action() -> ActionDefinition {
    action(
        "a2s_rules",
        "Answer a rules query with the server's configuration variables.",
        vec![parameter(
            "rules",
            "object",
            "Rule names to string values, such as {\"mp_timelimit\": \"30\"}",
            true,
        )],
        json!({"type":"a2s_rules","rules":{"mp_timelimit":"30","sv_gravity":"800"}}),
    )
}
fn refuse_action() -> ActionDefinition {
    action(
        "a2s_refuse",
        "Deliberately leave this query unanswered; logged as a refusal, unlike silence.",
        vec![parameter(
            "reason",
            "string",
            "Why the query is refused, for the log only",
            false,
        )],
        json!({"type":"a2s_refuse"}),
    )
}

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "a2s_query",
        "A Steam server-browser query passed the challenge. Answer with a2s_info, a2s_players or a2s_rules to match the query.",
        info_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("query", "string", "info, players or rules", true),
        parameter("remote_addr", "string", "Address the query came from", true),
    ])
    .with_actions(vec![info_action(), players_action(), rules_action(), refuse_action()])
});

/// The action that answers each query kind.
pub fn answer_name(kind: super::wire::Kind) -> &'static str {
    match kind {
        super::wire::Kind::Info => "a2s_info",
        super::wire::Kind::Players => "a2s_players",
        super::wire::Kind::Rules => "a2s_rules",
    }
}

impl Protocol for A2sProtocol {
    fn protocol_name(&self) -> &'static str {
        "A2S"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>A2S"
    }
    fn description(&self) -> &'static str {
        "Steam/Source server query (A2S_INFO, A2S_PLAYER, A2S_RULES) with challenges and split responses"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "a2s",
            "steam query",
            "source query",
            "server browser",
            "game server query",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            info_action(),
            players_action(),
            rules_action(),
            refuse_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![QUERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "info_challenge".into(),
            type_hint: "boolean".into(),
            description: "Require a challenge for A2S_INFO too, as Source servers have since 2020 (players and rules always need one)".into(),
            required: false,
            example: json!(false),
            default: Some(json!(super::DEFAULT_INFO_CHALLENGE)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(27015)
            .implementation("Source A2S over Tokio UDP: stateless keyed challenges, A2S_INFO with extra data, A2S_PLAYER, A2S_RULES, uncompressed split responses")
            .llm_control("What the server reports: its info, its players and its rules, per query")
            .e2e_testing("tests/server/a2s: raw datagrams and bounds; python-a2s and woozymasta/a2s (Go) as independent clients")
            .notes("Challenges are a keyed hash of the client's address with a per-server random key, so no state is kept per client and a spoofed source cannot complete a query. No GoldSource format, A2A_PING or compressed splits. Requests are capped at 1400 bytes, responses at 64 KiB in at most 64 packets, 64 queries in flight; datagrams beyond that are dropped. A handler failure or refusal leaves the query unanswered.")
            // Every A2S reply asserts something about the server; there is no error reply.
            .deliberately_silent()
            // Each query stands alone: the challenge is recomputed from the address, never stored.
            .connectionless()
            .max_inbound_bytes(super::wire::MAX_REQUEST)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "A2S server on UDP port 27015 that looks like a busy Counter-Strike server on de_dust2"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"a2s","port":27015,"instruction":"Report a busy Counter-Strike server on de_dust2"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"a2s_query","handler":{"type":"static","actions":[info_action().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"a2s_query","handler":{"type":"script","language":"python","code":"import json,sys\nq=json.load(sys.stdin)['event']['query']\na={'info':{'type':'a2s_info','name':'NetGet','map':'cs_office','folder':'csgo','game':'Counter-Strike'},'players':{'type':'a2s_players','players':[]},'rules':{'type':'a2s_rules','rules':{}}}[q]\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for A2sProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "a2s_info" => {
                super::wire::encode_info(&v)?;
            }
            "a2s_players" => {
                super::wire::encode_players(&v)?;
            }
            "a2s_rules" => {
                super::wire::encode_rules(&v)?;
            }
            "a2s_refuse" => {}
            _ => bail!("Unknown A2S server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}
