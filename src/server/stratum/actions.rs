//! What the model decides as a Stratum V1 pool: who may mine, which valid shares it credits,
//! and the work and difficulty it hands out. Rust owns the sessions, extranonces, jobs and
//! every share's arithmetic, so a share reaches the model only once it is proven to meet the
//! difficulty.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT: &str = "stratum_accept";
pub const REJECT: &str = "stratum_reject";
pub const SET_DIFFICULTY: &str = "stratum_set_difficulty";
pub const NEW_JOB: &str = "stratum_new_job";
pub const SHOW_MESSAGE: &str = "stratum_show_message";
/// The share difficulty a connection starts at.
pub const DEFAULT_DIFFICULTY: f64 = 1.0;
/// A difficulty must lie in (0, MAX_DIFFICULTY].
pub const MAX_DIFFICULTY: f64 = 1e15;
/// What a job's coinbase says when the model names nothing.
pub const DEFAULT_COINBASE_MESSAGE: &str = "NetGet";

#[derive(Default)]
pub struct StratumProtocol;
impl StratumProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Stratum {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action(
        ACCEPT,
        "Authorize the worker, or credit the share, being answered.",
        vec![],
        json!({"type": ACCEPT}),
    )
}

fn reject() -> ActionDefinition {
    action(
        REJECT,
        "Refuse the worker or the share being answered; the miner is told why.",
        vec![p(
            "message",
            "string",
            "The reason the miner is shown, e.g. unknown worker",
            true,
        )],
        json!({"type": REJECT, "message": "unknown worker"}),
    )
}

pub fn set_difficulty() -> ActionDefinition {
    action(
        SET_DIFFICULTY,
        "Set this miner's share difficulty (mining.set_difficulty); it applies to every share from now on.",
        vec![p("difficulty", "number", "Share difficulty, above 0; 1 is the classic minimum, fractions are allowed", true)],
        json!({"type": SET_DIFFICULTY, "difficulty": 0.5}),
    )
}

fn new_job() -> ActionDefinition {
    action(
        NEW_JOB,
        "Hand this miner new work (mining.notify). Rust builds the coinbase and header fields.",
        vec![
            p("message", "string", "Text the coinbase carries, at most 64 bytes (default NetGet)", false),
            p("prev_hash", "string", "Previous block hash as RPC shows it, 64 hex digits (default all zeros)", false),
            p("clean_jobs", "boolean", "Whether earlier jobs are void (default true): their shares are then refused as stale", false),
        ],
        json!({"type": NEW_JOB, "message": "block 2", "clean_jobs": true}),
    )
}

fn show_message() -> ActionDefinition {
    action(
        SHOW_MESSAGE,
        "Show the miner a message (client.show_message).",
        vec![p(
            "message",
            "string",
            "Text for the miner's operator",
            true,
        )],
        json!({"type": SHOW_MESSAGE, "message": "maintenance at noon"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        accept(),
        reject(),
        set_difficulty(),
        new_job(),
        show_message(),
    ]
}

pub static AUTHORIZE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_authorize",
        "A miner asked to mine as a worker (mining.authorize). Accept or reject it; work and the difficulty follow an accept.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("worker", "string", "The worker name, usually account.rig", true),
        p("password_given", "boolean", "Whether a password other than empty or x was sent (it is not shown)", true),
        p("user_agent", "string", "What the miner said it is in mining.subscribe", false),
        p("remote_addr", "string", "The miner's address and port", true),
    ])
    .with_actions(all_actions())
});

pub static SHARE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_share",
        "A miner submitted a share that Rust verified meets its difficulty. Accept (credit) or reject it.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("worker", "string", "The worker that submitted it", true),
        p("job_id", "string", "The job it was mined on", true),
        p("hash", "string", "The block header hash, as RPC shows hashes", true),
        p("share_difficulty", "number", "The difficulty the hash actually meets", true),
        p("difficulty", "number", "The miner's assigned difficulty, which the share meets", true),
        p("remote_addr", "string", "The miner's address and port", true),
    ])
    .with_actions(all_actions())
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT => {}
        REJECT | SHOW_MESSAGE => {
            let m = v["message"].as_str().context("message is required")?;
            ensure!(
                !m.is_empty() && m.len() <= 256,
                "message must be 1-256 bytes"
            );
        }
        SET_DIFFICULTY => {
            let d = v["difficulty"]
                .as_f64()
                .context("difficulty must be a number")?;
            ensure!(
                d > 0.0 && d <= MAX_DIFFICULTY,
                "difficulty must be above 0 and at most {MAX_DIFFICULTY}"
            );
        }
        NEW_JOB => {
            if let Some(m) = v.get("message").filter(|m| !m.is_null()) {
                let m = m.as_str().context("message must be text")?;
                ensure!(
                    m.len() <= super::wire::MAX_COINBASE_MESSAGE,
                    "message must be at most 64 bytes"
                );
            }
            super::wire::parse_prev_display(v["prev_hash"].as_str())?;
        }
        other => bail!("Unknown Stratum action {other:?}"),
    }
    Ok(())
}

impl Protocol for StratumProtocol {
    fn protocol_name(&self) -> &'static str {
        "Stratum"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Stratum"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "stratum",
            "mining pool",
            "bitcoin mining",
            "miner",
            "stratum+tcp",
        ]
    }
    fn description(&self) -> &'static str {
        "Stratum V1 mining pool: the model authorizes workers, credits shares Rust has verified, and sets difficulty and work"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![AUTHORIZE_EVENT.clone(), SHARE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "difficulty".into(),
                type_hint: "number".into(),
                description: "Share difficulty every miner starts at (fractions allowed, above 0)"
                    .into(),
                required: false,
                example: json!(0.01),
                default: Some(json!(DEFAULT_DIFFICULTY)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description:
                    "Seconds a miner may stay silent before it is disconnected (1..=86400)".into(),
                required: false,
                example: json!(1800),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(3333)
            .implementation("Newline-delimited JSON-RPC over Tokio TCP: mining.subscribe (a 4-byte extranonce1 per connection, 4-byte extranonce2), mining.authorize, mining.submit, mining.configure (no extensions), mining.extranonce.subscribe and mining.suggest_difficulty; jobs are built in Rust (BIP 34 height and a message in the coinbase, no other transactions) and every share is rebuilt into its header, double-SHA-256 hashed and measured before anyone is asked")
            .llm_control("Which workers may mine, whether each verified share is credited, and the difficulty, work and messages each miner gets")
            .e2e_testing("tests/server/stratum: cpuminer 2.5.1 (pooler, sha256d) mines against NetGet's jobs and has its shares accepted; raw JSON-RPC for refused shares, bounds and a failed handler")
            .notes("The pool is not connected to any node: its work is its own, so a share proves hashing and nothing is ever submitted as a block. Shares below the difficulty, duplicates, stale or unknown jobs, bad extranonce2 sizes and ntimes outside the job's window are refused by Rust (codes 20-25) without asking the model. Lines are capped at 16 KiB; a miner may be silent idle_timeout_secs.")
            .request_only("Every message answers a miner's request, except the work and difficulty that follow an answer")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_LINE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Stratum mining pool on port 3333 that accepts any worker and credits every share"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"stratum","port":3333,
            "instruction":"Authorize workers whose name starts with netget, credit every share, and raise the difficulty to 2 after the first share"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nif t=='stratum_authorize': a=[{'type':'stratum_accept'}] if e['worker'].startswith('netget') else [{'type':'stratum_reject','message':'unknown worker'}]\nelse: a=[{'type':'stratum_accept'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for StratumProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }
}
