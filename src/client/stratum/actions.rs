//! What the model does as a Stratum V1 miner: mine the pool's current job for a bounded number
//! of hashes (Rust does the hashing and submits what meets the difficulty), submit a share by
//! hand, suggest a difficulty, authorize more workers.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::stratum::actions::{action, p};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const MINE: &str = "stratum_mine";
pub const SUBMIT: &str = "stratum_submit";
pub const SUGGEST: &str = "stratum_suggest_difficulty";
pub const AUTHORIZE: &str = "stratum_authorize";
/// Hashes one stratum_mine tries when the model names no number.
pub const DEFAULT_MINE_HASHES: u64 = 1_000_000;
/// Hashes one stratum_mine may try at most.
pub const MAX_MINE_HASHES: u64 = 50_000_000;
/// The worker the client authorizes when none is named.
pub const DEFAULT_USER: &str = "netget";
/// The password sent with it when none is named (pools conventionally ignore it).
pub const DEFAULT_PASSWORD: &str = "x";

#[derive(Default)]
pub struct StratumClientProtocol;
impl StratumClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(MINE, "Mine the current job: Rust hashes up to max_hashes nonces and submits the first share that meets the pool's difficulty (and, with submit_best, the best one found if none does).",
            vec![
                p("max_hashes", "number", "How many nonces to try (default 1000000, at most 50000000)", false),
                p("submit_best", "boolean", "Submit the best share found even when it is below the difficulty, e.g. to see the pool's verdict (default false)", false),
            ],
            json!({"type": MINE, "max_hashes": 2000000})),
        action(SUBMIT, "Submit a share by hand (mining.submit) for the current or a named job.",
            vec![
                p("nonce", "number", "The header nonce, 0..=4294967295", true),
                p("extranonce2", "number", "The extranonce2 counter, 0..=4294967295", true),
                p("job_id", "string", "The job (default the latest)", false),
                p("ntime", "number", "Header timestamp in Unix seconds (default the job's)", false),
            ],
            json!({"type": SUBMIT, "nonce": 12345, "extranonce2": 1})),
        action(SUGGEST, "Ask the pool for a share difficulty (mining.suggest_difficulty); the pool may ignore it.",
            vec![p("difficulty", "number", "The difficulty wanted, above 0", true)],
            json!({"type": SUGGEST, "difficulty": 1})),
        action(AUTHORIZE, "Authorize another worker on this connection (mining.authorize).",
            vec![
                p("user", "string", "Worker name, usually account.rig", true),
                p("password", "string", "Its password (default x)", false),
            ],
            json!({"type": AUTHORIZE, "user": "netget.rig2"})),
        action("disconnect", "Close the connection to the pool.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": MINE, "max_hashes": 1000000}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static AUTHORIZED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_authorized",
        "The pool answered mining.authorize.",
        vec![
            p("worker", "string", "The worker that asked", true),
            p("ok", "boolean", "Whether the pool authorized it", true),
            p(
                "error",
                "array",
                "The pool's [code, message] when it refused",
                false,
            ),
        ],
    )
});

pub static JOB_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_job",
        "The pool sent new work (mining.notify).",
        vec![
            p(
                "job_id",
                "string",
                "The job's id, which stratum_submit can name",
                true,
            ),
            p(
                "clean_jobs",
                "boolean",
                "Whether earlier jobs are void",
                true,
            ),
            p(
                "prev_hash",
                "string",
                "The previous block hash, as RPC shows hashes",
                true,
            ),
            p(
                "ntime",
                "number",
                "The job's header timestamp (Unix seconds)",
                true,
            ),
            p("nbits", "string", "The network target, compact form", true),
            p(
                "merkle_branches",
                "number",
                "How many transaction branches the job carries",
                true,
            ),
            p(
                "difficulty",
                "number",
                "The share difficulty the pool currently asks for",
                true,
            ),
        ],
    )
});

pub static SHARE_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_share_result",
        "The pool answered a submitted share.",
        vec![
            p("job_id", "string", "The job the share was for", true),
            p("nonce", "number", "The share's nonce", true),
            p("extranonce2", "number", "The share's extranonce2", true),
            p(
                "hash",
                "string",
                "The header hash Rust computed for the share, as RPC shows hashes",
                true,
            ),
            p(
                "share_difficulty",
                "number",
                "The difficulty that hash meets",
                true,
            ),
            p("accepted", "boolean", "Whether the pool accepted it", true),
            p(
                "error",
                "array",
                "The pool's [code, message] when it refused",
                false,
            ),
        ],
    )
});

pub static MINED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_mining_done",
        "A stratum_mine run ended without submitting anything.",
        vec![
            p("hashes", "number", "How many nonces the run tried", true),
            p(
                "best_difficulty",
                "number",
                "The best share difficulty found",
                true,
            ),
            p(
                "difficulty",
                "number",
                "The difficulty the pool asks for",
                true,
            ),
            p(
                "reason",
                "string",
                "Why nothing was submitted (no job yet, nothing met the difficulty)",
                true,
            ),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("stratum_message", "The pool sent something else: client.show_message, client.reconnect, mining.set_extranonce, or a reply to suggest_difficulty.", vec![
        p("method", "string", "The pool's method, or the action it answers", true),
        p("params", "array", "What it carried", true),
    ])
});

fn u32_field(v: &Value, key: &str, required: bool) -> Result<()> {
    match v.get(key).filter(|x| !x.is_null()) {
        Some(x) => {
            let n = x
                .as_u64()
                .with_context(|| format!("{key} must be a whole number"))?;
            ensure!(n <= u64::from(u32::MAX), "{key} must fit in 32 bits");
            Ok(())
        }
        None if required => bail!("{key} is required"),
        None => Ok(()),
    }
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        MINE => {
            if let Some(n) = v.get("max_hashes").filter(|x| !x.is_null()) {
                let n = n.as_u64().context("max_hashes must be a whole number")?;
                ensure!(
                    (1..=MAX_MINE_HASHES).contains(&n),
                    "max_hashes must be 1..={MAX_MINE_HASHES}"
                );
            }
        }
        SUBMIT => {
            u32_field(v, "nonce", true)?;
            u32_field(v, "extranonce2", true)?;
            u32_field(v, "ntime", false)?;
        }
        SUGGEST => {
            let d = v["difficulty"]
                .as_f64()
                .context("difficulty must be a number")?;
            ensure!(d > 0.0, "difficulty must be above 0");
        }
        AUTHORIZE => {
            let u = v["user"].as_str().context("user is required")?;
            ensure!(!u.is_empty() && u.len() <= 128, "user must be 1-128 bytes");
        }
        other => bail!("Unknown Stratum client action {other:?}"),
    }
    Ok(())
}

impl Protocol for StratumClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Stratum"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Stratum"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "stratum",
            "miner",
            "mining client",
            "stratum+tcp",
            "bitcoin mining",
        ]
    }
    fn description(&self) -> &'static str {
        "Stratum V1 miner: subscribes and authorizes, hears the pool's work, and mines and submits shares as the model directs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            AUTHORIZED_EVENT.clone(),
            JOB_EVENT.clone(),
            SHARE_RESULT_EVENT.clone(),
            MINED_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "Worker name authorized on connect, usually account.rig (a payout address on solo pools)".into(),
                required: false,
                example: json!("netget.rig1"),
                default: Some(json!(DEFAULT_USER)),
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "Password sent with the worker; most pools ignore it or read options from it".into(),
                required: false,
                example: json!("d=1"),
                default: Some(json!(DEFAULT_PASSWORD)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Newline-delimited JSON-RPC over Tokio TCP: mining.subscribe and mining.authorize on connect, mining.notify and mining.set_difficulty tracked, shares built from the job (coinbase, merkle root, header) and double-SHA-256 hashed in Rust")
            .llm_control("When and how long to mine, what to submit, which workers to authorize and what difficulty to ask for")
            .e2e_testing("tests/client/stratum: ckpool (solo mode) over Bitcoin Core 28.1 in regtest; ckpool's own hash of every submitted share is read from its log and must equal NetGet's")
            .notes("Mining is CPU-only, single-threaded and bounded per action (50M hashes); it exists to prove work, not to earn. No version rolling, no extranonce subscription. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the pool at 127.0.0.1:3333 as netget.rig1 and mine each job for a million hashes"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"stratum","remote_addr":"127.0.0.1:3333",
            "startup_params":{"user":"netget.rig1"},
            "instruction":"Mine every new job for a million hashes and report accepted shares"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"stratum_job","handler":{"type":"static","actions":[{"type":MINE,"max_hashes":1000000}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'stratum_mine','max_hashes':1000000}] if t=='stratum_job' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for StratumClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
