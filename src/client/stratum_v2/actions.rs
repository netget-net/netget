//! What the model does as a Stratum V2 mining device: mine the current job for a bounded number
//! of hashes (Rust does the hashing and submits what meets the channel's target), submit a
//! share by hand, open, update and close channels.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::stratum_v2::actions::{action, p};
use crate::server::stratum_v2::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const MINE: &str = "stratum_v2_mine";
pub const SUBMIT: &str = "stratum_v2_submit";
pub const OPEN_CHANNEL: &str = "stratum_v2_open_channel";
pub const UPDATE_CHANNEL: &str = "stratum_v2_update_channel";
pub const CLOSE_CHANNEL: &str = "stratum_v2_close_channel";
/// Hashes one stratum_v2_mine tries when the model names no number.
pub const DEFAULT_MINE_HASHES: u64 = 1_000_000;
/// Hashes one stratum_v2_mine may try at most.
pub const MAX_MINE_HASHES: u64 = 50_000_000;
/// The user a channel opens as when none is named.
pub const DEFAULT_USER: &str = "netget";
/// The hash rate a channel declares when none is named, in hashes per second.
pub const DEFAULT_NOMINAL_HASH_RATE: f64 = 1_000_000.0;
/// The channel kind opened on connect when none is named.
pub const DEFAULT_CHANNEL_KIND: &str = "standard";

#[derive(Default)]
pub struct StratumV2ClientProtocol;
impl StratumV2ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(MINE, "Mine the channel's current job: Rust hashes up to max_hashes nonces and submits the first share that meets the channel's target (and, with submit_best, the best one found if none does).",
            vec![
                p("max_hashes", "number", "How many nonces to try (default 1000000, at most 50000000)", false),
                p("submit_best", "boolean", "Submit the best share found even when it misses the target, e.g. to see the pool's verdict (default false)", false),
                p("channel_id", "number", "The channel (default the first open one)", false),
            ],
            json!({"type": MINE, "max_hashes": 2000000})),
        action(SUBMIT, "Submit a share by hand for the current or a named job.",
            vec![
                p("nonce", "number", "The header nonce, 0..=4294967295", true),
                p("ntime", "number", "Header timestamp in Unix seconds (default the job's start)", false),
                p("version", "number", "Header version (default the job's)", false),
                p("job_id", "number", "The job (default the active one)", false),
                p("extranonce", "number", "Extended channels: the extranonce counter Rust writes into the channel's extranonce bytes (default 0)", false),
                p("channel_id", "number", "The channel (default the first open one)", false),
            ],
            json!({"type": SUBMIT, "nonce": 12345})),
        action(OPEN_CHANNEL, "Open another mining channel on this connection.",
            vec![
                p("user_identity", "string", "Who mines on it, usually account.worker", true),
                p("nominal_hash_rate", "number", "Hash rate to declare, hashes per second (default 1000000)", false),
                p("channel_kind", "string", "standard or extended (default: the connection's kind)", false),
            ],
            json!({"type": OPEN_CHANNEL, "user_identity": "netget.rig2"})),
        action(UPDATE_CHANNEL, "Tell the pool the channel's hash rate changed (UpdateChannel), and optionally the lowest difficulty it accepts.",
            vec![
                p("nominal_hash_rate", "number", "The new hash rate, hashes per second", true),
                p("min_difficulty", "number", "The pool must not set a difficulty below this (default: no bound)", false),
                p("channel_id", "number", "The channel (default the first open one)", false),
            ],
            json!({"type": UPDATE_CHANNEL, "nominal_hash_rate": 5000000})),
        action(CLOSE_CHANNEL, "Close a channel (CloseChannel).",
            vec![
                p("reason_code", "string", "A printable-ASCII reason, e.g. shutdown", true),
                p("channel_id", "number", "The channel (default the first open one)", false),
            ],
            json!({"type": CLOSE_CHANNEL, "reason_code": "shutdown"})),
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

pub static CHANNEL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_v2_channel",
        "The pool answered a request to open a channel.",
        vec![
            p("ok", "boolean", "Whether the channel opened", true),
            p("request_id", "number", "The request it answers", true),
            p("channel_id", "number", "The new channel's id", false),
            p("channel_kind", "string", "standard or extended", false),
            p("user_identity", "string", "Who mines on it", false),
            p(
                "difficulty",
                "number",
                "The channel's share difficulty",
                false,
            ),
            p(
                "extranonce_size",
                "number",
                "Bytes of extranonce Rust rolls (extended channels)",
                false,
            ),
            p(
                "error_code",
                "string",
                "The pool's reason when it refused",
                false,
            ),
        ],
    )
});

pub static JOB_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("stratum_v2_job", "A job became the channel's work: a NewMiningJob or NewExtendedMiningJob that is active now, or a future one activated by SetNewPrevHash.", vec![
        p("channel_id", "number", "The channel the job or share belongs to", true),
        p("job_id", "number", "The job's id, which stratum_v2_submit can name", true),
        p("channel_kind", "string", "standard or extended", true),
        p("user_identity", "string", "Who mines on the channel", true),
        p("prev_hash", "string", "The previous block hash, as RPC shows hashes", true),
        p("ntime", "number", "The header timestamp hashing starts at", true),
        p("nbits", "string", "The network target, compact form", true),
        p("version", "number", "The header version", true),
        p("difficulty", "number", "The channel's share difficulty", true),
        p("merkle_path_len", "number", "Extended jobs: how many transaction branches the job carries", false),
    ])
});

pub static SHARE_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_v2_share_result",
        "The pool answered a submitted share (SubmitShares.Success or SubmitShares.Error).",
        vec![
            p(
                "channel_id",
                "number",
                "The channel the job or share belongs to",
                true,
            ),
            p(
                "sequence_number",
                "number",
                "The share's sequence number",
                true,
            ),
            p("job_id", "number", "The job it was for", false),
            p("nonce", "number", "The nonce of the share submitted", false),
            p(
                "ntime",
                "number",
                "The header timestamp of the share submitted",
                false,
            ),
            p(
                "hash",
                "string",
                "The header hash Rust computed for it, as RPC shows hashes",
                false,
            ),
            p(
                "share_difficulty",
                "number",
                "The difficulty that hash meets",
                false,
            ),
            p("accepted", "boolean", "Whether the pool accepted it", true),
            p(
                "error_code",
                "string",
                "The pool's reason when it refused",
                false,
            ),
            p(
                "new_submits_accepted_count",
                "number",
                "Shares the pool acknowledged in this batch",
                false,
            ),
            p(
                "new_shares_sum",
                "number",
                "Their summed difficulty, as the pool counts it",
                false,
            ),
        ],
    )
});

pub static MINED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "stratum_v2_mining_done",
        "A stratum_v2_mine run ended without submitting anything.",
        vec![
            p(
                "channel_id",
                "number",
                "The channel, when there is one",
                false,
            ),
            p("hashes", "number", "How many nonces the run tried", true),
            p(
                "best_difficulty",
                "number",
                "The best share difficulty found",
                true,
            ),
            p("difficulty", "number", "The channel's difficulty", true),
            p(
                "reason",
                "string",
                "Why nothing was submitted (no channel, no job yet, nothing met the target)",
                true,
            ),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("stratum_v2_message", "The pool sent something else: CloseChannel, Reconnect, UpdateChannel.Error, SetExtranoncePrefix, SetGroupChannel or ChannelEndpointChanged.", vec![
        p("message", "string", "The message's name", true),
        p("fields", "object", "What it carried", true),
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

fn rate(v: &Value, key: &str, required: bool) -> Result<()> {
    match v.get(key).filter(|x| !x.is_null()) {
        Some(x) => {
            let r = x
                .as_f64()
                .with_context(|| format!("{key} must be a number"))?;
            ensure!(
                r.is_finite() && (0.0..=1e21).contains(&r),
                "{key} must be between 0 and 1e21"
            );
            Ok(())
        }
        None if required => bail!("{key} is required"),
        None => Ok(()),
    }
}

pub fn check(v: &Value) -> Result<()> {
    u32_field(v, "channel_id", false)?;
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
            u32_field(v, "ntime", false)?;
            u32_field(v, "version", false)?;
            u32_field(v, "job_id", false)?;
            if let Some(x) = v.get("extranonce").filter(|x| !x.is_null()) {
                x.as_u64().context("extranonce must be a whole number")?;
            }
        }
        OPEN_CHANNEL => {
            let u = v["user_identity"]
                .as_str()
                .context("user_identity is required")?;
            ensure!(u.len() <= 255, "user_identity must be at most 255 bytes");
            rate(v, "nominal_hash_rate", false)?;
            if let Some(k) = v.get("channel_kind").filter(|x| !x.is_null()) {
                ensure!(
                    matches!(k.as_str(), Some("standard" | "extended")),
                    "channel_kind must be standard or extended"
                );
            }
        }
        UPDATE_CHANNEL => {
            rate(v, "nominal_hash_rate", true)?;
            if let Some(d) = v.get("min_difficulty").filter(|x| !x.is_null()) {
                let d = d.as_f64().context("min_difficulty must be a number")?;
                ensure!(d > 0.0, "min_difficulty must be above 0");
            }
        }
        CLOSE_CHANNEL => {
            let r = v["reason_code"]
                .as_str()
                .context("reason_code is required")?;
            ensure!(
                r.len() <= 64 && wire::valid_error_code(r),
                "reason_code must be 1-64 printable ASCII characters"
            );
        }
        other => bail!("Unknown Stratum V2 client action {other:?}"),
    }
    Ok(())
}

impl Protocol for StratumV2ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Stratum V2"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Noise>StratumV2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["stratum v2", "stratum2", "sv2", "stratum2+tcp"]
    }
    fn description(&self) -> &'static str {
        "Stratum V2 mining device: Noise NX handshake pinned to the pool's authority key, SetupConnection, a mining channel, and shares mined and submitted as the model directs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CHANNEL_EVENT.clone(),
            JOB_EVENT.clone(),
            SHARE_RESULT_EVENT.clone(),
            MINED_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "authority_public_key".into(),
                type_hint: "string".into(),
                description: "The pool's authority public key, base58check as pools publish it (the path of a stratum2+tcp:// URL); the pool's certificate must be signed by it".into(),
                required: true,
                example: json!("9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"),
                default: None,
            },
            ParameterDefinition {
                name: "user_identity".into(),
                type_hint: "string".into(),
                description: "Who the first channel mines as, usually account.worker".into(),
                required: false,
                example: json!("netget.rig1"),
                default: Some(json!(DEFAULT_USER)),
            },
            ParameterDefinition {
                name: "nominal_hash_rate".into(),
                type_hint: "number".into(),
                description: "Hash rate the first channel declares, hashes per second; pools set the difficulty from it".into(),
                required: false,
                example: json!(500000),
                default: Some(json!(DEFAULT_NOMINAL_HASH_RATE)),
            },
            ParameterDefinition {
                name: "channel_kind".into(),
                type_hint: "string".into(),
                description: "standard (header-only mining, REQUIRES_STANDARD_JOBS) or extended (Rust rolls the extranonce)".into(),
                required: false,
                example: json!("extended"),
                default: Some(json!(DEFAULT_CHANNEL_KIND)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-rolled from sv2-spec, sharing the server role's Noise NX initiator, codec and share arithmetic: the pool's certificate is verified against the configured authority key before SetupConnection is sent; a standard or extended channel opens on connect; NewMiningJob, NewExtendedMiningJob, SetNewPrevHash, SetTarget and SetExtranoncePrefix are tracked; shares are built (coinbase, merkle path, header) and double-SHA-256 hashed in Rust")
            .llm_control("When and how long to mine, what to submit, and which channels to open, update or close")
            .e2e_testing("tests/client/stratum_v2: SRI's pool_sv2 (sv2-apps v0.8.0) over Bitcoin Core 31.0 in regtest via IPC accepts NetGet's channel and shares; on regtest a share is a block, so the block Bitcoin Core accepts must have the exact hash NetGet computed")
            .notes("Experimental: one independent pool (SRI's) and its node agree with it; the extended-channel path is exercised only against NetGet's own pool. Mining is CPU-only, single-threaded and bounded per action (50M hashes); it exists to prove work, not to earn. No job declaration, no extensions. A handler chain stops after 8 follow-ups; frames over 256 KiB end the connection.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Stratum V2 pool at 127.0.0.1:3333 with authority key 9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72 and mine each job for a million hashes"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"stratum_v2","remote_addr":"127.0.0.1:3333",
            "startup_params":{"authority_public_key":"9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72","user_identity":"netget.rig1"},
            "instruction":"Mine every new job for a million hashes and report accepted shares"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"stratum_v2_job","handler":{"type":"static","actions":[{"type":MINE,"max_hashes":1000000}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'stratum_v2_mine','max_hashes':1000000}] if t=='stratum_v2_job' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for StratumV2ClientProtocol {
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
