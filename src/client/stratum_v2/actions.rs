//! What the model does as a Stratum V2 client. As a mining device: mine the current job for a
//! bounded number of hashes (Rust does the hashing and submits what meets the channel's
//! target), submit a share by hand, open, update and close channels. As a job declarator
//! client: ask for tokens, declare the jobs it chooses, and mine and push a solution. As a
//! template client: ask for a template's transactions, and mine a template and submit it.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::stratum_v2::actions::{action, p};
use crate::server::stratum_v2::{bitcoin as btc, wire};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const MINE: &str = "stratum_v2_mine";
pub const SUBMIT: &str = "stratum_v2_submit";
pub const OPEN_CHANNEL: &str = "stratum_v2_open_channel";
pub const UPDATE_CHANNEL: &str = "stratum_v2_update_channel";
pub const CLOSE_CHANNEL: &str = "stratum_v2_close_channel";
pub const REQUEST_TOKEN: &str = "stratum_v2_request_token";
pub const DECLARE_JOB: &str = "stratum_v2_declare_job";
pub const PUSH_SOLUTION: &str = "stratum_v2_push_solution";
pub const REQUEST_TRANSACTIONS: &str = "stratum_v2_request_transactions";
pub const MINE_TEMPLATE: &str = "stratum_v2_mine_template";
pub const SET_CONSTRAINTS: &str = "stratum_v2_set_coinbase_constraints";
/// The role a client takes when `role` is not given.
pub const DEFAULT_ROLE: &str = "mining";
/// The chain a job declarator client checks heights and the subsidy against by default.
pub const DEFAULT_NETWORK: &str = "mainnet";
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

pub fn jd_actions() -> Vec<ActionDefinition> {
    vec![
        action(REQUEST_TOKEN, "Ask the job declarator for another mining job token (AllocateMiningJobToken); one is requested on connect, and each declaration uses one.",
            vec![p("user_identifier", "string", "Who to ask as (default the user_identity startup parameter)", false)],
            json!({"type": REQUEST_TOKEN})),
        action(DECLARE_JOB, "Declare the block NetGet will mine (DeclareMiningJob), using the oldest token held. Rust builds the coinbase — BIP 34 height, the message, 8 bytes of extranonce space, the outputs the token requires with the coinbase value on the first, and the witness commitment — and answers the job declarator's ProvideMissingTransactions from these transactions.",
            vec![
                p("height", "number", "The height of the block being declared: the chain tip's height plus one", true),
                p("transactions", "array", "Up to 64 transactions, each {\"inputs\": [{\"txid\": <64 hex digits as RPC shows it>, \"vout\": <output index>, \"value_sats\": <value of the output spent>}], \"outputs\": [{\"value_sats\": <n>, \"pay_to\": \"op_true\"} or {\"value_sats\": 0, \"op_return\": <text of at most 80 bytes>}]}", false),
                p("coinbase_value_sats", "number", "What the coinbase pays, at most the height's subsidy plus the transactions' fees (default: exactly that)", false),
                p("version", "number", "The block version (default 536870912, which is 0x20000000)", false),
                p("message", "string", "Text the coinbase scriptSig carries, at most 32 bytes", false),
            ],
            json!({"type": DECLARE_JOB, "height": 120, "message": "NetGet"})),
        action(PUSH_SOLUTION, "Mine an accepted declaration on the given tip and push the first block found (PushSolution); Rust hashes up to max_hashes nonces.",
            vec![
                p("prev_hash", "string", "The chain tip the block builds on, as RPC shows hashes (64 hex digits)", true),
                p("nbits", "string", "The compact target as RPC shows it, 8 hex digits such as 207fffff", true),
                p("ntime", "number", "The header timestamp, unix seconds (default now)", false),
                p("request_id", "number", "The declaration (default the newest accepted)", false),
                p("max_hashes", "number", "How many nonces to try (default 1000000, at most 50000000)", false),
            ],
            json!({"type": PUSH_SOLUTION, "prev_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "nbits": "207fffff"})),
        action("disconnect", "Close the connection to the job declarator.", vec![], json!({"type": "disconnect"})),
    ]
}

pub fn tdp_actions() -> Vec<ActionDefinition> {
    vec![
        action(REQUEST_TRANSACTIONS, "Ask the template provider for a template's transactions (RequestTransactionData). Rust parses them and checks the template's merkle path and witness commitment against them; the answer arrives as stratum_v2_template_transactions.",
            vec![p("template_id", "number", "The template (default the newest)", false)],
            json!({"type": REQUEST_TRANSACTIONS})),
        action(MINE_TEMPLATE, "Mine a template on its tip and submit the first block found (SubmitSolution). Rust builds the coinbase the template describes, with NetGet's OP_TRUE output taking the remaining value, and hashes up to max_hashes nonces.",
            vec![
                p("template_id", "number", "The template (default the newest that can be mined)", false),
                p("max_hashes", "number", "How many nonces to try (default 1000000, at most 50000000)", false),
                p("message", "string", "Text the coinbase scriptSig carries after the height, at most 32 bytes", false),
            ],
            json!({"type": MINE_TEMPLATE, "max_hashes": 1000000})),
        action(SET_CONSTRAINTS, "Tell the template provider how much room NetGet's coinbase outputs need (CoinbaseOutputConstraints); one is sent on connect for NetGet's single output.",
            vec![
                p("max_additional_size", "number", "Bytes NetGet's coinbase outputs add, 0 to 4294967295", true),
                p("max_additional_sigops", "number", "Signature operations they add, 0 to 65535", true),
            ],
            json!({"type": SET_CONSTRAINTS, "max_additional_size": 100, "max_additional_sigops": 4})),
        action("disconnect", "Close the connection to the template provider.", vec![], json!({"type": "disconnect"})),
    ]
}

fn tdp_event(
    id: &str,
    description: &str,
    example: Value,
    params: Vec<crate::llm::actions::Parameter>,
) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(tdp_actions())
}

pub static TEMPLATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    tdp_event(
        "stratum_v2_template",
        "The template provider sent a block template (NewTemplate). A future template becomes minable when SetNewPrevHash names it.",
        json!({"type": REQUEST_TRANSACTIONS}),
        vec![
            p("template_id", "number", "The template's id", true),
            p("future", "boolean", "Whether it waits for a SetNewPrevHash", true),
            p("version", "number", "The block version", true),
            p("height", "number", "The height its coinbase prefix commits to (BIP 34)", false),
            p("coinbase_value_sats", "number", "What the coinbase may pay, in satoshis", true),
            p("merkle_path_len", "number", "Levels of the coinbase's merkle path", true),
            p("coinbase_outputs", "array", "Outputs the template's coinbase must carry: value_sats and script_type", true),
            p("prev_hash", "string", "The tip it builds on, for a template that is not a future one", false),
        ],
    )
});

pub static TEMPLATE_PREV_HASH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    tdp_event(
        "stratum_v2_template_prev_hash",
        "The template provider moved to a new chain tip (SetNewPrevHash), activating the template it names.",
        json!({"type": MINE_TEMPLATE}),
        vec![
            p("template_id", "number", "The template it activates", true),
            p("prev_hash", "string", "The new tip, as RPC shows hashes", true),
            p("ntime", "number", "The header timestamp to mine from", true),
            p("nbits", "string", "The compact target, 8 hex digits", true),
            p("target_matches_nbits", "boolean", "Whether the target it sent is the one nbits gives", true),
        ],
    )
});

pub static TEMPLATE_TRANSACTIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    tdp_event(
        "stratum_v2_template_transactions",
        "The template provider answered RequestTransactionData. Rust parsed the transactions and checked the template's merkle path and witness commitment against them.",
        json!({"type": MINE_TEMPLATE}),
        vec![
            p("template_id", "number", "The template whose transactions these are", true),
            p("transaction_count", "number", "Transactions besides the coinbase", false),
            p("segwit_transactions", "number", "How many carry witness data", false),
            p("weight", "number", "The transactions' total weight, in weight units", false),
            p("merkle_path_matches", "boolean", "Whether the template's merkle path is the one these transactions give", false),
            p("witness_commitment_matches", "boolean", "Whether the template's witness commitment covers these transactions", false),
            p("error_code", "string", "The provider's reason when it had no data (RequestTransactionData.Error)", false),
        ],
    )
});

pub static TEMPLATE_SOLUTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    tdp_event(
        "stratum_v2_template_solution",
        "A stratum_v2_mine_template run ended: with a block found and submitted (SubmitSolution), or without.",
        json!({"type": REQUEST_TRANSACTIONS}),
        vec![
            p("template_id", "number", "The template mined", true),
            p("height", "number", "The block height the mined template commits to", false),
            p("found", "boolean", "Whether a header met the target", true),
            p("submitted", "boolean", "Whether SubmitSolution was sent", true),
            p("hash", "string", "The best header hash, as RPC shows hashes", true),
            p("hashes", "number", "How many nonces the run hashed", true),
            p("nonce", "number", "The nonce of that header", true),
        ],
    )
});

fn jd_event(
    id: &str,
    description: &str,
    example: Value,
    params: Vec<crate::llm::actions::Parameter>,
) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(jd_actions())
}

pub static JD_TOKEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    jd_event(
        "stratum_v2_jd_token",
        "The job declarator gave NetGet a mining job token (AllocateMiningJobToken.Success). Declare a job with it (stratum_v2_declare_job) or keep it.",
        json!({"type": DECLARE_JOB, "height": 120}),
        vec![
            p("request_id", "number", "The request it answers", true),
            p("coinbase_outputs", "array", "Outputs a declared coinbase must pay: value_sats and script_type, with op_return text", true),
            p("tokens_held", "number", "Unused tokens now held", true),
        ],
    )
});

pub static JD_DECLARE_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    jd_event(
        "stratum_v2_jd_declare_result",
        "The job declarator answered a declaration: DeclareMiningJob.Success (accepted) or DeclareMiningJob.Error (with its error code).",
        json!({"type": PUSH_SOLUTION, "prev_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "nbits": "207fffff"}),
        vec![
            p("request_id", "number", "The declaration", true),
            p("accepted", "boolean", "Whether it was accepted", true),
            p("height", "number", "The height declared", true),
            p("transaction_count", "number", "Transactions declared besides the coinbase", true),
            p("error_code", "string", "The job declarator's reason when it refused", false),
            p("new_token_bytes", "number", "The length of the token issued for the accepted job", false),
        ],
    )
});

pub static JD_SOLUTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    jd_event(
        "stratum_v2_jd_solution_pushed",
        "A stratum_v2_push_solution run ended: with a block found and pushed (PushSolution), or without.",
        json!({"type": REQUEST_TOKEN}),
        vec![
            p("request_id", "number", "The declaration mined", true),
            p("height", "number", "The block height the mined declaration commits to", true),
            p("found", "boolean", "Whether a header met nbits", true),
            p("pushed", "boolean", "Whether PushSolution was sent", true),
            p("hash", "string", "The best header hash, as RPC shows hashes", true),
            p("hashes", "number", "How many nonces the run hashed", true),
            p("nonce", "number", "The nonce of that header", true),
            p("ntime", "number", "The header timestamp the run mined at, unix seconds", true),
        ],
    )
});

/// nbits from a hex string ("207fffff", as RPC shows it) or a number.
pub fn nbits(v: &Value) -> Result<Option<u32>> {
    match &v["nbits"] {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(
            u32::from_str_radix(s.trim_start_matches("0x"), 16)
                .with_context(|| format!("nbits {s:?} is not hex"))?,
        )),
        Value::Number(n) => {
            let n = n.as_u64().context("nbits must be unsigned")?;
            ensure!(n <= u64::from(u32::MAX), "nbits must fit 32 bits");
            Ok(Some(n as u32))
        }
        _ => bail!("nbits must be hex text or a number"),
    }
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
        REQUEST_TOKEN => {
            if let Some(u) = v.get("user_identifier").filter(|x| !x.is_null()) {
                let u = u.as_str().context("user_identifier must be text")?;
                ensure!(u.len() <= 255, "user_identifier must be at most 255 bytes");
            }
        }
        DECLARE_JOB => {
            let h = v["height"].as_u64().context("height is required")?;
            ensure!(
                (1..=u64::from(crate::server::stratum_v2::template_provider::MAX_HEIGHT))
                    .contains(&h),
                "height must be 1..=10000000"
            );
            btc::txs_from_json(&v["transactions"])?;
            u32_field(v, "version", false)?;
            if let Some(c) = v.get("coinbase_value_sats").filter(|x| !x.is_null()) {
                ensure!(
                    c.as_u64().is_some_and(|c| c <= btc::MAX_MONEY),
                    "coinbase_value_sats must be 0..=21M BTC in sats"
                );
            }
            if let Some(m) = v.get("message").filter(|x| !x.is_null()) {
                let m = m.as_str().context("message must be text")?;
                ensure!(m.len() <= 32, "message must be at most 32 bytes");
            }
        }
        PUSH_SOLUTION => {
            btc::parse_txid(v["prev_hash"].as_str().context("prev_hash is required")?)
                .context("prev_hash")?;
            btc::compact_to_target(nbits(v)?.context("nbits is required")?)?;
            u32_field(v, "ntime", false)?;
            u32_field(v, "request_id", false)?;
            if let Some(n) = v.get("max_hashes").filter(|x| !x.is_null()) {
                let n = n.as_u64().context("max_hashes must be a whole number")?;
                ensure!(
                    (1..=MAX_MINE_HASHES).contains(&n),
                    "max_hashes must be 1..={MAX_MINE_HASHES}"
                );
            }
        }
        REQUEST_TRANSACTIONS => {
            if let Some(x) = v.get("template_id").filter(|x| !x.is_null()) {
                x.as_u64().context("template_id must be a whole number")?;
            }
        }
        MINE_TEMPLATE => {
            if let Some(x) = v.get("template_id").filter(|x| !x.is_null()) {
                x.as_u64().context("template_id must be a whole number")?;
            }
            if let Some(n) = v.get("max_hashes").filter(|x| !x.is_null()) {
                let n = n.as_u64().context("max_hashes must be a whole number")?;
                ensure!(
                    (1..=MAX_MINE_HASHES).contains(&n),
                    "max_hashes must be 1..={MAX_MINE_HASHES}"
                );
            }
            if let Some(m) = v.get("message").filter(|x| !x.is_null()) {
                let m = m.as_str().context("message must be text")?;
                ensure!(m.len() <= 32, "message must be at most 32 bytes");
            }
        }
        SET_CONSTRAINTS => {
            u32_field(v, "max_additional_size", true)?;
            let s = v["max_additional_sigops"]
                .as_u64()
                .context("max_additional_sigops is required")?;
            ensure!(s <= 65535, "max_additional_sigops must be 0..=65535");
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
        "Stratum V2 client, Noise NX pinned to the server's authority key: a mining device (a mining channel, and shares mined and submitted as the model directs) or a job declarator client (tokens, jobs the model chooses declared to a Job Declaration Server, solutions pushed)"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        let mut all = actions();
        all.extend(
            jd_actions()
                .into_iter()
                .chain(tdp_actions())
                .filter(|a| a.name != "disconnect"),
        );
        all
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
            JD_TOKEN_EVENT.clone(),
            JD_DECLARE_RESULT_EVENT.clone(),
            JD_SOLUTION_EVENT.clone(),
            TEMPLATE_EVENT.clone(),
            TEMPLATE_PREV_HASH_EVENT.clone(),
            TEMPLATE_TRANSACTIONS_EVENT.clone(),
            TEMPLATE_SOLUTION_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "role".into(),
                type_hint: "string".into(),
                description: "mining (a mining device on a pool's Mining Protocol), job_declarator (a Job Declarator Client declaring its own jobs to a Job Declaration Server) or template_client (taking block templates from a Template Provider)".into(),
                required: false,
                example: json!("job_declarator"),
                default: Some(json!(DEFAULT_ROLE)),
            },
            ParameterDefinition {
                name: "network".into(),
                type_hint: "string".into(),
                description: "Job declarator: the chain heights, nbits and the block subsidy are checked against (mainnet, testnet4, signet or regtest)".into(),
                required: false,
                example: json!("regtest"),
                default: Some(json!(DEFAULT_NETWORK)),
            },
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
                description: "Who the first channel mines as, usually account.worker; a job declarator asks for tokens as this".into(),
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
            .implementation("Hand-rolled from sv2-spec, sharing the server roles' Noise NX initiator, codec and Bitcoin arithmetic; the server's certificate is verified against the configured authority key before SetupConnection is sent. mining: a standard or extended channel opens on connect, jobs are tracked, and shares are built (coinbase, merkle path, header) and double-SHA-256 hashed in Rust. job_declarator: tokens are requested, the model's jobs are declared with a coinbase built the way SRI's JDS splits one and the witness commitment for their transactions, ProvideMissingTransactions is answered, and accepted jobs can be mined and pushed. template_client: templates and tips are tracked, each template's merkle path and commitment are checked against its transactions, and a template can be mined and submitted")
            .llm_control("mining: when and how long to mine, what to submit, and which channels to open, update or close. job_declarator: which jobs to declare (height, coinbase value, transactions) and when to mine and push one. template_client: which templates to inspect and mine")
            .e2e_testing("tests/client/stratum_v2: SRI's pool_sv2 (sv2-apps v0.8.0) over Bitcoin Core 31.0 in regtest via IPC accepts NetGet's channel and shares, and the block Bitcoin Core accepts has the hash NetGet computed; the JDS embedded in SRI's pool_sv2 asks for, validates (Bitcoin Core's checkBlock) and accepts NetGet's declared job, refuses one spending a missing output, and receives its PushSolution; sv2-tp 1.1.2 serves templates from Bitcoin Core's mempool, NetGet checks their merkle path and commitment against three segwit transactions, and Bitcoin Core accepts the block NetGet mines on one")
            .notes("Experimental: one independent server per role (SRI's pool, SRI's JDS, sv2-tp); the mining device's extended-channel path is exercised only against NetGet's own pool. Mining is CPU-only, single-threaded and bounded per action (50M hashes); it exists to prove work, not to earn. The job declarator client declares jobs but opens no mining channel to redeem them (no SetCustomMiningJob); the template client's coinbase pays OP_TRUE. No extensions. A handler chain stops after 8 follow-ups; frames over 256 KiB (mining, job declarator) or 8 MiB (template client) end the connection.")
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
