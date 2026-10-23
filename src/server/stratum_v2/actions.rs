//! What the model decides as a Stratum V2 server. As a pool: which devices may connect, which
//! channels open and at what difficulty, which shares Rust has proven valid it credits, and the
//! work each channel gets. As a template provider: who may take templates and every template
//! they get. As a job declarator: who may declare, who gets a token, and which declared jobs
//! are accepted. Rust owns the Noise session, every message's encoding, the coinbase, merkle
//! and header arithmetic, and every refusal that arithmetic decides.
use super::{bitcoin as btc, wire};
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

pub const ACCEPT: &str = "stratum_v2_accept";
pub const REJECT: &str = "stratum_v2_reject";
pub const SET_TARGET: &str = "stratum_v2_set_target";
pub const NEW_JOB: &str = "stratum_v2_new_job";
pub const CLOSE_CHANNEL: &str = "stratum_v2_close_channel";
pub const NEW_TEMPLATE: &str = "stratum_v2_new_template";
pub const ALLOCATE_TOKEN: &str = "stratum_v2_allocate_token";
/// The role a server takes when `role` is not given.
pub const DEFAULT_ROLE: &str = "pool";
/// The chain the template provider and job declarator check against when `network` is not given.
pub const DEFAULT_NETWORK: &str = "mainnet";
/// A difficulty must lie in (0, MAX_DIFFICULTY].
pub const MAX_DIFFICULTY: f64 = 1e15;
/// What a job's coinbase says when the model names nothing.
pub const DEFAULT_COINBASE_MESSAGE: &str = "NetGet";
/// Error and reason codes the model writes are at most this long.
pub const MAX_CODE_LEN: usize = 64;

#[derive(Default)]
pub struct StratumV2Protocol;
impl StratumV2Protocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Stratum V2 {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action(
        ACCEPT,
        "Accept the connection, open the channel, or credit the share being answered.",
        vec![],
        json!({"type": ACCEPT}),
    )
}

fn reject() -> ActionDefinition {
    action(
        REJECT,
        "Refuse the connection (SetupConnection.Error), the channel (OpenMiningChannel.Error), the custom job (SetCustomMiningJob.Error) or the share (SubmitShares.Error) being answered.",
        vec![p(
            "error_code",
            "string",
            "A printable-ASCII error code the device is shown, e.g. unknown-user or share-rejected (at most 64 characters)",
            true,
        )],
        json!({"type": REJECT, "error_code": "unknown-user"}),
    )
}

pub fn set_target() -> ActionDefinition {
    action(
        SET_TARGET,
        "Set the share difficulty of the channel being answered: with an accepted channel it is the channel's first target, otherwise Rust sends SetTarget. Rust never exceeds the channel's max_target.",
        vec![p(
            "difficulty",
            "number",
            "Share difficulty above 0 (difficulty 1 is the target 0x00000000ffff0000…; fractions are allowed)",
            true,
        )],
        json!({"type": SET_TARGET, "difficulty": 0.5}),
    )
}

fn new_job() -> ActionDefinition {
    action(
        NEW_JOB,
        "Give the channel being answered new work. Rust builds the coinbase (BIP 34 height, this message, the extranonce) and the header fields. A new prev_hash makes it the only valid job (SetNewPrevHash); without one it joins the current work.",
        vec![
            p("message", "string", "Text the coinbase carries, at most 32 bytes (default NetGet)", false),
            p("prev_hash", "string", "Previous block hash as RPC shows it, 64 hex digits (default: the channel's current one)", false),
        ],
        json!({"type": NEW_JOB, "message": "block 2"}),
    )
}

fn close_channel() -> ActionDefinition {
    action(
        CLOSE_CHANNEL,
        "Close the channel being answered (CloseChannel); its shares are refused from then on.",
        vec![p(
            "reason_code",
            "string",
            "A printable-ASCII reason, e.g. maintenance (at most 64 characters)",
            true,
        )],
        json!({"type": CLOSE_CHANNEL, "reason_code": "maintenance"}),
    )
}

pub fn new_template() -> ActionDefinition {
    action(
        NEW_TEMPLATE,
        "Send the template provider's client a block template. Rust serialises the transactions, computes the merkle path, the witness commitment and the BIP 34 height push, and sends NewTemplate — followed by SetNewPrevHash when prev_hash names a new chain tip. A template on the current tip may omit prev_hash, height and nbits. Rust refuses a template whose height, nbits, version, coinbase value or weight no node would accept.",
        vec![
            p("prev_hash", "string", "The block this template builds on, as RPC shows hashes (64 hex digits); required for the first template and to move to a new tip", false),
            p("height", "number", "The height of the block being built, from 1 to 10,000,000; required with a new prev_hash", false),
            p("nbits", "string", "The compact target as RPC shows it, 8 hex digits such as 207fffff; it may be no easier than the network's limit (default: that limit)", false),
            p("ntime", "number", "The header timestamp the tip allows from, in unix seconds (default: now)", false),
            p("version", "number", "The block version, at least 4 (default 536870912, which is 0x20000000)", false),
            p("coinbase_value_sats", "number", "What the coinbase may pay, in satoshis: at most the height's subsidy plus the fees of the transactions (default: exactly that)", false),
            p("transactions", "array", "Up to 64 transactions, each {\"inputs\": [{\"txid\": <64 hex digits as RPC shows it>, \"vout\": <output index>, \"value_sats\": <value of the output spent>}], \"outputs\": [{\"value_sats\": <n>, \"pay_to\": \"op_true\"} or {\"value_sats\": 0, \"op_return\": <text of at most 80 bytes>}]}; 1 to 16 inputs and outputs each, and outputs may not exceed inputs", false),
        ],
        json!({"type": NEW_TEMPLATE, "prev_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
               "height": 102, "nbits": "207fffff",
               "transactions": [{"inputs": [{"txid": "5c4e9bb1b6f5f2b2d6c0cfb0e4ee2ad6a3b4bc2dfe32e7d3cd8b7d0bb2b8a0f1", "vout": 0, "value_sats": 5000000000u64}],
                                 "outputs": [{"value_sats": 4999990000u64, "pay_to": "op_true"}]}]}),
    )
}

fn allocate_token() -> ActionDefinition {
    action(
        ALLOCATE_TOKEN,
        "Give the job declarator client a mining job token (AllocateMiningJobToken.Success), naming the output its coinbase must include. Answer an allocation with stratum_v2_accept and this; stratum_v2_reject refuses, and since the protocol has no AllocateMiningJobToken.Error the connection then ends.",
        vec![
            p("pay_to", "string", "The script of the output the declared coinbase must pay: op_true (default)", false),
            p("op_return", "string", "Instead of pay_to: an OP_RETURN output carrying this text (at most 80 bytes)", false),
        ],
        json!({"type": ALLOCATE_TOKEN, "pay_to": "op_true"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![accept(), reject(), set_target(), new_job(), close_channel()]
}

fn template_actions() -> Vec<ActionDefinition> {
    vec![new_template()]
}

fn job_declarator_actions() -> Vec<ActionDefinition> {
    vec![accept(), reject(), allocate_token()]
}

pub static TP_SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_tp_setup_connection",
        "A pool or job declarator client completed the Noise handshake and asked to take templates (SetupConnection for the Template Distribution Protocol). Accept or reject it; templates follow once it sends CoinbaseOutputConstraints.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("vendor", "string", "The client's vendor string (often empty)", true),
        p("hardware_version", "string", "The hardware version it reports", true),
        p("firmware", "string", "The firmware it reports", true),
        p("device_id", "string", "The device id it reports", true),
        p("endpoint_host", "string", "The host it says it connected to", true),
        p("endpoint_port", "number", "The port it says it connected to", true),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(vec![accept(), reject()])
});

pub static TP_CONSTRAINTS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_tp_coinbase_output_constraints",
        "The template client said how much room its own coinbase outputs need (CoinbaseOutputConstraints). Answer with stratum_v2_new_template to give it work; the first template names prev_hash and height. Answering nothing sends no work.",
        json!({"type": NEW_TEMPLATE, "prev_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "height": 102}),
    )
    .with_parameters(vec![
        p("max_additional_size", "number", "Bytes its coinbase outputs add", true),
        p("max_additional_sigops", "number", "Signature operations its coinbase outputs add", true),
        p("tip", "object", "The current tip templates build on: prev_hash, height, nbits, ntime (null before the first template)", true),
        p("templates_sent", "number", "Templates already sent on this connection", true),
        p("network", "string", "The chain heights, nbits and the subsidy are checked against", true),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(template_actions())
});

pub static TP_SOLUTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_tp_solution",
        "The template client submitted a solution (SubmitSolution) that Rust rebuilt into a block and verified: its coinbase follows the template and its header hash meets the template's target. The block is logged in full. Answer with stratum_v2_new_template to move the client on, typically to a new tip on top of this block (prev_hash = its hash, height + 1), or with nothing.",
        json!({"type": NEW_TEMPLATE, "prev_hash": "3e1b4f86ac4b8e83a6d4b0aaf5e0d0c3d0c1b6d1a5d6f4a7b8e2c9a0f1d2e3c4", "height": 103}),
    )
    .with_parameters(vec![
        p("template_id", "number", "The template it solves", true),
        p("hash", "string", "The block hash, as RPC shows hashes", true),
        p("height", "number", "The block's height", true),
        p("prev_hash", "string", "The block it builds on", true),
        p("version", "number", "The header version, with any rolled bits", true),
        p("ntime", "number", "The header timestamp", true),
        p("nonce", "number", "The header nonce", true),
        p("nbits", "string", "The compact target the hash meets", true),
        p("transaction_count", "number", "Transactions besides the coinbase", true),
        p("block_size", "number", "The block's size in bytes", true),
        p("stale", "boolean", "Whether a newer tip has been sent since this template", true),
        p("coinbase_outputs", "array", "The coinbase's outputs: value_sats and script_type, with op_return text", true),
        p("relay", "string", RELAY_DESCRIPTION, false),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(template_actions())
});

pub static JD_SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_jd_setup_connection",
        "A job declarator client completed the Noise handshake and asked to declare its own jobs (SetupConnection for the Job Declaration Protocol). Accept or reject it.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("vendor", "string", "The client's vendor string (often empty)", true),
        p("hardware_version", "string", "The hardware version it reports", true),
        p("firmware", "string", "The firmware it reports", true),
        p("device_id", "string", "The device id it reports", true),
        p("endpoint_host", "string", "The host it says it connected to", true),
        p("endpoint_port", "number", "The port it says it connected to", true),
        p("declare_tx_data", "boolean", "Whether it set DECLARE_TX_DATA (full-template declarations)", true),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(vec![accept(), reject()])
});

pub static JD_ALLOCATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_jd_allocate_token",
        "The job declarator client asked for a mining job token (AllocateMiningJobToken). Answer stratum_v2_accept with stratum_v2_allocate_token naming the output its coinbase must pay, or stratum_v2_reject, which ends the connection (the protocol has no error for this).",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("user_identifier", "string", "Who the client says it is", true),
        p("request_id", "number", "The client's request id, which the success echoes", true),
        p("tokens_held", "number", "Tokens this connection already holds", true),
        p("max_tokens", "number", "Tokens a connection may hold before the oldest is evicted", true),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(job_declarator_actions())
});

pub static JD_DECLARE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_jd_declare_job",
        "The job declarator client declared the block it wants to mine (DeclareMiningJob), and Rust has every one of its transactions — asking for the missing ones first — checked that they are the ones it named, and checked its coinbase and witness commitment (and, with a node configured, that its height is the node's next block). Accept it (DeclareMiningJob.Success with a new token, which a SetCustomMiningJob on this server's pool can redeem once) or reject it with an error code (DeclareMiningJob.Error), e.g. invalid-job or stale-chain-tip.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The declaration's request id", true),
        p("version", "number", "The block version it will mine", true),
        p("height", "number", "The height its coinbase commits to (BIP 34)", true),
        p("prev_hash", "string", "The tip it builds on, as the configured Bitcoin Core node reported it; absent without a node, when nothing checks the job against a chain", false),
        p("coinbase_outputs", "array", "Its coinbase outputs: value_sats and script_type, with op_return text", true),
        p("coinbase_value_sats", "number", "What its coinbase pays in total", true),
        p("pays_required_outputs", "boolean", "Whether the coinbase includes every output its token required", true),
        p("transactions", "number", "Transactions besides the coinbase", true),
        p("weight", "number", "The block's weight without the header", true),
        p("extranonce_size", "number", "Bytes of extranonce its coinbase leaves for mining", true),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_actions(job_declarator_actions())
});

pub static JD_SOLUTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_jd_solution",
        "The job declarator client pushed a solution (PushSolution) that Rust matched to an accepted job, rebuilt into a block and verified against its nbits. The block is logged in full. The protocol has no reply.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The declaration it solves", true),
        p("hash", "string", "The block hash, as RPC shows hashes", true),
        p("height", "number", "The height its coinbase commits to", false),
        p("prev_hash", "string", "The block it builds on", true),
        p("nbits", "string", "The compact target the hash meets", true),
        p("ntime", "number", "The header timestamp", true),
        p("nonce", "number", "The header nonce", true),
        p("version", "number", "The header version", true),
        p("block_size", "number", "The block's size in bytes", true),
        p("relay", "string", RELAY_DESCRIPTION, false),
        p("remote_addr", "string", "The client's address and port", true),
    ])
    .with_no_actions()
});

/// What a `relay` event field means, everywhere one appears.
const RELAY_DESCRIPTION: &str = "What the configured Bitcoin Core node said when Rust handed it the block: accepted, its reason (duplicate, inconclusive, high-hash, …), already-relayed or relay-failed; absent without a node";

pub static CUSTOM_JOB_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_custom_job",
        "A device that negotiated work selection asked to mine its own job (SetCustomMiningJob) on an extended channel, redeeming a token this server's job declarator issued when it accepted the job's declaration. Rust has spent the token and checked the custom job against that declaration: version, coinbase (version, prefix, sequence, outputs, locktime, the extranonce size), merkle path, and — when a node was consulted at declaration — prev hash and nbits. Accept it (SetCustomMiningJob.Success; its shares are then verified against it) or reject it with an error code (SetCustomMiningJob.Error).",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("channel_id", "number", "The extended channel it is for", true),
        p("request_id", "number", "The device's request id, which the answer echoes", true),
        p("user_identity", "string", "The channel's user", true),
        p("declaration_request_id", "number", "The request id of the DeclareMiningJob the token came from", true),
        p("height", "number", "The height its coinbase commits to (BIP 34)", false),
        p("prev_hash", "string", "The block it builds on, as RPC shows hashes", true),
        p("nbits", "string", "The compact target of its block, 8 hex digits", true),
        p("version", "number", "The block version", true),
        p("min_ntime", "number", "The earliest header timestamp it may use", true),
        p("transactions", "number", "Transactions besides the coinbase", true),
        p("coinbase_outputs", "array", "Its coinbase outputs: value_sats and script_type, with op_return text", true),
        p("coinbase_value_sats", "number", "What its coinbase pays in total", true),
        p("tip_checked", "boolean", "Whether prev_hash and nbits were checked against the tip a Bitcoin Core node reported at declaration (false without a node: only the network's nbits limit was checked)", true),
        p("remote_addr", "string", "The device's address and port", true),
    ])
    .with_actions(vec![accept(), reject()])
});

/// The outputs a `stratum_v2_allocate_token` requires the declared coinbase to pay.
pub fn allocation_outputs(v: &Value) -> Result<Vec<btc::TxOut>> {
    Ok(vec![btc::TxOut {
        value: 0,
        script: btc::output_script(v)?,
    }])
}

pub static SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_setup_connection",
        "A mining device completed the Noise handshake and sent SetupConnection for the Mining Protocol. Accept or reject the connection.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("vendor", "string", "The device's vendor string", true),
        p("hardware_version", "string", "The hardware version the device reports", true),
        p("firmware", "string", "The firmware the device reports", true),
        p("device_id", "string", "The device id it reports (often empty)", true),
        p("endpoint_host", "string", "The host it says it connected to", true),
        p("endpoint_port", "number", "The port it says it connected to", true),
        p("flags", "array", "The features it requires: REQUIRES_STANDARD_JOBS, REQUIRES_VERSION_ROLLING, and REQUIRES_WORK_SELECTION (only a pool_and_job_declarator gets this far with it)", true),
        p("remote_addr", "string", "The device's address and port", true),
    ])
    .with_actions(all_actions())
});

pub static OPEN_CHANNEL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_open_channel",
        "A device asked to open a mining channel. Accept (optionally with stratum_v2_set_target for its difficulty and stratum_v2_new_job for its first job's coinbase message) or reject it.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("channel_kind", "string", "standard (header-only mining) or extended (the device rolls its own extranonce)", true),
        p("user_identity", "string", "Who is mining, usually account.worker", true),
        p("nominal_hash_rate", "number", "The hash rate it declared, in hashes per second", true),
        p("max_target_difficulty", "number", "The lowest difficulty the device accepts (from its max_target)", true),
        p("default_difficulty", "number", "The difficulty Rust assigns if you do not set one (from the hash rate and shares_per_minute)", true),
        p("extranonce_size", "number", "Bytes of extranonce the device rolls (extended channels)", false),
        p("remote_addr", "string", "The device's address and port", true),
    ])
    .with_actions(all_actions())
});

pub static SHARE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stratum_v2_share",
        "A device submitted a share that Rust rebuilt into its block header and verified meets the channel's target. On a custom job a share that also meets the job's nbits is a block: Rust has logged it and handed it to the configured node. Accept (credit) or reject it.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("user_identity", "string", "The channel's user", true),
        p("channel_id", "number", "The channel it was submitted on", true),
        p("channel_kind", "string", "standard or extended", true),
        p("job_id", "number", "The job it was mined on", true),
        p("sequence_number", "number", "The device's sequence number for it", true),
        p("hash", "string", "The block header hash, as RPC shows hashes", true),
        p("share_difficulty", "number", "The difficulty the hash actually meets", true),
        p("difficulty", "number", "The channel's difficulty, which the share meets", true),
        p("nonce", "number", "The header nonce", true),
        p("ntime", "number", "The header timestamp", true),
        p("version", "number", "The header version, with any rolled bits", true),
        p("custom_job", "boolean", "Whether the job is the device's own (SetCustomMiningJob) rather than the pool's", true),
        p("solves_block", "boolean", "Whether the share is a block: a custom job's hash that meets its nbits (the pool's own jobs build on no real chain and never are)", true),
        p("relay", "string", RELAY_DESCRIPTION, false),
        p("remote_addr", "string", "The device's address and port", true),
    ])
    .with_actions(all_actions())
});

fn code(v: &Value, key: &str) -> Result<()> {
    let c = v[key]
        .as_str()
        .with_context(|| format!("{key} is required"))?;
    ensure!(
        c.len() <= MAX_CODE_LEN && wire::valid_error_code(c),
        "{key} must be 1-{MAX_CODE_LEN} printable ASCII characters"
    );
    Ok(())
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT => {}
        REJECT => code(v, "error_code")?,
        CLOSE_CHANNEL => code(v, "reason_code")?,
        SET_TARGET => {
            let d = v["difficulty"]
                .as_f64()
                .context("difficulty must be a number")?;
            ensure!(
                d > 0.0 && d <= MAX_DIFFICULTY,
                "difficulty must be above 0 and at most {MAX_DIFFICULTY}"
            );
        }
        NEW_TEMPLATE => super::template_provider::check_action(v)?,
        ALLOCATE_TOKEN => {
            allocation_outputs(v)?;
        }
        NEW_JOB => {
            if let Some(m) = v.get("message").filter(|m| !m.is_null()) {
                let m = m.as_str().context("message must be text")?;
                ensure!(
                    m.len() <= wire::MAX_COINBASE_MESSAGE,
                    "message must be at most {} bytes",
                    wire::MAX_COINBASE_MESSAGE
                );
            }
            wire::parse_display_hash(v["prev_hash"].as_str())?;
        }
        other => bail!("Unknown Stratum V2 action {other:?}"),
    }
    Ok(())
}

impl Protocol for StratumV2Protocol {
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
        "Stratum V2 server (Noise NX): a mining pool (the model admits devices and channels, sets difficulty and work, and credits shares Rust has verified), a template provider (the model writes every block template; Rust makes it consistent and verifies solutions), or a job declarator (the model allocates tokens and accepts or refuses declared jobs)"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut all = all_actions();
        all.push(new_template());
        all.push(allocate_token());
        all
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SETUP_EVENT.clone(),
            OPEN_CHANNEL_EVENT.clone(),
            SHARE_EVENT.clone(),
            TP_SETUP_EVENT.clone(),
            TP_CONSTRAINTS_EVENT.clone(),
            TP_SOLUTION_EVENT.clone(),
            JD_SETUP_EVENT.clone(),
            JD_ALLOCATE_EVENT.clone(),
            JD_DECLARE_EVENT.clone(),
            JD_SOLUTION_EVENT.clone(),
            CUSTOM_JOB_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "role".into(),
                type_hint: "string".into(),
                description: "Which Stratum V2 protocol to serve: pool (the Mining Protocol, for mining devices), template_provider (the Template Distribution Protocol, for a pool or job declarator client taking block templates), job_declarator (the Job Declaration Protocol, for miners declaring their own jobs) or pool_and_job_declarator (both on this one port, the protocol each connection names choosing which serves it; the pool then takes work selection, SetCustomMiningJob, redeeming the tokens the job declarator issued)".into(),
                required: false,
                example: json!("template_provider"),
                default: Some(json!(DEFAULT_ROLE)),
            },
            ParameterDefinition {
                name: "network".into(),
                type_hint: "string".into(),
                description: "The chain a template provider or job declarator checks heights, nbits and the block subsidy against: mainnet, testnet4, signet or regtest".into(),
                required: false,
                example: json!("regtest"),
                default: Some(json!(DEFAULT_NETWORK)),
            },
            ParameterDefinition {
                name: "bitcoin_rpc_url".into(),
                type_hint: "string".into(),
                description: "A Bitcoin Core node's JSON-RPC endpoint (Bitcoin Core 29 or later), e.g. http://127.0.0.1:8332. With one, every block a role verifies is relayed to it with submitblock, and the job declarator refuses a declaration whose height is not the node's next block and records the node's tip, which the pool checks a custom job's prev hash and nbits against. Omitted: blocks are only logged".into(),
                required: false,
                example: json!("http://127.0.0.1:18443"),
                default: None,
            },
            ParameterDefinition {
                name: "bitcoin_rpc_user".into(),
                type_hint: "string".into(),
                description: "The RPC user for bitcoin_rpc_url (rpcuser or an rpcauth user)".into(),
                required: false,
                example: json!("netget"),
                default: None,
            },
            ParameterDefinition {
                name: "bitcoin_rpc_password".into(),
                type_hint: "string".into(),
                description: "The RPC password for bitcoin_rpc_user; never logged".into(),
                required: false,
                example: json!("change-me"),
                default: None,
            },
            ParameterDefinition {
                name: "authority_secret_key".into(),
                type_hint: "string".into(),
                description: "The pool authority's secret key, base58check-encoded as SRI's configuration writes it; it signs the server's certificate. Omitted: a fresh authority is generated and its public key logged for miners to pin".into(),
                required: false,
                example: json!("mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"),
                default: None,
            },
            ParameterDefinition {
                name: "cert_validity_secs".into(),
                type_hint: "number".into(),
                description: "How long each certificate the pool issues is valid, in seconds (60..=31536000)".into(),
                required: false,
                example: json!(3600),
                default: Some(json!(super::DEFAULT_CERT_VALIDITY_SECS)),
            },
            ParameterDefinition {
                name: "shares_per_minute".into(),
                type_hint: "number".into(),
                description: "Shares a channel should find per minute at its declared hash rate; sets the default difficulty (0.01..=600)".into(),
                required: false,
                example: json!(10),
                default: Some(json!(super::DEFAULT_SHARES_PER_MINUTE)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds a device may stay silent before it is disconnected (1..=86400)".into(),
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
            .implementation("Hand-rolled from sv2-spec: Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256 with an authority-signed certificate (libsecp256k1 for the curve and BIP 340 signatures, chacha20poly1305 for the AEAD), encrypted framing, and three roles chosen by `role`. pool: the Mining Protocol (SetupConnection, Open{Standard,Extended}MiningChannel, NewMiningJob, NewExtendedMiningJob, SetNewPrevHash, SetTarget, UpdateChannel, CloseChannel, SubmitShares{Standard,Extended}); jobs are built in Rust and every share is rebuilt into its header and compared with the channel's target before anyone is asked. template_provider: the Template Distribution Protocol (CoinbaseOutputConstraints, NewTemplate, SetNewPrevHash, RequestTransactionData, SubmitSolution); Rust serialises the model's transactions and computes the merkle path, witness commitment and BIP 34 height push, and rebuilds every solution into its block. job_declarator: the Job Declaration Protocol (AllocateMiningJobToken, DeclareMiningJob, ProvideMissingTransactions, PushSolution); Rust keeps the token table and a wtxid-keyed mempool and checks every supplied transaction and commitment")
            .llm_control("pool: which devices may connect, which channels open and at what difficulty, which verified shares are credited, and each channel's work. template_provider: who may take templates and every template (tip, height, nbits, version, coinbase value, transactions). job_declarator: who may declare, token allocation and the output it requires, and whether each declared job is accepted, with the error code")
            .e2e_testing("tests/server/stratum_v2: SRI's mining_device (sv2-apps v0.8.0) mines the model's job on the pool role; SRI's pool_sv2 takes the template provider's templates over network TDP with mining_device mining on it, and Bitcoin Core 31.0 accepts the block NetGet assembles from the model's template and SRI's coinbase; SRI's jd_client declares its job to the job declarator, supplies the missing transaction and receives DeclareMiningJob.Success; raw Noise frames for every refusal Rust decides, every bound and both fail-closed paths")
            .notes("Experimental. pool: one independent device (SRI's mining_device), one short of Stable's two, and the extended-channel path is driven only by NetGet's own client; it is connected to no node, so a share proves hashing and nothing is submitted as a block. template_provider: SRI's pool and jd_client take its templates (one SRI implementation of template receiving) and Bitcoin Core accepts the resulting block; solved blocks are logged, not relayed (no node). job_declarator: SRI's jd_client declares to it, but no independent client has pushed a solution, since jd_client pushes only for jobs its pool acknowledged and SRI's pool v0.8.0 redeems tokens only from its own JDS. Inbound frames are bounded per role: 16 KiB (pool), 66 KiB (template provider), 4 MiB (job declarator, ProvideMissingTransactions.Success). Refused before the model: a handshake or frame that does not authenticate, a frame over its bound, an unknown core message, a malformed field, REQUIRES_WORK_SELECTION, shares that are stale, duplicate, out of time, with foreign version bits or above the target; template solutions above the target or not following the template; declarations with an unknown token, over 8192 transactions, a coinbase that does not parse, transactions that are not the declared ones, or a commitment that does not cover them.")
            .request_only("Every message answers a client's request, except the jobs, prev-hash and targets that follow an accepted channel (pool) and the templates and prev-hash that follow CoinbaseOutputConstraints or a solution (template provider)")
            .answers_on_failure()
            .max_inbound_bytes(super::job_declarator::MAX_INBOUND_PAYLOAD)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Stratum V2 mining pool on port 3333 that accepts any device and credits every share"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"stratum_v2","port":3333,
            "instruction":"Accept every device, open channels for users starting with netget at difficulty 0.01, credit every share"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nif t=='stratum_v2_open_channel': a=[{'type':'stratum_v2_accept'},{'type':'stratum_v2_set_target','difficulty':0.01}] if e['user_identity'].startswith('netget') else [{'type':'stratum_v2_reject','error_code':'unknown-user'}]\nelse: a=[{'type':'stratum_v2_accept'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for StratumV2Protocol {
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
