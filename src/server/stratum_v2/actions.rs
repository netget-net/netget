//! What the model decides as a Stratum V2 pool: which devices may connect, which channels open
//! and at what difficulty, which shares Rust has proven valid it credits, and the work each
//! channel gets. Rust owns the Noise session, every message's encoding, the jobs' coinbase and
//! header arithmetic, and every refusal that arithmetic decides.
use super::wire;
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
        "Refuse the connection (SetupConnection.Error), the channel (OpenMiningChannel.Error) or the share (SubmitShares.Error) being answered.",
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

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![accept(), reject(), set_target(), new_job(), close_channel()]
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
        p("flags", "array", "The features it requires: REQUIRES_STANDARD_JOBS, REQUIRES_VERSION_ROLLING", true),
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
        "A device submitted a share that Rust rebuilt into its block header and verified meets the channel's target. Accept (credit) or reject it.",
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
        "Stratum V2 mining pool (Noise NX, Mining Protocol): the model admits devices and channels, sets difficulty and work, and credits shares Rust has verified"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SETUP_EVENT.clone(),
            OPEN_CHANNEL_EVENT.clone(),
            SHARE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
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
            .implementation("Hand-rolled from sv2-spec: Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256 with an authority-signed certificate (libsecp256k1 for the curve and BIP 340 signatures, chacha20poly1305 for the AEAD), encrypted framing, and the Common and Mining Protocol messages: SetupConnection, Open{Standard,Extended}MiningChannel, NewMiningJob, NewExtendedMiningJob, SetNewPrevHash, SetTarget, UpdateChannel, CloseChannel, SubmitShares{Standard,Extended}. Jobs are built in Rust and every share is rebuilt into its header, double-SHA-256 hashed and compared with the channel's target before anyone is asked")
            .llm_control("Which devices may connect, which channels open and at what difficulty, which verified shares are credited, and the work and channel closures each channel gets")
            .e2e_testing("tests/server/stratum_v2: SRI's mining_device (sv2-apps v0.8.0, its own noise_sv2/codec_sv2) pins NetGet's authority key, opens a standard channel, mines the model's job and has its shares verified and credited; raw Noise frames for every refusal Rust decides, bounds and a failed handler")
            .notes("Experimental: one independent device (SRI's mining_device) completes a session against it, which is one short of the two Stable needs and of an independent second opinion on the extended-channel path, which only NetGet's own client drives. The pool is connected to no node: its work is its own, so a share proves hashing and nothing is ever submitted as a block. Refused before the model: a handshake or frame that does not authenticate, a frame over 16 KiB, an unknown core message, a malformed field, REQUIRES_WORK_SELECTION, and shares that are stale, duplicate, out of time, with foreign version bits or above the target.")
            .request_only("Every message answers a device's request, except the jobs, prev-hash and targets that follow an accepted channel")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_INBOUND_PAYLOAD)
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
