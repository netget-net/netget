//! What the model decides as an iSCSI target: which targets discovery reveals, who may log in
//! to a target and what its LUNs contain. CHAP is checked in Rust before the model is asked,
//! and every SCSI command is served from the description at no model cost.
use super::lun::TargetDescription;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT_LOGIN: &str = "iscsi_accept_login";
pub const REJECT_LOGIN: &str = "iscsi_reject_login";
pub const SEND_TARGETS: &str = "iscsi_send_targets";

/// Targets one SendTargets answer may list.
pub const MAX_TARGETS: usize = 256;
/// iSCSI names are at most 223 bytes (RFC 7143 §4.2.7.1).
pub const MAX_NAME: usize = 223;

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn action(
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
        log_template: Some(LogTemplate::new().with_info(format!("-> {name}"))),
    }
}

pub fn accept_login_action() -> ActionDefinition {
    action(
        ACCEPT_LOGIN,
        "Admit the initiator to the target and describe its logical units. Each LUN is a disk: \
         its size, its content as extents (text, hex or a fill byte at a byte offset; \
         everything else reads as zeroes), optional regions whose I/O fails, and whether \
         writes are accepted. NetGet serves every SCSI command from this description. Writes \
         to a writable LUN are kept in memory for this session only and read back by it; a \
         LUN that is not writable refuses writes as write-protected.",
        vec![
            p(
                "luns",
                "array",
                "[{lun (default: its position), size (bytes, up to 64 TiB, rounded up to whole \
                 blocks), block_size (512, 1024, 2048 or 4096; default 512), extents \
                 ([{offset, text} | {offset, hex} | {offset, length, fill: 0-255}], byte \
                 offsets, up to 16 MiB of explicit bytes over all LUNs), errors ([{offset, \
                 length, error: medium_error|hardware_error}]), writable (default false), \
                 vendor (≤8), product (≤16), revision (≤4), serial}], 1 to 256 LUNs",
                true,
            ),
            p(
                "alias",
                "string",
                "A human-readable alias for the target (TargetAlias)",
                false,
            ),
        ],
        json!({"type": ACCEPT_LOGIN, "luns": [{"lun": 0, "size": 1048576, "block_size": 512,
            "extents": [{"offset": 0, "text": "hello from netget"}, {"offset": 4096, "length": 512, "fill": 255}],
            "errors": [{"offset": 524288, "length": 4096, "error": "medium_error"}],
            "writable": true, "product": "BOOT-DISK"}]}),
    )
}

pub fn reject_login_action() -> ActionDefinition {
    action(
        REJECT_LOGIN,
        "Refuse the login. not_found: there is no such target (status 0x0203); unauthorized: \
         this initiator may not use it (0x0202).",
        vec![p(
            "reason",
            "string",
            "not_found or unauthorized",
            true,
        )],
        json!({"type": REJECT_LOGIN, "reason": "unauthorized"}),
    )
}

pub fn send_targets_action() -> ActionDefinition {
    action(
        SEND_TARGETS,
        "Answer a discovery session's SendTargets: the targets this initiator may see. An \
         empty list reveals nothing. A target with no addresses is reached at the portal the \
         initiator is already connected to.",
        vec![p(
            "targets",
            "array",
            "[{name (an iqn. or eui. name, ≤223 bytes), addresses (optional, [\"host:port\"])}], \
             at most 256",
            true,
        )],
        json!({"type": SEND_TARGETS, "targets": [{"name": "iqn.2026-10.net.netget:disk0"}]}),
    )
}

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_login",
        "An initiator is logging in to a target (a normal session). NetGet has already checked \
         CHAP where it is configured. Decide whether the target exists and this initiator may \
         use it: answer iscsi_accept_login with its LUNs, or iscsi_reject_login.",
        accept_login_action().example,
    )
    .with_parameters(vec![
        p(
            "initiator_name",
            "string",
            "The initiator's iSCSI name (InitiatorName)",
            true,
        ),
        p(
            "target_name",
            "string",
            "The target it asks for (TargetName)",
            true,
        ),
        p(
            "initiator_address",
            "string",
            "The address the initiator connected from",
            true,
        ),
        p(
            "authenticated_user",
            "string",
            "The CHAP name it proved it holds the secret for; null when no authentication \
             was configured",
            false,
        ),
    ])
    .with_actions(vec![accept_login_action(), reject_login_action()])
    .with_log_template(
        LogTemplate::new().with_info("iSCSI login {initiator_name} -> {target_name}"),
    )
});

pub static DISCOVERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_discovery",
        "An initiator in a discovery session asks which targets exist (SendTargets=All). \
         Answer iscsi_send_targets with the targets it may see.",
        send_targets_action().example,
    )
    .with_parameters(vec![
        p(
            "initiator_name",
            "string",
            "The initiator's iSCSI name",
            true,
        ),
        p(
            "initiator_address",
            "string",
            "The address the initiator connected from",
            true,
        ),
        p(
            "authenticated_user",
            "string",
            "The CHAP name it authenticated as; null when no authentication was configured",
            false,
        ),
    ])
    .with_actions(vec![send_targets_action()])
    .with_log_template(LogTemplate::new().with_info("iSCSI discovery from {initiator_name}"))
});

/// The targets of an `iscsi_send_targets` action: (name, addresses).
pub fn targets_of(v: &Value) -> Result<Vec<(String, Vec<String>)>> {
    let Some(list) = v["targets"].as_array() else {
        bail!("targets is an array");
    };
    ensure!(
        list.len() <= MAX_TARGETS,
        "at most {MAX_TARGETS} targets"
    );
    let mut out = Vec::new();
    for t in list {
        let name = t["name"].as_str().unwrap_or_default();
        ensure!(
            valid_name(name),
            "each target has an iSCSI name (iqn., eui. or naa.) of at most {MAX_NAME} bytes"
        );
        let addresses = match &t["addresses"] {
            Value::Null => vec![],
            Value::Array(a) => {
                ensure!(a.len() <= 16, "at most 16 addresses per target");
                a.iter()
                    .map(|x| {
                        let s = x.as_str().unwrap_or_default();
                        ensure!(
                            !s.is_empty()
                                && s.len() <= 255
                                && s.bytes().all(|b| b.is_ascii_graphic() && b != b','),
                            "an address is host:port"
                        );
                        Ok(s.to_string())
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            _ => bail!("addresses is an array of host:port"),
        };
        out.push((name.to_string(), addresses));
    }
    Ok(out)
}

/// Whether a string is a well-formed iSCSI name: iqn., eui. or naa. form, printable, no
/// spaces, at most 223 bytes.
pub fn valid_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name.len() <= MAX_NAME
        && (lower.starts_with("iqn.") || lower.starts_with("eui.") || lower.starts_with("naa."))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// Check an answer's shape.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT_LOGIN => {
            TargetDescription::from_action(v, "iqn.2026-10.net.netget:check")?;
        }
        REJECT_LOGIN => ensure!(
            matches!(v["reason"].as_str(), Some("not_found" | "unauthorized")),
            "reason is not_found or unauthorized"
        ),
        SEND_TARGETS => {
            targets_of(v)?;
        }
        other => bail!("Unknown iSCSI target action {other:?}"),
    }
    Ok(())
}

fn string_param(name: &str, description: &str, example: Value) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "string".into(),
        description: description.into(),
        required: false,
        example,
        default: None,
    }
}

#[derive(Default, Clone)]
pub struct IscsiProtocol;
impl IscsiProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for IscsiProtocol {
    fn protocol_name(&self) -> &'static str {
        "iSCSI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>iSCSI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["iscsi", "iscsi target", "san", "lun", "iqn"]
    }
    fn description(&self) -> &'static str {
        "iSCSI target (RFC 7143, TCP 3260): the model decides which targets discovery shows, \
         who may log in and what each LUN contains; NetGet runs login, CHAP, negotiation and \
         the SCSI block commands from that description"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_login_action(),
            reject_login_action(),
            send_targets_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOGIN_EVENT.clone(), DISCOVERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "chap_accounts".into(),
                type_hint: "array".into(),
                description: "CHAP accounts initiators must authenticate with, as \
                              [{\"name\": …, \"secret\": …}] (secrets of 12 to 255 bytes). With \
                              any, every session — discovery and normal — needs CHAP; with \
                              none, logins are unauthenticated. Checked by NetGet; the model \
                              never sees a secret."
                    .into(),
                required: false,
                example: json!([{"name": "alice", "secret": "wonderland12"}]),
                default: None,
            },
            string_param(
                "target_chap_name",
                "The name this target answers with when an initiator asks it to authenticate \
                 too (mutual CHAP). Needs target_chap_secret",
                json!("netget-target"),
            ),
            string_param(
                "target_chap_secret",
                "The secret this target proves to an initiator that asks for mutual CHAP \
                 (12 to 255 bytes)",
                json!("targetsecret1"),
            ),
            ParameterDefinition {
                name: "initial_r2t".into(),
                type_hint: "boolean".into(),
                description: "InitialR2T as this target declares it: true (the RFC default) makes \
                              every non-immediate write wait for an R2T; false lets an initiator \
                              that also says No send its first burst unsolicited"
                    .into(),
                required: false,
                example: json!(false),
                default: Some(json!(super::DEFAULT_INITIAL_R2T)),
            },
            ParameterDefinition {
                name: "digests".into(),
                type_hint: "string".into(),
                description: "Header and data digests this target accepts: either (CRC32C or \
                              None, whichever the initiator lists first), crc32c or none"
                    .into(),
                required: false,
                example: json!("either"),
                default: Some(json!(super::DEFAULT_DIGESTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(3260)
            .implementation("Hand-written iSCSI target (src/server/iscsi): PDU framing with CRC32C header and data digests (pdu.rs), login through the security and operational stages with text-key negotiation (text.rs), CHAP MD5 with optional mutual CHAP checked against configured secrets (chap.rs), discovery sessions with SendTargets and multi-PDU text continuation, CmdSN/StatSN/DataSN/R2TSN sequencing with a 32-command window, SCSI Command/Response, Data-In with phase collapse and residuals, unsolicited, immediate and R2T-solicited Data-Out, NOP-In/Out, Logout, task management (ABORT TASK, ABORT/CLEAR TASK SET, LUN RESET, TARGET WARM/COLD RESET), Reject. SCSI (src/server/scsi_common.rs, shared with the USB mass-storage device): INQUIRY with VPD 0x00/0x80/0x83, READ CAPACITY(10)/(16), READ/WRITE 6/10/12/16, TEST UNIT READY, REQUEST SENSE, MODE SENSE(6)/(10), REPORT LUNS, SYNCHRONIZE CACHE(10)/(16), START STOP UNIT, PREVENT ALLOW MEDIUM REMOVAL, fixed-format sense")
            .llm_control("Which targets discovery reveals, whether each login is admitted (initiator name, target name, address and authenticated CHAP user are in the event), and every LUN: size, block size, content, failing regions, identity and whether writes are accepted")
            .e2e_testing("tests/server/iscsi: raw-socket sessions for login, CHAP, negotiation, digests, every bound, sequence numbers and the fail-closed paths, with the pcap oracle (tshark's iscsi and scsi dissectors) in e2e_test.rs; libiscsi 1.20's iscsi-ls, iscsi-inq, iscsi-readcapacity16, iscsi-md5sum and iscsi-test-cu in libiscsi_test.rs; the Linux kernel initiator (open-iscsi iscsiadm, then dd from the block device) in open_iscsi_test.rs, as root in CI")
            .notes("Experimental: libiscsi passes its discovery, login, inquiry, capacity and read/write tools and the iscsi-test-cu subset named in tests/server/iscsi/AGENTS.md; the open-iscsi kernel initiator runs only as root in the pair job, which had not run in CI when this landed. Error recovery level 0, one connection per session, no reinstatement, no SNACK, no ACA, no persistent reservations, no protection information, no UNMAP/WRITE SAME/COMPARE AND WRITE. A login the model fails or does not answer is refused (status 0x0300, or 0x0301 when the backend is saturated) and no LUN is ever exposed that the model did not describe; discovery that fails lists no targets. Writes are held in memory for the session only (64 MiB) and discarded with it. Bounds: data segment ≤ the negotiated MaxRecvDataSegmentLength (8 KiB during login, 256 KiB after), AHS ≤ 1020 bytes, 128 text keys and 64 KiB of text per exchange, 32 outstanding commands, 32 MiB per command, bursts as negotiated, 256 LUNs of up to 64 TiB, login within 60 s, a PDU's rest within 60 s of its first byte, 256 connections.")
            .answers_on_failure()
            .max_inbound_bytes(super::text::OUR_MAX_RECV_DATA_SEGMENT as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "iSCSI target on port 3260 exporting iqn.2026-10.net.netget:disk0, a 1 MiB disk whose first sector says hello"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "iscsi", "port": 3260,
            "instruction": "Offer one target, iqn.2026-10.net.netget:disk0, to everyone: LUN 0 is 1 MiB and starts with the text hello; it is read-only."});
        let accept = json!({"type": ACCEPT_LOGIN, "luns": [{"lun": 0, "size": 1048576, "extents": [{"offset": 0, "text": "hello"}]}]});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "iscsi_login", "handler": {"type": "static", "actions": [accept]}},
            {"event_pattern": "iscsi_discovery", "handler": {"type": "static", "actions": [{"type": SEND_TARGETS, "targets": [{"name": "iqn.2026-10.net.netget:disk0"}]}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\ne=i['event']\nif i['event_type_id']=='iscsi_discovery':\n  a={'type':'iscsi_send_targets','targets':[{'name':'iqn.2026-10.net.netget:disk0'}]}\nelif e['target_name']=='iqn.2026-10.net.netget:disk0':\n  a={'type':'iscsi_accept_login','luns':[{'lun':0,'size':1048576,'extents':[{'offset':0,'text':'hello'}]}]}\nelse:\n  a={'type':'iscsi_reject_login','reason':'not_found'}\nprint(json.dumps({'actions':[a]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for IscsiProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
