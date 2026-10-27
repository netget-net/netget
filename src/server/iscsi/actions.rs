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
pub const ALLOW_TASK_MANAGEMENT: &str = "iscsi_allow_reset";
pub const REFUSE_TASK_MANAGEMENT: &str = "iscsi_refuse_reset";

/// The task management response a refusal names (RFC 7143 §11.6.1); anything else is
/// "function rejected".
pub fn refusal_code(response: &str) -> u8 {
    use super::pdu::tmf;
    match response {
        "not_supported" => tmf::NOT_SUPPORTED,
        "unauthorized" => tmf::AUTHORIZATION_FAILED,
        _ => tmf::REJECTED,
    }
}

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
        vec![p("reason", "string", "not_found or unauthorized", true)],
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

pub fn allow_reset_action() -> ActionDefinition {
    action(
        ALLOW_TASK_MANAGEMENT,
        "Let the reset go ahead. NetGet ends the tasks it covers in every session logged in to \
         the target and reports the reset to each initiator as a unit attention on its next \
         command; a cold reset also ends every session of the target.",
        vec![],
        json!({"type": ALLOW_TASK_MANAGEMENT}),
    )
}

pub fn refuse_reset_action() -> ActionDefinition {
    action(
        REFUSE_TASK_MANAGEMENT,
        "Refuse the reset; nothing is reset. response names the answer the initiator gets: \
         rejected (function rejected, 255), not_supported (5) or unauthorized (function \
         authorization failed, 6).",
        vec![p(
            "response",
            "string",
            "rejected, not_supported or unauthorized",
            true,
        )],
        json!({"type": REFUSE_TASK_MANAGEMENT, "response": "unauthorized"}),
    )
}

pub static TASK_MANAGEMENT_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "iscsi_task_management",
        "An initiator asks for a reset: logical_unit_reset (one LUN), target_warm_reset (every \
         LUN of the target) or target_cold_reset (a power cycle: every session of the target \
         ends). Answer iscsi_allow_reset or iscsi_refuse_reset.",
        allow_reset_action().example,
    )
    .with_parameters(vec![
        p(
            "function",
            "string",
            "logical_unit_reset, target_warm_reset or target_cold_reset",
            true,
        ),
        p(
            "lun",
            "number",
            "The LUN a logical_unit_reset names; null for the target resets",
            false,
        ),
        p("initiator_name", "string", "The initiator asking", true),
        p("target_name", "string", "The target it is logged in to", true),
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
        p(
            "outstanding_tasks",
            "number",
            "Tasks the reset would end, across every session of the target",
            true,
        ),
        p(
            "sessions_affected",
            "number",
            "Sessions logged in to the target, the asking one included",
            true,
        ),
    ])
    .with_actions(vec![allow_reset_action(), refuse_reset_action()])
    .with_log_template(
        LogTemplate::new().with_info("iSCSI {function} from {initiator_name} on {target_name}"),
    )
    });

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
    ensure!(list.len() <= MAX_TARGETS, "at most {MAX_TARGETS} targets");
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
        ALLOW_TASK_MANAGEMENT => {}
        REFUSE_TASK_MANAGEMENT => ensure!(
            matches!(
                v["response"].as_str(),
                Some("rejected" | "not_supported" | "unauthorized")
            ),
            "response is rejected, not_supported or unauthorized"
        ),
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
            allow_reset_action(),
            refuse_reset_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            LOGIN_EVENT.clone(),
            DISCOVERY_EVENT.clone(),
            TASK_MANAGEMENT_EVENT.clone(),
        ]
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
            ParameterDefinition {
                name: "max_connections".into(),
                type_hint: "number".into(),
                description: "MaxConnections this target offers: how many TCP connections one \
                              session may have (1 to 8). An initiator that offers fewer gets \
                              fewer (the result is the minimum)"
                    .into(),
                required: false,
                example: json!(2),
                default: Some(json!(super::DEFAULT_MAX_CONNECTIONS_PER_SESSION)),
            },
            ParameterDefinition {
                name: "error_recovery_level".into(),
                type_hint: "number".into(),
                description: "The highest ErrorRecoveryLevel this target offers: 0 (session \
                              recovery only), 1 (digest error recovery: SNACK, recovery R2T) or \
                              2 (connection recovery and task reassignment). The result is the \
                              lower of this and the initiator's"
                    .into(),
                required: false,
                example: json!(1),
                default: Some(json!(super::DEFAULT_ERROR_RECOVERY_LEVEL)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(3260)
            .implementation("Hand-written iSCSI target (src/server/iscsi): PDU framing with CRC32C header and data digests and a cancel-safe PDU reader (pdu.rs), login through the security and operational stages with text-key negotiation (text.rs), CHAP MD5 with optional mutual CHAP checked against configured secrets (chap.rs), discovery sessions with SendTargets and multi-PDU text continuation; sessions of up to MaxConnections connections sharing one CmdSN window, task set, write overlay and unit attentions (session.rs), with commands run in CmdSN order across connections, session and connection reinstatement, and logout of the session, of a connection or for recovery (ffp.rs); SCSI Command/Response, Data-In with phase collapse and residuals, unsolicited, immediate and R2T-solicited Data-Out (scsi.rs); every task management function: ABORT TASK, ABORT TASK SET and CLEAR TASK SET (answered once the transfers they end have finished), CLEAR ACA (not supported: no ACA), LOGICAL UNIT RESET and TARGET WARM/COLD RESET (each the model's decision, leaving 29h/03h, 29h/00h or 29h/01h on every I_T nexus), TASK REASSIGN (tmf.rs); error recovery levels 1 and 2: recovery R2T after a lost Data-Out, Data/R2T, Status, DataACK and R-Data SNACK with bounded retransmission, connection recovery with Time2Wait/Time2Retain (recovery.rs); NOP-In/Out, Reject. SCSI (src/server/scsi_common.rs, shared with the USB mass-storage device): INQUIRY with VPD 0x00/0x80/0x83/0xB0/0xB1, READ CAPACITY(10)/(16), READ/WRITE 6/10/12/16, TEST UNIT READY, REQUEST SENSE (reporting a pending unit attention), MODE SENSE(6)/(10), REPORT LUNS, SYNCHRONIZE CACHE(10)/(16), START STOP UNIT, PREVENT ALLOW MEDIUM REMOVAL, fixed-format sense")
            .llm_control("Which targets discovery reveals, whether each login is admitted (initiator name, target name, address and authenticated CHAP user are in the event), every LUN (size, block size, content, failing regions, identity and whether writes are accepted), and whether each LOGICAL UNIT RESET, TARGET WARM RESET and TARGET COLD RESET may go ahead (iscsi_task_management, with how many tasks and sessions it would affect)")
            .e2e_testing("tests/server/iscsi: raw-socket sessions for login, CHAP, negotiation, digests, every bound, sequence numbers and the fail-closed paths (e2e_test.rs), and for task management, unit attentions, two-connection sessions, CmdSN order across connections, reinstatement, recovery R2T, every SNACK type and TASK REASSIGN (recovery_test.rs), with the pcap oracle (tshark's iscsi and scsi dissectors); libiscsi 1.20's iscsi-ls, iscsi-inq, iscsi-readcapacity16, iscsi-md5sum and iscsi-test-cu (a subset, and the iSCSITMF and MultipathIO.Reset suites) and the Linux kernel initiator (open-iscsi iscsiadm, dd from the block device, sg_reset for LUN and target resets) in real_client_test.rs, the kernel as root in CI")
            .notes("Experimental: libiscsi passes its discovery, login, inquiry, capacity and read/write tools, the iscsi-test-cu subset and its task management tests named in tests/server/iscsi/AGENTS.md; the open-iscsi kernel initiator runs only as root in the pair job. Error recovery levels 1 and 2 and sessions of several connections are driven by NetGet's own raw-PDU tests only: libiscsi and open-iscsi both hard-code ErrorRecoveryLevel=0 and MaxConnections=1 and send no SNACK, DataACK or TASK REASSIGN, so no independent initiator exercises them. No ACA, no persistent reservations, no protection information, no UNMAP/WRITE SAME/COMPARE AND WRITE, no asynchronous messages, no iSER. A login or reset the model fails or does not answer is refused (login status 0x0300 or 0x0301; task management response 255) and no LUN is ever exposed that the model did not describe; discovery that fails lists no targets. Writes are held in memory for the session only (64 MiB) and discarded with it, so two sessions of one target do not see each other's writes. Bounds: data segment ≤ the negotiated MaxRecvDataSegmentLength (8 KiB during login, 256 KiB after), AHS ≤ 1020 bytes, 128 text keys and 64 KiB of text per exchange, 32 outstanding commands, 32 MiB per command, bursts as negotiated, 256 LUNs of up to 64 TiB, login within 60 s, a PDU's rest within 60 s of its first byte, 256 connections, 256 sessions, 8 connections per session, 8 retransmissions per task, 256 completed tasks and 64 MiB of read data kept per session, 256 statuses kept per connection, failed connections' tasks kept at most 120 s.")
            .answers_on_failure()
            .request_only("Every PDU this target sends answers one the initiator sent: it sends no NOP-In pings and no asynchronous messages, and StatSN is the connection task's to assign")
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
