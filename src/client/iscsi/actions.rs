//! What the model does as an iSCSI initiator: discover targets, log in, and run SCSI block
//! commands — REPORT LUNS, INQUIRY, READ CAPACITY, READ and WRITE — reading what comes back.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::iscsi::actions::{p, valid_name};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DISCOVER: &str = "iscsi_discover";
pub const LOGIN: &str = "iscsi_login";
pub const REPORT_LUNS: &str = "iscsi_report_luns";
pub const INQUIRY: &str = "iscsi_inquiry";
pub const READ_CAPACITY: &str = "iscsi_read_capacity";
pub const READ: &str = "iscsi_read";
pub const WRITE: &str = "iscsi_write";
pub const TEST_UNIT_READY: &str = "iscsi_test_unit_ready";
pub const LOGOUT: &str = "iscsi_logout";

/// Bytes one read or write action moves, so a result fits in an event.
pub const MAX_TRANSFER: usize = 8192;

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

fn lun_param() -> Parameter {
    p(
        "lun",
        "number",
        "The logical unit number (from iscsi_report_luns); default 0",
        false,
    )
}

pub fn client_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            DISCOVER,
            "Ask the target portal which targets it offers (a discovery session with \
             SendTargets=All). The answer arrives as iscsi_targets.",
            vec![],
            json!({"type": DISCOVER}),
        ),
        action(
            LOGIN,
            "Log in to a target (a normal session), with CHAP when it is configured. The \
             answer arrives as iscsi_login_result.",
            vec![p(
                "target_name",
                "string",
                "The target's iSCSI name (iqn.…); default: the target_name startup parameter",
                false,
            )],
            json!({"type": LOGIN, "target_name": "iqn.2026-10.net.netget:disk0"}),
        ),
        action(
            REPORT_LUNS,
            "List the logged-in target's logical units (REPORT LUNS).",
            vec![],
            json!({"type": REPORT_LUNS}),
        ),
        action(
            INQUIRY,
            "Ask a LUN what it is (INQUIRY): standard data (vendor, product, revision, device \
             type), or a vital product data page.",
            vec![
                lun_param(),
                p(
                    "page",
                    "string",
                    "standard (default), supported_pages, serial or device_identification",
                    false,
                ),
            ],
            json!({"type": INQUIRY, "lun": 0, "page": "standard"}),
        ),
        action(
            READ_CAPACITY,
            "Ask a LUN its size (READ CAPACITY(10), then (16) when the disk is past 2 TiB).",
            vec![lun_param()],
            json!({"type": READ_CAPACITY, "lun": 0}),
        ),
        action(
            READ,
            "Read blocks from a LUN (at most 8 KiB). The data comes back as text when it is \
             text (encoding utf8, trailing zero bytes counted rather than shown) and as hex \
             otherwise; ask for hex to always get hex.",
            vec![
                lun_param(),
                p("lba", "number", "The first logical block to read", true),
                p("blocks", "number", "How many blocks (default 1)", false),
                p("encoding", "string", "utf8 (default: text when it is text) or hex", false),
            ],
            json!({"type": READ, "lun": 0, "lba": 0, "blocks": 1}),
        ),
        action(
            WRITE,
            "Write data to a LUN from a block (at most 8 KiB). The data is zero-padded to whole \
             blocks.",
            vec![
                lun_param(),
                p("lba", "number", "The first logical block to write", true),
                p("data", "string", "What to write", true),
                p(
                    "encoding",
                    "string",
                    "How data is written: utf8 (the text's bytes; default) or hex (pairs of hex \
                     digits, for binary)",
                    false,
                ),
            ],
            json!({"type": WRITE, "lun": 0, "lba": 8, "data": "hello from netget", "encoding": "utf8"}),
        ),
        action(
            TEST_UNIT_READY,
            "Ask whether a LUN is ready (TEST UNIT READY).",
            vec![lun_param()],
            json!({"type": TEST_UNIT_READY, "lun": 0}),
        ),
        action(
            LOGOUT,
            "Log out of the target (the client stays, and may log in again).",
            vec![],
            json!({"type": LOGOUT}),
        ),
        action(
            "disconnect",
            "Log out if logged in, and stop this client.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_connected",
        "The iSCSI initiator is ready. Discover targets with iscsi_discover, or log in to one \
         with iscsi_login.",
        json!({"type": DISCOVER}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The target portal's address", true),
        p("initiator_name", "string", "This initiator's iSCSI name", true),
        p(
            "target_name",
            "string",
            "The configured target name, if any",
            false,
        ),
        p("chap", "boolean", "Whether CHAP credentials are configured", true),
    ])
    .with_actions(client_actions())
});

pub static TARGETS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_targets",
        "The portal answered SendTargets: the targets it offers this initiator.",
        json!({"type": LOGIN, "target_name": "iqn.2026-10.net.netget:disk0"}),
    )
    .with_parameters(vec![
        p(
            "targets",
            "array",
            "[{name, addresses: [\"host:port,tag\"]}]",
            true,
        ),
        p(
            "error",
            "string",
            "Why discovery failed (refused login, transport error)",
            false,
        ),
    ])
    .with_actions(client_actions())
});

pub static LOGIN_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_login_result",
        "A login finished: logged in, or refused with the target's status.",
        json!({"type": REPORT_LUNS}),
    )
    .with_parameters(vec![
        p("target_name", "string", "The target", true),
        p("logged_in", "boolean", "Whether the session is open", true),
        p(
            "status",
            "string",
            "The login status class and detail, e.g. 0x0000 success, 0x0201 authentication \
             failure, 0x0203 not found",
            false,
        ),
        p("status_meaning", "string", "What the status means", false),
        p("alias", "string", "The target's alias, if it gave one", false),
        p(
            "negotiated",
            "object",
            "The operational parameters agreed: digests, data segment and burst lengths, \
             immediate data, initial R2T",
            false,
        ),
        p("error", "string", "Why the login could not run", false),
    ])
    .with_actions(client_actions())
});

pub static COMMAND_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_command_result",
        "A SCSI command finished. status is GOOD, or CHECK CONDITION with the sense condition \
         that says why.",
        json!({"type": READ, "lun": 0, "lba": 0, "blocks": 1}),
    )
    .with_parameters(vec![
        p(
            "operation",
            "string",
            "report_luns, inquiry, read_capacity, read, write or test_unit_ready",
            true,
        ),
        p("lun", "number", "The LUN", false),
        p("status", "string", "The SCSI status (GOOD, CHECK CONDITION, …)", false),
        p(
            "sense",
            "string",
            "The sense key and condition, e.g. ILLEGAL REQUEST: LOGICAL BLOCK ADDRESS OUT OF \
             RANGE",
            false,
        ),
        p("luns", "array", "report_luns: the LUN numbers", false),
        p(
            "inquiry",
            "object",
            "inquiry: vendor, product, revision, device_type; or pages / serial / designators",
            false,
        ),
        p(
            "capacity",
            "object",
            "read_capacity: blocks, block_size, size_bytes",
            false,
        ),
        p("data", "string", "read: the data, in the named encoding", false),
        p(
            "encoding",
            "string",
            "read: utf8 (data is the text) or hex (data is hex digits)",
            false,
        ),
        p(
            "trailing_zero_bytes",
            "number",
            "read, utf8: zero bytes after the text, not shown",
            false,
        ),
        p("bytes", "number", "read or write: bytes moved", false),
        p("error", "string", "Why the command could not run", false),
    ])
    .with_actions(client_actions())
});

pub static LOGGED_OUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "iscsi_logged_out",
        "The session ended: this client logged out, or the target closed it.",
        json!({"type": LOGIN, "target_name": "iqn.2026-10.net.netget:disk0"}),
    )
    .with_parameters(vec![
        p("target_name", "string", "The target", true),
        p("reason", "string", "What ended it", true),
    ])
    .with_actions(client_actions())
});

/// A LUN number from an action, default 0.
pub fn lun_of(v: &Value) -> Result<u16> {
    match &v["lun"] {
        Value::Null => Ok(0),
        n => {
            let n = n.as_u64().context("lun is a number")?;
            ensure!(n <= 16383, "lun is at most 16383");
            Ok(n as u16)
        }
    }
}

/// The bytes of a write action's data.
pub fn write_data(v: &Value) -> Result<Vec<u8>> {
    let data = v["data"].as_str().context("data is text")?;
    let bytes = match v["encoding"].as_str().unwrap_or("utf8") {
        "utf8" => data.as_bytes().to_vec(),
        "hex" => hex::decode(data.trim()).context("data is not hex")?,
        other => bail!("encoding is utf8 or hex, not {other:?}"),
    };
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_TRANSFER,
        "data is 1 to {MAX_TRANSFER} bytes"
    );
    Ok(bytes)
}

/// Check an action's fields.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DISCOVER | REPORT_LUNS | LOGOUT => {}
        LOGIN => match &v["target_name"] {
            Value::Null => {}
            Value::String(s) => ensure!(valid_name(s), "target_name is an iSCSI name (iqn.…)"),
            _ => bail!("target_name is text"),
        },
        INQUIRY => {
            lun_of(v)?;
            ensure!(
                matches!(
                    v["page"].as_str(),
                    None | Some("standard" | "supported_pages" | "serial" | "device_identification")
                ),
                "page is standard, supported_pages, serial or device_identification"
            );
        }
        READ_CAPACITY | TEST_UNIT_READY => {
            lun_of(v)?;
        }
        READ => {
            lun_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            match &v["blocks"] {
                Value::Null => {}
                b => ensure!(
                    b.as_u64().is_some_and(|b| (1..=MAX_TRANSFER as u64 / 512).contains(&b)),
                    "blocks is 1 to {}",
                    MAX_TRANSFER / 512
                ),
            }
            ensure!(
                matches!(v["encoding"].as_str(), None | Some("utf8" | "hex")),
                "encoding is utf8 or hex"
            );
        }
        WRITE => {
            lun_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            write_data(v)?;
        }
        other => bail!("Unknown iSCSI client action {other:?}"),
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
pub struct IscsiClientProtocol;
impl IscsiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for IscsiClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "iSCSI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>iSCSI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["iscsi", "iscsi initiator", "san", "lun", "iqn"]
    }
    fn description(&self) -> &'static str {
        "iSCSI initiator (RFC 7143): discover targets, log in with CHAP, and read, write and \
         query a target's LUNs with SCSI block commands"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        client_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            TARGETS_EVENT.clone(),
            LOGIN_RESULT_EVENT.clone(),
            COMMAND_RESULT_EVENT.clone(),
            LOGGED_OUT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "initiator_name".into(),
                type_hint: "string".into(),
                description: "This initiator's iSCSI name".into(),
                required: false,
                example: json!(super::DEFAULT_INITIATOR_NAME),
                default: Some(json!(super::DEFAULT_INITIATOR_NAME)),
            },
            string_param(
                "target_name",
                "The target iscsi_login logs in to when the action names none",
                json!("iqn.2026-10.net.netget:disk0"),
            ),
            string_param(
                "chap_name",
                "The CHAP name to authenticate with (needs chap_secret)",
                json!("alice"),
            ),
            string_param(
                "chap_secret",
                "The CHAP secret. Used by NetGet; the model never sees it",
                json!("wonderland12"),
            ),
            string_param(
                "target_chap_name",
                "Ask the target to authenticate too (mutual CHAP), under this name; needs \
                 target_chap_secret",
                json!("netget-target"),
            ),
            string_param(
                "target_chap_secret",
                "The secret the target must prove for mutual CHAP",
                json!("targetsecret1"),
            ),
            ParameterDefinition {
                name: "digests".into(),
                type_hint: "string".into(),
                description: "Header and data digests to offer: either (None or CRC32C, the \
                              target chooses), crc32c or none"
                    .into(),
                required: false,
                example: json!("crc32c"),
                default: Some(json!(super::DEFAULT_DIGESTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written iSCSI initiator (src/client/iscsi/initiator.rs) over the target's PDU, text and CHAP modules: login through the security and operational stages, CHAP MD5 with optional mutual CHAP, discovery with SendTargets and text continuation, CRC32C digests when negotiated, SCSI commands with Data-In checked for DataSN and offset order, immediate, unsolicited and R2T-solicited Data-Out within the target's MaxRecvDataSegmentLength, NOP-In pings answered, logout. CDBs and answers through src/server/scsi_common.rs")
            .llm_control("When to discover, which target to log in to, and which SCSI commands to run on which LUNs, with what data")
            .e2e_testing("tests/client/iscsi: NetGet's own target for the login, CHAP, discovery and command shapes and the fail-closed paths; gotgt (an independent Go target) on macOS and Linux, and tgtd (Linux SCSI target framework, as root in CI) in real_server_test.rs, each read back from the backing file the target serves")
            .notes("Experimental: two independent targets (gotgt and tgtd), and the tgtd half runs only as root in the pair job, which had not run in CI when this landed. Error recovery level 0, one connection per session. A read or write moves at most 8 KiB; read data is shown as text only when it is text, hex otherwise. A handler chain stops after 16 follow-ups (a whole discover, log in, inspect, read, write, read back and log out session is nine). CHAP secrets come from the startup parameters and never reach the model.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the iSCSI portal at 10.0.0.5:3260, discover its targets, log in to the first and read block 0 of LUN 0"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "iscsi", "remote_addr": "127.0.0.1:3260",
            "startup_params": {"target_name": "iqn.2026-10.net.netget:disk0"},
            "instruction": "Log in, list the LUNs, read LUN 0's capacity and its first block, and report them"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "iscsi_connected", "handler": {"type": "static", "actions": [{"type": LOGIN}]}},
            {"event_pattern": "iscsi_login_result", "handler": {"type": "static", "actions": [{"type": READ, "lun": 0, "lba": 0, "blocks": 1}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']\na=[{'type':'iscsi_login'}] if t=='iscsi_connected' else [{'type':'iscsi_read','lun':0,'lba':0}] if t=='iscsi_login_result' and i['event']['logged_in'] else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for IscsiClientProtocol {
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
