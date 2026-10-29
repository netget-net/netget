//! What the model does as an NVMe/TCP host: read a discovery controller's log, connect to a
//! subsystem, identify its controller and namespaces, read, write, flush and zero blocks, read
//! the health log, and disconnect.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::nvme_tcp::actions::p;
use crate::server::nvme_tcp::nvme::valid_nqn;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DISCOVER: &str = "nvme_tcp_discover";
pub const CONNECT: &str = "nvme_tcp_connect";
pub const IDENTIFY_CONTROLLER: &str = "nvme_tcp_identify_controller";
pub const IDENTIFY_NAMESPACE: &str = "nvme_tcp_identify_namespace";
pub const LIST_NAMESPACES: &str = "nvme_tcp_list_namespaces";
pub const READ: &str = "nvme_tcp_read";
pub const WRITE: &str = "nvme_tcp_write";
pub const WRITE_ZEROES: &str = "nvme_tcp_write_zeroes";
pub const FLUSH: &str = "nvme_tcp_flush";
pub const GET_LOG_PAGE: &str = "nvme_tcp_get_log_page";
pub const DISCONNECT: &str = "nvme_tcp_disconnect";
pub const COMPARE: &str = "nvme_tcp_compare";
pub const VERIFY: &str = "nvme_tcp_verify";
pub const COPY: &str = "nvme_tcp_copy";
pub const RESERVATION_REGISTER: &str = "nvme_tcp_reservation_register";
pub const RESERVATION_ACQUIRE: &str = "nvme_tcp_reservation_acquire";
pub const RESERVATION_RELEASE: &str = "nvme_tcp_reservation_release";
pub const RESERVATION_REPORT: &str = "nvme_tcp_reservation_report";

/// Bytes one read or write action moves, so a result fits in an event.
pub const MAX_TRANSFER: usize = 8192;
/// Blocks one Write Zeroes may cover (its NLB field is 16 bits).
pub const MAX_ZERO_BLOCKS: u64 = 65536;
/// Blocks one Verify or one Copy source range may cover (their NLB fields are 16 bits).
pub const MAX_RANGE_BLOCKS: u64 = 65536;
/// Source ranges one Copy may name.
pub const MAX_COPY_RANGES: usize = 128;
/// Bytes a Reservation Report asks for: the header and 63 registrants.
pub const REPORT_LEN: usize = 4096;

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

fn nsid_param() -> Parameter {
    p(
        "nsid",
        "number",
        "The namespace ID (from nvme_tcp_list_namespaces); default 1",
        false,
    )
}

pub fn client_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            DISCOVER,
            "Ask the target's discovery controller (nqn.2014-08.org.nvmexpress.discovery) which \
             subsystems it offers. The answer arrives as nvme_tcp_discovery_log.",
            vec![],
            json!({"type": DISCOVER}),
        ),
        action(
            CONNECT,
            "Connect to a subsystem: an admin queue and one I/O queue, the controller enabled \
             and identified, its active namespaces listed. The answer arrives as \
             nvme_tcp_connect_result.",
            vec![p(
                "subsystem_nqn",
                "string",
                "The subsystem's NQN (nqn.…); default: the subsystem_nqn startup parameter",
                false,
            )],
            json!({"type": CONNECT, "subsystem_nqn": "nqn.2026-10.net.netget:disk0"}),
        ),
        action(
            IDENTIFY_CONTROLLER,
            "Ask the connected controller what it is (Identify Controller): model, serial, \
             firmware, version, transfer and queue limits.",
            vec![],
            json!({"type": IDENTIFY_CONTROLLER}),
        ),
        action(
            IDENTIFY_NAMESPACE,
            "Ask a namespace its size, block size, write protection and identifiers (Identify \
             Namespace and its identification descriptors).",
            vec![nsid_param()],
            json!({"type": IDENTIFY_NAMESPACE, "nsid": 1}),
        ),
        action(
            LIST_NAMESPACES,
            "List the controller's active namespace IDs.",
            vec![],
            json!({"type": LIST_NAMESPACES}),
        ),
        action(
            READ,
            "Read blocks from a namespace (at most 8 KiB). The data comes back as text when it \
             is text (encoding utf8, trailing zero bytes counted rather than shown) and as hex \
             otherwise; ask for hex to always get hex.",
            vec![
                nsid_param(),
                p("lba", "number", "The first logical block to read", true),
                p("blocks", "number", "How many blocks (default 1)", false),
                p(
                    "encoding",
                    "string",
                    "utf8 (default: text when it is text) or hex",
                    false,
                ),
            ],
            json!({"type": READ, "nsid": 1, "lba": 0, "blocks": 1}),
        ),
        action(
            WRITE,
            "Write data to a namespace from a block (at most 8 KiB). The data is zero-padded \
             to whole blocks.",
            vec![
                nsid_param(),
                p("lba", "number", "The first logical block to write", true),
                p(
                    "data",
                    "string",
                    "The bytes to write: the text itself for utf8, pairs of hex digits for hex",
                    true,
                ),
                p(
                    "encoding",
                    "string",
                    "How data is written: utf8 (the text's bytes; default) or hex (pairs of hex \
                     digits, for binary)",
                    false,
                ),
            ],
            json!({"type": WRITE, "nsid": 1, "lba": 8, "data": "hello from netget", "encoding": "utf8"}),
        ),
        action(
            WRITE_ZEROES,
            "Set blocks of a namespace to zeroes (Write Zeroes), at most 65536 blocks.",
            vec![
                nsid_param(),
                p("lba", "number", "The first logical block", true),
                p("blocks", "number", "How many blocks (default 1)", false),
            ],
            json!({"type": WRITE_ZEROES, "nsid": 1, "lba": 8, "blocks": 1}),
        ),
        action(
            FLUSH,
            "Ask the controller to make a namespace's writes durable (Flush).",
            vec![nsid_param()],
            json!({"type": FLUSH, "nsid": 1}),
        ),
        action(
            GET_LOG_PAGE,
            "Read a log page from the controller: smart (health: temperature, spare, data \
             read and written, error counts), error, firmware_slot or changed_namespaces.",
            vec![p(
                "page",
                "string",
                "smart (default), error, firmware_slot or changed_namespaces",
                false,
            )],
            json!({"type": GET_LOG_PAGE, "page": "smart"}),
        ),
        action(
            COMPARE,
            "Compare data with blocks of a namespace (at most 8 KiB, zero-padded to whole \
             blocks): status SUCCESS when they match, COMPARE FAILURE when they differ.",
            vec![
                nsid_param(),
                p("lba", "number", "The first logical block to compare", true),
                p(
                    "data",
                    "string",
                    "The bytes expected there: the text itself for utf8, pairs of hex digits \
                     for hex",
                    true,
                ),
                p("encoding", "string", "utf8 (default) or hex", false),
            ],
            json!({"type": COMPARE, "nsid": 1, "lba": 0, "data": "hello from netget"}),
        ),
        action(
            VERIFY,
            "Ask the controller to check that blocks are readable (Verify); no data moves.",
            vec![
                nsid_param(),
                p("lba", "number", "The first logical block", true),
                p(
                    "blocks",
                    "number",
                    "How many blocks (default 1, at most 65536)",
                    false,
                ),
            ],
            json!({"type": VERIFY, "nsid": 1, "lba": 0, "blocks": 8}),
        ),
        action(
            COPY,
            "Copy blocks within a namespace (Copy, descriptor format 0): the source ranges, in \
             order, to consecutive blocks from destination_lba.",
            vec![
                nsid_param(),
                p("destination_lba", "number", "The first block written", true),
                p(
                    "ranges",
                    "array",
                    "[{lba, blocks}]: 1 to 128 source ranges of 1 to 65536 blocks",
                    true,
                ),
            ],
            json!({"type": COPY, "nsid": 1, "destination_lba": 200, "ranges": [{"lba": 0, "blocks": 1}, {"lba": 8, "blocks": 1}]}),
        ),
        action(
            RESERVATION_REGISTER,
            "Register this host's reservation key with a namespace, unregister it, or replace \
             it (Reservation Register).",
            vec![
                nsid_param(),
                p(
                    "action",
                    "string",
                    "register (default), unregister or replace",
                    false,
                ),
                p(
                    "current_key",
                    "number",
                    "unregister and replace: the key registered now",
                    false,
                ),
                p(
                    "new_key",
                    "number",
                    "register and replace: the key to register",
                    false,
                ),
                p(
                    "ignore_existing_key",
                    "boolean",
                    "Do not check current_key (IEKEY)",
                    false,
                ),
            ],
            json!({"type": RESERVATION_REGISTER, "nsid": 1, "action": "register", "new_key": 161}),
        ),
        action(
            RESERVATION_ACQUIRE,
            "Take a reservation on a namespace, or preempt another host's (Reservation \
             Acquire).",
            vec![
                nsid_param(),
                p(
                    "action",
                    "string",
                    "acquire (default), preempt or preempt_and_abort",
                    false,
                ),
                p(
                    "reservation_type",
                    "string",
                    "write_exclusive, exclusive_access, write_exclusive_registrants_only, \
                     exclusive_access_registrants_only, write_exclusive_all_registrants or \
                     exclusive_access_all_registrants",
                    true,
                ),
                p("current_key", "number", "This host's registered key", true),
                p(
                    "preempt_key",
                    "number",
                    "preempt: the key whose registrations (and reservation) are taken",
                    false,
                ),
            ],
            json!({"type": RESERVATION_ACQUIRE, "nsid": 1, "action": "acquire", "reservation_type": "write_exclusive", "current_key": 161}),
        ),
        action(
            RESERVATION_RELEASE,
            "Release this host's reservation, or clear the namespace's reservation and every \
             registration (Reservation Release).",
            vec![
                nsid_param(),
                p("action", "string", "release (default) or clear", false),
                p(
                    "reservation_type",
                    "string",
                    "release: the type of the reservation held",
                    false,
                ),
                p("current_key", "number", "This host's registered key", true),
            ],
            json!({"type": RESERVATION_RELEASE, "nsid": 1, "action": "release", "reservation_type": "write_exclusive", "current_key": 161}),
        ),
        action(
            RESERVATION_REPORT,
            "Read a namespace's reservation status (Reservation Report, extended): the \
             reservation type, the registered hosts, their keys and who holds it.",
            vec![nsid_param()],
            json!({"type": RESERVATION_REPORT, "nsid": 1}),
        ),
        action(
            DISCONNECT,
            "Shut the controller down (CC.SHN) and close its queues; the client stays and may \
             connect again.",
            vec![],
            json!({"type": DISCONNECT}),
        ),
        action(
            "disconnect",
            "Disconnect from the subsystem if connected, and stop this client.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_connected",
        "The NVMe/TCP host is ready. Read the discovery log with nvme_tcp_discover, or \
         connect to a subsystem with nvme_tcp_connect.",
        json!({"type": DISCOVER}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The target's address", true),
        p("host_nqn", "string", "This host's NQN", true),
        p(
            "subsystem_nqn",
            "string",
            "The configured subsystem NQN, if any",
            false,
        ),
    ])
    .with_actions(client_actions())
});

pub static DISCOVERY_LOG_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_discovery_log",
        "The discovery controller's log page: the subsystems it offers this host.",
        json!({"type": CONNECT, "subsystem_nqn": "nqn.2026-10.net.netget:disk0"}),
    )
    .with_parameters(vec![
        p(
            "entries",
            "array",
            "[{subsystem_nqn, transport, address_family, address, port, subsystem_type, \
             port_id, controller_id, admin_queue_size, treq, secure_channel (required, \
             not_required or not_specified), security (none, tls1.2 or tls1.3)}]",
            true,
        ),
        p(
            "generation",
            "number",
            "The log's generation counter",
            false,
        ),
        p(
            "controller",
            "object",
            "The discovery controller: model, serial, version",
            false,
        ),
        p(
            "error",
            "string",
            "Why discovery failed (refused Connect, transport error)",
            false,
        ),
    ])
    .with_actions(client_actions())
});

pub static CONNECT_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_connect_result",
        "A connect finished: connected with the controller and its namespaces, or refused with \
         the target's status.",
        json!({"type": READ, "nsid": 1, "lba": 0, "blocks": 1}),
    )
    .with_parameters(vec![
        p(
            "subsystem_nqn",
            "string",
            "The subsystem's NQN (nqn.…)",
            true,
        ),
        p(
            "connected",
            "boolean",
            "Whether the controller is ready",
            true,
        ),
        p(
            "status",
            "string",
            "The Connect status when refused, e.g. CONNECT INVALID HOST",
            false,
        ),
        p(
            "controller",
            "object",
            "cntlid, model, serial, firmware, version, mdts_bytes, max_commands, namespaces \
             (NN), io_queues",
            false,
        ),
        p("namespaces", "array", "The active namespace IDs", false),
        p(
            "authentication",
            "object",
            "When the target required DH-HMAC-CHAP: {protocol, hash, dh_group, bidirectional}",
            false,
        ),
        p("error", "string", "Why the connect could not run", false),
    ])
    .with_actions(client_actions())
});

pub static COMMAND_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_command_result",
        "An NVMe command finished. status is SUCCESS or the NVMe status that says why not.",
        json!({"type": READ, "nsid": 1, "lba": 0, "blocks": 1}),
    )
    .with_parameters(vec![
        p(
            "operation",
            "string",
            "identify_controller, identify_namespace, list_namespaces, read, write, \
             write_zeroes, flush, get_log_page, compare, verify, copy, reservation_register, \
             reservation_acquire, reservation_release or reservation_report",
            true,
        ),
        p("nsid", "number", "The namespace the command went to", false),
        p(
            "status",
            "string",
            "The NVMe status (SUCCESS, LBA OUT OF RANGE, NAMESPACE IS WRITE PROTECTED, …)",
            false,
        ),
        p(
            "controller",
            "object",
            "identify_controller: model, serial, firmware, version, limits",
            false,
        ),
        p(
            "namespace",
            "object",
            "identify_namespace: blocks, block_size, size_bytes, write_protected, nguid, \
             eui64, descriptors",
            false,
        ),
        p("namespaces", "array", "list_namespaces: the NSIDs", false),
        p(
            "log",
            "object",
            "get_log_page: the page's fields (smart: temperature_celsius, available_spare, \
             data_units_read, data_units_written, host_read_commands, host_write_commands, \
             media_errors, …)",
            false,
        ),
        p(
            "data",
            "string",
            "read: the data, in the named encoding",
            false,
        ),
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
        p(
            "matches",
            "boolean",
            "compare: whether the data matched",
            false,
        ),
        p(
            "reservation",
            "object",
            "reservation_report: {generation, type, registrants, entries: [{host_id, key, \
             holds_reservation, controller_id}]}",
            false,
        ),
        p("error", "string", "Why the command could not run", false),
    ])
    .with_actions(client_actions())
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_disconnected",
        "The controller is gone: this host shut it down, or the target ended a queue.",
        json!({"type": CONNECT, "subsystem_nqn": "nqn.2026-10.net.netget:disk0"}),
    )
    .with_parameters(vec![
        p(
            "subsystem_nqn",
            "string",
            "The subsystem's NQN (nqn.…)",
            true,
        ),
        p(
            "reason",
            "string",
            "Why: shut down by this host, or the error that ended it",
            true,
        ),
    ])
    .with_actions(client_actions())
});

/// A namespace ID from an action, default 1.
pub fn nsid_of(v: &Value) -> Result<u32> {
    match &v["nsid"] {
        Value::Null => Ok(1),
        n => {
            let n = n.as_u64().context("nsid is a number")?;
            ensure!((1..0xFFFF_FFFF).contains(&n), "nsid is 1 to 4294967294");
            Ok(n as u32)
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
        DISCOVER | IDENTIFY_CONTROLLER | LIST_NAMESPACES | DISCONNECT => {}
        CONNECT => match &v["subsystem_nqn"] {
            Value::Null => {}
            Value::String(s) => ensure!(valid_nqn(s), "subsystem_nqn is an NQN (nqn.…)"),
            _ => bail!("subsystem_nqn is text"),
        },
        IDENTIFY_NAMESPACE | FLUSH => {
            nsid_of(v)?;
        }
        READ => {
            nsid_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            match &v["blocks"] {
                Value::Null => {}
                b => ensure!(
                    b.as_u64()
                        .is_some_and(|b| (1..=MAX_TRANSFER as u64 / 512).contains(&b)),
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
            nsid_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            write_data(v)?;
        }
        WRITE_ZEROES => {
            nsid_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            match &v["blocks"] {
                Value::Null => {}
                b => ensure!(
                    b.as_u64()
                        .is_some_and(|b| (1..=MAX_ZERO_BLOCKS).contains(&b)),
                    "blocks is 1 to {MAX_ZERO_BLOCKS}"
                ),
            }
        }
        GET_LOG_PAGE => ensure!(
            matches!(
                v["page"].as_str(),
                None | Some("smart" | "error" | "firmware_slot" | "changed_namespaces")
            ),
            "page is smart, error, firmware_slot or changed_namespaces"
        ),
        COMPARE => {
            nsid_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            write_data(v)?;
        }
        VERIFY => {
            nsid_of(v)?;
            v["lba"].as_u64().context("lba is a number")?;
            match &v["blocks"] {
                Value::Null => {}
                b => ensure!(
                    b.as_u64()
                        .is_some_and(|b| (1..=MAX_RANGE_BLOCKS).contains(&b)),
                    "blocks is 1 to {MAX_RANGE_BLOCKS}"
                ),
            }
        }
        COPY => {
            nsid_of(v)?;
            v["destination_lba"]
                .as_u64()
                .context("destination_lba is a number")?;
            copy_ranges_of(v)?;
        }
        RESERVATION_REGISTER | RESERVATION_ACQUIRE | RESERVATION_RELEASE => {
            nsid_of(v)?;
            reservation_command(v["type"].as_str().unwrap_or_default(), v)?;
        }
        RESERVATION_REPORT => {
            nsid_of(v)?;
        }
        other => bail!("Unknown NVMe/TCP client action {other:?}"),
    }
    Ok(())
}

/// A Copy action's source ranges: (LBA, blocks).
pub fn copy_ranges_of(v: &Value) -> Result<Vec<(u64, u32)>> {
    let list = v["ranges"]
        .as_array()
        .context("ranges is an array of {lba, blocks}")?;
    ensure!(
        (1..=MAX_COPY_RANGES).contains(&list.len()),
        "ranges holds 1 to {MAX_COPY_RANGES} source ranges"
    );
    list.iter()
        .map(|r| {
            let lba = r["lba"].as_u64().context("each range has an lba")?;
            let blocks = match &r["blocks"] {
                Value::Null => 1,
                b => b.as_u64().context("blocks is a number")?,
            };
            ensure!(
                (1..=MAX_RANGE_BLOCKS).contains(&blocks),
                "each range is 1 to {MAX_RANGE_BLOCKS} blocks"
            );
            Ok((lba, blocks as u32))
        })
        .collect()
}

fn key(v: &Value, name: &str) -> Result<u64> {
    match &v[name] {
        Value::Null => Ok(0),
        k => k.as_u64().with_context(|| format!("{name} is a number")),
    }
}

/// A reservation action as its command: (opcode, CDW10, data).
pub fn reservation_command(kind: &str, v: &Value) -> Result<(u8, u32, Vec<u8>)> {
    use crate::server::nvme_tcp::nvme::io;
    use crate::server::nvme_tcp::resv::rtype;
    let action = v["action"].as_str();
    let rtype_of = |required: bool| -> Result<u32> {
        match v["reservation_type"].as_str() {
            Some(t) => rtype::parse(t)
                .map(u32::from)
                .with_context(|| format!("reservation_type is one of {}", rtype::NAMES.join(", "))),
            None if required => bail!("reservation_type is required"),
            None => Ok(0),
        }
    };
    let mut data = key(v, "current_key")?.to_le_bytes().to_vec();
    Ok(match kind {
        RESERVATION_REGISTER => {
            let rrega = match action {
                None | Some("register") => 0,
                Some("unregister") => 1,
                Some("replace") => 2,
                Some(a) => bail!("action is register, unregister or replace, not {a:?}"),
            };
            let iekey = v["ignore_existing_key"].as_bool().unwrap_or(false) as u32;
            data.extend(key(v, "new_key")?.to_le_bytes());
            (io::RESV_REGISTER, rrega | iekey << 3, data)
        }
        RESERVATION_ACQUIRE => {
            let racqa = match action {
                None | Some("acquire") => 0,
                Some("preempt") => 1,
                Some("preempt_and_abort") => 2,
                Some(a) => bail!("action is acquire, preempt or preempt_and_abort, not {a:?}"),
            };
            data.extend(key(v, "preempt_key")?.to_le_bytes());
            (io::RESV_ACQUIRE, racqa | rtype_of(true)? << 8, data)
        }
        _ => {
            let (rrela, t) = match action {
                None | Some("release") => (0, rtype_of(true)?),
                Some("clear") => (1, rtype_of(false)?),
                Some(a) => bail!("action is release or clear, not {a:?}"),
            };
            (io::RESV_RELEASE, rrela | t << 8, data)
        }
    })
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
pub struct NvmeTcpClientProtocol;
impl NvmeTcpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for NvmeTcpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NVMe-TCP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NVMe/TCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "nvme",
            "nvme-tcp",
            "nvme/tcp",
            "nvme over tcp",
            "nvme-of",
            "nvmf",
            "nqn",
        ]
    }
    fn description(&self) -> &'static str {
        "NVMe over TCP host: read a discovery log, connect to a subsystem (authenticating with \
         DH-HMAC-CHAP when asked), and identify, read, write, compare, verify, copy, flush, zero \
         and reserve its namespaces"
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
            DISCOVERY_LOG_EVENT.clone(),
            CONNECT_RESULT_EVENT.clone(),
            COMMAND_RESULT_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "host_nqn".into(),
                type_hint: "string".into(),
                description: "This host's NQN (HOSTNQN)".into(),
                required: false,
                example: json!(super::DEFAULT_HOST_NQN),
                default: Some(json!(super::DEFAULT_HOST_NQN)),
            },
            string_param(
                "host_id",
                "This host's identifier (HOSTID), a UUID; default: a random one for this client",
                json!("6c3a8f04-1f3e-4b0e-9f43-2d1c0a6b7e55"),
            ),
            string_param(
                "subsystem_nqn",
                "The subsystem nvme_tcp_connect connects to when the action names none",
                json!("nqn.2026-10.net.netget:disk0"),
            ),
            ParameterDefinition {
                name: "digests".into(),
                type_hint: "string".into(),
                description: "none (ask for no digests) or crc32c (ask for header and data \
                              digests, and refuse a target that does not enable both)"
                    .into(),
                required: false,
                example: json!("crc32c"),
                default: Some(json!(super::DEFAULT_DIGESTS)),
            },
            string_param(
                "dhchap_secret",
                "This host's DH-HMAC-CHAP secret (DHHC-1:<hh>:<base64>:, as nvme gen-dhchap-key \
                 prints it), answered when a target's Connect requires authentication",
                json!("DHHC-1:00:<base64 of a 32, 48 or 64 byte key and its CRC-32>:"),
            ),
            string_param(
                "dhchap_ctrl_secret",
                "The controller's DH-HMAC-CHAP secret: with it the host also makes the \
                 controller prove itself (bidirectional) and refuses one that cannot",
                json!("DHHC-1:00:<base64 of a 32, 48 or 64 byte key and its CRC-32>:"),
            ),
            string_param(
                "tls_key",
                "A configured TLS PSK (NVMeTLSkey-1:<hh>:<base64>:, as nvme gen-tls-key prints \
                 it): every queue opens a TLS 1.3 secure channel with it before its first PDU, \
                 offering a retained PSK identity for this host and the subsystem it connects \
                 to. Unix builds only",
                json!("NVMeTLSkey-1:01:<base64 of a 32 or 48 byte key and its CRC-32>:"),
            ),
            ParameterDefinition {
                name: "tls_identity_version".into(),
                type_hint: "number".into(),
                description: "The PSK identity offered with tls_key: 1 (NVMe TCP 1.1, ending with \
                              the PSK digest) or 0 (NVMe TCP 1.0c)"
                    .into(),
                required: false,
                example: json!(1),
                default: Some(json!(super::DEFAULT_TLS_IDENTITY_VERSION)),
            },
            ParameterDefinition {
                name: "keep_alive_ms".into(),
                type_hint: "number".into(),
                description: "The keep-alive timeout asked for in Connect (KATO, milliseconds); \
                              Keep Alive goes out every third of it while connected"
                    .into(),
                required: false,
                example: json!(30000),
                default: Some(json!(super::DEFAULT_KATO_MS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written NVMe/TCP host (src/client/nvme_tcp/host.rs) over the target's PDU, NVMe, DH-HMAC-CHAP and reservation modules: ICReq/ICResp with optional CRC32C digests, Connect of an admin queue and one I/O queue, DH-HMAC-CHAP after a Connect that sets AUTHREQ.ATR (every hash and group offered, one way, or both ways with a controller secret whose R2 is checked before Success2), CAP/VS/CC/CSTS bring-up and CC.SHN shutdown, Identify (controller, namespace with its Copy limits and reservation types, active namespace list, identification descriptors), Set Features (number of queues), Get Log Page (discovery with offsets and a generation check, SMART / health, error, firmware slot, changed namespaces), Keep Alive on a timer, Read, Write (in-capsule or R2T-solicited H2CData within MAXH2CDATA), Write Zeroes, Flush, Compare, Verify, Copy (format 0) and Reservation Register/Acquire/Release/Report (extended), C2HData checked for offset and length and SUCCESS honoured; TLS 1.3 secure channels with tls_key on every queue (the target's tls_psk.rs and tls.rs: OpenSSL's use-session callback, version 1 or 0 identities; Unix builds), and each discovery entry's TREQ and SECTYPE reported")
            .llm_control("When to read the discovery log, which subsystem to connect to, and which commands to run on which namespaces, with what data: reads, writes, compares, verifies, copies and reservation registrations, acquisitions, releases and reports")
            .e2e_testing("tests/client/nvme_tcp: NetGet's own target for the shapes and the fail-closed paths (DH-HMAC-CHAP and the new actions in auth_commands_test.rs); the Linux kernel target (nvmet-tcp configured through configfs, as root, including DH-HMAC-CHAP through the host's dhchap_key/dhchap_ctrl_key/dhchap_hash/dhchap_dhgroup and reservations on a resv_enable namespace) in real_server_test.rs and SPDK's nvmf_tgt (configured through rpc.py, an AIO bdev over a file, including DH-HMAC-CHAP through keyring_file_add_key and nvmf_subsystem_add_host, Compare, Copy and reservations) in spdk_target_test.rs, each read back from the file it serves, all in the nvme-tcp pair job")
            .notes("Experimental: two independent targets (the Linux kernel's nvmet-tcp and SPDK v26.09's nvmf_tgt) pass, DH-HMAC-CHAP both ways and reservations included, measured on a Linux 7.2 aarch64 kernel; in CI they run only in the nvme-tcp pair job, which had not run when this landed. Compare and Copy have only nvmf_tgt as an independent target (nvmet implements neither) and Verify none (both answer INVALID COMMAND OPCODE). One admin and one I/O queue, one command at a time, no TLS. A read, write or compare moves at most 8 KiB; a Copy names at most 128 ranges; read data is shown as text only when it is text, hex otherwise. A handler chain stops after 16 follow-ups. The discovery log is read up to 1024 entries; a reservation report up to 4 KiB (63 registrants). TLS has the Linux nvmet-tcp target through tlshd and SPDK's nvmf_tgt --secure-channel in the nvme-tcp pair job.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the NVMe/TCP target at 10.0.0.5:4420, read its discovery log, connect to the first subsystem and read block 0 of namespace 1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "nvme_tcp", "remote_addr": "127.0.0.1:4420",
            "startup_params": {"subsystem_nqn": "nqn.2026-10.net.netget:disk0"},
            "instruction": "Connect, identify namespace 1, read its first block, and report them"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "nvme_tcp_connected", "handler": {"type": "static", "actions": [{"type": CONNECT}]}},
            {"event_pattern": "nvme_tcp_connect_result", "handler": {"type": "static", "actions": [{"type": READ, "nsid": 1, "lba": 0, "blocks": 1}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']\na=[{'type':'nvme_tcp_connect'}] if t=='nvme_tcp_connected' else [{'type':'nvme_tcp_read','nsid':1,'lba':0}] if t=='nvme_tcp_connect_result' and i['event']['connected'] else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for NvmeTcpClientProtocol {
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
