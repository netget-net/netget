//! What the model decides as an NVMe/TCP target: which subsystems the discovery log lists,
//! whether a host may connect to a subsystem, and what that subsystem's namespaces contain. It
//! is asked once per association (the admin queue Connect) and once per discovery controller;
//! every I/O command is served from the description at no model cost.
use super::ns::SubsystemDescription;
use super::nvme;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT_CONNECT: &str = "nvme_tcp_accept_connect";
pub const REJECT_CONNECT: &str = "nvme_tcp_reject_connect";
pub const DISCOVERY_ENTRIES: &str = "nvme_tcp_discovery_entries";
pub const ALLOW_RESERVATION: &str = "nvme_tcp_allow_reservation";
pub const REFUSE_RESERVATION: &str = "nvme_tcp_refuse_reservation";

/// Entries one discovery log may list.
pub const MAX_DISCOVERY_ENTRIES: usize = 256;

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

pub fn accept_connect_action() -> ActionDefinition {
    action(
        ACCEPT_CONNECT,
        "Admit the host to the subsystem and describe its namespaces. Each namespace is a disk: \
         its size, its content as extents (text, hex or a fill byte at a byte offset; \
         everything else reads as zeroes), optional regions whose I/O fails, and whether \
         writes are accepted. NetGet serves every I/O command from this description. Writes \
         to a writable namespace are kept in memory for this connection (the association) \
         only and read back by it; a namespace that is not writable refuses writes as write \
         protected.",
        vec![
            p(
                "namespaces",
                "array",
                "[{nsid (default: its position from 1), size (bytes, up to 64 TiB, rounded up to \
                 whole blocks), block_size (512, 1024, 2048 or 4096; default 512), extents \
                 ([{offset, text} | {offset, hex} | {offset, length, fill: 0-255}], byte \
                 offsets, up to 16 MiB of explicit bytes over all namespaces), errors \
                 ([{offset, length, error: medium_error|hardware_error}]), writable (default \
                 false), nguid (32 hex digits), eui64 (16 hex digits), uuid}], 1 to 64 \
                 namespaces, NSIDs 1 to 1024",
                true,
            ),
            p(
                "model",
                "string",
                "The controller's model number (≤40 ASCII characters)",
                false,
            ),
            p(
                "serial",
                "string",
                "The controller's serial number (≤20 ASCII characters; default derived from the \
                 subsystem NQN)",
                false,
            ),
            p(
                "firmware",
                "string",
                "The firmware revision (≤8 ASCII characters)",
                false,
            ),
            p(
                "require_authentication",
                "boolean",
                "true: the host must prove it holds the configured DH-HMAC-CHAP secret before \
                 anything else (only when the event says authentication_available); default \
                 false",
                false,
            ),
        ],
        json!({"type": ACCEPT_CONNECT, "namespaces": [{"nsid": 1, "size": 1048576, "block_size": 512,
            "extents": [{"offset": 0, "text": "hello from netget"}, {"offset": 4096, "length": 512, "fill": 255}],
            "errors": [{"offset": 524288, "length": 4096, "error": "medium_error"}],
            "writable": true}], "model": "NetGet Boot Disk"}),
    )
}

pub fn reject_connect_action() -> ActionDefinition {
    action(
        REJECT_CONNECT,
        "Refuse the connection. not_found: there is no such subsystem (Connect Invalid \
         Parameters, naming the subsystem NQN); invalid_host: this host may not use it \
         (Connect Invalid Host).",
        vec![p("reason", "string", "not_found or invalid_host", true)],
        json!({"type": REJECT_CONNECT, "reason": "invalid_host"}),
    )
}

pub fn discovery_entries_action() -> ActionDefinition {
    action(
        DISCOVERY_ENTRIES,
        "Answer a discovery controller's log page: the subsystems this host may see. An empty \
         list reveals nothing. A subsystem with no address is reached at this server's own \
         address and NVMe/TCP port.",
        vec![p(
            "subsystems",
            "array",
            "[{nqn (an nqn. name, ≤223 bytes), address (optional, \"ip:port\")}], at most 256",
            true,
        )],
        json!({"type": DISCOVERY_ENTRIES, "subsystems": [{"nqn": "nqn.2026-10.net.netget:disk0"}]}),
    )
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_connect",
        "A host is connecting to a subsystem (an admin queue Connect). Decide whether the \
         subsystem exists and this host may use it: answer nvme_tcp_accept_connect with its \
         namespaces, or nvme_tcp_reject_connect.",
        accept_connect_action().example,
    )
    .with_parameters(vec![
        p(
            "host_nqn",
            "string",
            "The host's NVMe Qualified Name (HOSTNQN)",
            true,
        ),
        p(
            "host_id",
            "string",
            "The host identifier (HOSTID, a UUID)",
            true,
        ),
        p(
            "subsystem_nqn",
            "string",
            "The subsystem it asks for (SUBNQN)",
            true,
        ),
        p(
            "host_address",
            "string",
            "The address the host connected from",
            true,
        ),
        p(
            "keep_alive_ms",
            "number",
            "The keep-alive timeout the host asked for (KATO, milliseconds; 0 is none)",
            true,
        ),
        p(
            "authentication_available",
            "boolean",
            "Whether a DH-HMAC-CHAP secret is configured, so require_authentication can be \
             answered",
            true,
        ),
    ])
    .with_actions(vec![accept_connect_action(), reject_connect_action()])
    .with_log_template(
        LogTemplate::new().with_info("NVMe/TCP connect {host_nqn} -> {subsystem_nqn}"),
    )
});

pub static DISCOVERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_discovery",
        "A host connected to the discovery controller reads the discovery log page. Answer \
         nvme_tcp_discovery_entries with the subsystems it may see.",
        discovery_entries_action().example,
    )
    .with_parameters(vec![
        p("host_nqn", "string", "The host's NVMe Qualified Name", true),
        p("host_id", "string", "The host identifier (a UUID)", true),
        p(
            "host_address",
            "string",
            "The address the host connected from",
            true,
        ),
    ])
    .with_actions(vec![discovery_entries_action()])
    .with_log_template(LogTemplate::new().with_info("NVMe/TCP discovery from {host_nqn}"))
});

pub fn allow_reservation_action() -> ActionDefinition {
    action(
        ALLOW_RESERVATION,
        "Let the reservation change happen as the event's effect describes it.",
        vec![],
        json!({"type": ALLOW_RESERVATION}),
    )
}

pub fn refuse_reservation_action() -> ActionDefinition {
    action(
        REFUSE_RESERVATION,
        "Refuse the reservation change: the host gets RESERVATION CONFLICT and nothing changes.",
        vec![],
        json!({"type": REFUSE_RESERVATION}),
    )
}

pub static RESERVATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nvme_tcp_reservation",
        "A host asks to change a namespace's persistent reservations (Reservation Register, \
         Acquire or Release). NetGet has checked the request against the registrations and \
         worked out its effect; answer nvme_tcp_allow_reservation to apply it or \
         nvme_tcp_refuse_reservation to refuse it.",
        allow_reservation_action().example,
    )
    .with_parameters(vec![
        p(
            "operation",
            "string",
            "register, unregister, replace, acquire, preempt, preempt_and_abort, release or clear",
            true,
        ),
        p(
            "nsid",
            "number",
            "The namespace ID whose reservations would change",
            true,
        ),
        p(
            "type",
            "string",
            "acquire, preempt and release: the reservation type (write_exclusive, \
             exclusive_access, write_exclusive_registrants_only, \
             exclusive_access_registrants_only, write_exclusive_all_registrants, \
             exclusive_access_all_registrants)",
            false,
        ),
        p("host_nqn", "string", "The host asking", true),
        p("host_id", "string", "Its host identifier (a UUID)", true),
        p(
            "subsystem_nqn",
            "string",
            "The NQN of the subsystem the namespace belongs to",
            true,
        ),
        p("effect", "string", "What the change does if allowed", true),
        p(
            "host_registered",
            "boolean",
            "Whether the host is registered now",
            true,
        ),
        p(
            "registrants",
            "number",
            "How many hosts are registered now",
            true,
        ),
        p(
            "holder",
            "object",
            "The reservation now: {host_id, type}, or null when there is none",
            false,
        ),
    ])
    .with_actions(vec![
        allow_reservation_action(),
        refuse_reservation_action(),
    ])
    .with_log_template(
        LogTemplate::new().with_info("NVMe/TCP reservation {operation} on {nsid} by {host_nqn}"),
    )
});

/// The subsystems of an `nvme_tcp_discovery_entries` action: (NQN, address).
pub fn entries_of(v: &Value) -> Result<Vec<(String, Option<std::net::SocketAddr>)>> {
    let Some(list) = v["subsystems"].as_array() else {
        bail!("subsystems is an array");
    };
    ensure!(
        list.len() <= MAX_DISCOVERY_ENTRIES,
        "at most {MAX_DISCOVERY_ENTRIES} subsystems"
    );
    let mut out = Vec::new();
    for s in list {
        let nqn = s["nqn"].as_str().unwrap_or_default();
        ensure!(
            nvme::valid_nqn(nqn) && nqn != nvme::DISCOVERY_NQN,
            "each subsystem has an NQN (nqn.…) of at most 223 bytes, not the discovery NQN"
        );
        let address = match &s["address"] {
            Value::Null => None,
            Value::String(a) => Some(
                a.parse::<std::net::SocketAddr>()
                    .map_err(|_| anyhow::anyhow!("address is ip:port"))?,
            ),
            _ => bail!("address is ip:port text"),
        };
        out.push((nqn.to_string(), address));
    }
    Ok(out)
}

/// Check an answer's shape.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT_CONNECT => {
            SubsystemDescription::from_action(v, "nqn.2026-10.net.netget:check")?;
        }
        REJECT_CONNECT => ensure!(
            matches!(v["reason"].as_str(), Some("not_found" | "invalid_host")),
            "reason is not_found or invalid_host"
        ),
        DISCOVERY_ENTRIES => {
            entries_of(v)?;
        }
        ALLOW_RESERVATION | REFUSE_RESERVATION => {}
        other => bail!("Unknown NVMe/TCP target action {other:?}"),
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct NvmeTcpProtocol;
impl NvmeTcpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for NvmeTcpProtocol {
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
        "NVMe over TCP target (TCP 4420): the model decides which subsystems the discovery log \
         lists, which hosts may connect and whether they must authenticate (DH-HMAC-CHAP), \
         what each namespace contains, and each change to its reservations; NetGet runs the \
         PDUs, digests, Connect, authentication, properties, admin commands and \
         Read/Write/Flush/Write Zeroes/Compare/Verify/Copy from that description"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_connect_action(),
            reject_connect_action(),
            discovery_entries_action(),
            allow_reservation_action(),
            refuse_reservation_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            DISCOVERY_EVENT.clone(),
            RESERVATION_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "digests".into(),
                type_hint: "string".into(),
                description: "Header and data digests: either (enable the ones each host asks \
                              for in its ICReq), crc32c (refuse a host that does not ask for \
                              both) or none (enable neither)"
                    .into(),
                required: false,
                example: json!("either"),
                default: Some(json!(super::DEFAULT_DIGESTS)),
            },
            ParameterDefinition {
                name: "discovery_port".into(),
                type_hint: "number".into(),
                description: "Also listen on this port (8009 is the discovery service's \
                              well-known port), serving the same discovery and I/O controllers"
                    .into(),
                required: false,
                example: json!(8009),
                default: None,
            },
            ParameterDefinition {
                name: "dhchap_secret".into(),
                type_hint: "string".into(),
                description: "The DH-HMAC-CHAP host secret (DHHC-1:<hh>:<base64>:, as nvme \
                              gen-dhchap-key prints it) a host the model requires to \
                              authenticate must prove; without it no host can be required to"
                    .into(),
                required: false,
                example: json!("DHHC-1:00:<base64 of a 32, 48 or 64 byte key and its CRC-32>:"),
                default: None,
            },
            ParameterDefinition {
                name: "dhchap_ctrl_secret".into(),
                type_hint: "string".into(),
                description: "The DH-HMAC-CHAP controller secret this target proves itself \
                              with when a host asks for bidirectional authentication; without \
                              it such a host is refused"
                    .into(),
                required: false,
                example: json!("DHHC-1:00:<base64 of a 32, 48 or 64 byte key and its CRC-32>:"),
                default: None,
            },
            ParameterDefinition {
                name: "dhchap_hashes".into(),
                type_hint: "string".into(),
                description: "DH-HMAC-CHAP hash functions in preference order (sha256, sha384, \
                              sha512): the first the host offers is used"
                    .into(),
                required: false,
                example: json!("sha512,sha256"),
                default: Some(json!(super::DEFAULT_DHCHAP_HASHES)),
            },
            ParameterDefinition {
                name: "dhchap_dhgroups".into(),
                type_hint: "string".into(),
                description: "DH-HMAC-CHAP Diffie-Hellman groups in preference order (null, \
                              ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192): the \
                              first the host offers is used"
                    .into(),
                required: false,
                example: json!("ffdhe2048,null"),
                default: Some(json!(super::DEFAULT_DHCHAP_DHGROUPS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(4420)
            .implementation("Hand-written NVMe/TCP target (src/server/nvme_tcp): PDU framing with CRC32C header and data digests and the receiver's data alignment (pdu.rs), ICReq/ICResp, CapsuleCmd/CapsuleResp, C2HData with LAST_PDU and SUCCESS, R2T and H2CData, C2HTermReq with the specification's fatal error status; NVMe over Fabrics Connect (dynamic controllers, admin and I/O queues, SQSIZE and KATO, AUTHREQ.ATR), Property Get/Set (CAP, VS, CC, CSTS), Disconnect, Authentication Send/Receive carrying DH-HMAC-CHAP (auth.rs: negotiate, challenge, reply, success1/2, failure1/2; SHA-256/384/512; NULL and RFC 7919 ffdhe2048 to ffdhe8192; one way and both ways; DHHC-1 secrets); admin Identify (controller, namespace, active namespace list, namespace identification descriptors), Get Log Page (error, SMART / health, firmware slot, changed namespaces, discovery), Set/Get Features (number of queues, keep alive timer, async event configuration, volatile write cache), Keep Alive, Abort, Asynchronous Event Request (held); NVM Read, Write, Flush, Write Zeroes, Dataset Management, Compare, Verify, Copy (format 0) and Reservation Register/Acquire/Release/Report over a bounded per-namespace table (resv.rs); the discovery controller on nqn.2014-08.org.nvmexpress.discovery (nvme.rs, ns.rs)")
            .llm_control("Which subsystems the discovery log lists, whether each host may connect to each subsystem and whether it must first authenticate with DH-HMAC-CHAP (host NQN, host ID, address, keep-alive timeout and whether a secret is configured are in the event; the secrets never are), every namespace: size, block size, content, failing regions, identifiers and whether writes are accepted, and every change to a namespace's persistent reservations (register, unregister, replace, acquire, preempt, release, clear), after NetGet has checked it against the rules and worked out its effect")
            .e2e_testing("tests/server/nvme_tcp: a raw host written from the specification's offsets for ICReq, digests, Connect, properties, admin and I/O commands, every bound and the fail-closed paths, with the pcap oracle (tshark's nvme-tcp and nvme dissectors) in e2e_test.rs; DH-HMAC-CHAP against the raw host's own independent implementation (HMAC, CRC-32, ffdhe2048) in auth_test.rs; Compare, Verify, Copy and reservations with two raw hosts in commands_test.rs; the Linux kernel host (nvme-cli discover, connect, id-ctrl, id-ns, smart-log, O_DIRECT reads and a write of the block devices, disconnect) in real_client_test.rs and, authenticating with every hash and group one way and both ways and running nvme compare, verify, copy and resv-register/acquire/report/release, in kernel_auth_test.rs, as root; SPDK's userspace host (spdk_nvme_identify on the discovery and I/O controllers, spdk_dd reading the namespace through SPDK's bdev layer, spdk_nvme_perf mixed random read/write with 16 commands outstanding, and spdk_nvme_perf authenticating one way and both ways) in spdk_host_test.rs; all in the nvme-tcp pair job")
            .notes("Experimental: two independent hosts (the Linux kernel's nvme-tcp with nvme-cli, and SPDK v26.09) pass, DH-HMAC-CHAP included, measured on a Linux 7.2 aarch64 kernel; in CI they run only in the nvme-tcp pair job, which had not run when this landed, so the rating waits for that job. One association per admin queue (dynamic controllers), at most 8 I/O queues of 128 entries, one R2T at a time per command, no TLS (and so no secure channel concatenation), no reservation notifications or persistence through power loss, no ANA, no asynchronous events ever completed, no fused Compare and Write. A Connect the model refuses, fails or does not answer gets a Connect status and no controller; a host the model requires to authenticate gets AUTHENTICATION REQUIRED for everything but the exchange until its response checks out, and a model that requires it with no secret configured fails closed; a reservation change the model refuses or does not answer changes nothing; no namespace exists that the model did not describe; a discovery log the model does not answer lists nothing. Writes and copies are held in memory for the association only (64 MiB) and discarded with it; reservations live as long as some controller of the subsystem does. Bounds: ICReq within 30 s of connecting and the first Connect within 30 s of it, authentication within 30 s of the Connect and four negotiations per queue, a PDU's rest within 60 s of its first byte, 8 KiB of in-capsule data, MAXH2CDATA 128 KiB per H2CData PDU, MDTS 1 MiB per command, authentication messages of 4 KiB (8 KiB received), Copy of 128 ranges and 4 MiB, 64 registrants per namespace and 1024 reservation tables, 4 commands with an R2T open per queue, 64 controllers, 256 discovery log entries, 64 namespaces of up to 64 TiB, 256 connections.")
            .answers_on_failure()
            .request_only("Every PDU this target sends answers one the host sent: it completes no asynchronous event and sends nothing unasked")
            .max_inbound_bytes(super::MAX_H2C_DATA)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "NVMe/TCP target on port 4420 exporting nqn.2026-10.net.netget:disk0, a 1 MiB namespace whose first block says hello"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "nvme-tcp", "port": 4420,
            "instruction": "Offer one subsystem, nqn.2026-10.net.netget:disk0, to every host: namespace 1 is 1 MiB and starts with the text hello; it is read-only."});
        let accept = json!({"type": ACCEPT_CONNECT, "namespaces": [{"nsid": 1, "size": 1048576, "extents": [{"offset": 0, "text": "hello"}]}]});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "nvme_tcp_connect", "handler": {"type": "static", "actions": [accept]}},
            {"event_pattern": "nvme_tcp_discovery", "handler": {"type": "static", "actions": [{"type": DISCOVERY_ENTRIES, "subsystems": [{"nqn": "nqn.2026-10.net.netget:disk0"}]}]}},
            {"event_pattern": "nvme_tcp_reservation", "handler": {"type": "static", "actions": [{"type": ALLOW_RESERVATION}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\ne=i['event']\nif i['event_type_id']=='nvme_tcp_discovery':\n  a={'type':'nvme_tcp_discovery_entries','subsystems':[{'nqn':'nqn.2026-10.net.netget:disk0'}]}\nelif i['event_type_id']=='nvme_tcp_reservation':\n  a={'type':'nvme_tcp_allow_reservation'}\nelif e['subsystem_nqn']=='nqn.2026-10.net.netget:disk0':\n  a={'type':'nvme_tcp_accept_connect','namespaces':[{'nsid':1,'size':1048576,'extents':[{'offset':0,'text':'hello'}]}]}\nelse:\n  a={'type':'nvme_tcp_reject_connect','reason':'not_found'}\nprint(json.dumps({'actions':[a]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for NvmeTcpProtocol {
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
