//! What the model decides as a portmapper: which programs are registered where (it answers
//! every lookup and dump with mappings) and which registrations to accept. Rust owns XDR,
//! record marking, the RPC error replies, NULL and GETTIME, and picks from the model's
//! mappings the ones each procedure returns.
use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const MAPPINGS: &str = "sunrpc_mappings";
pub const ACCEPT: &str = "sunrpc_accept";
pub const REJECT: &str = "sunrpc_reject";

#[derive(Default, Clone)]
pub struct SunRpcProtocol;

impl SunRpcProtocol {
    pub fn new() -> Self {
        Self
    }
}

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
    info: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn mappings_action() -> ActionDefinition {
    action(
        MAPPINGS,
        "Answer a lookup or dump with the registered programs. Give every mapping you hold (or just the matching ones): NetGet picks what the procedure returns. An empty list means nothing is registered.",
        vec![p(
            "mappings",
            "array",
            "Each {program, version, protocol (tcp, udp, tcp6 or udp6), port, owner?}, e.g. NFS 100003 v3 on tcp port 2049",
            true,
        )],
        json!({"type": MAPPINGS, "mappings": [
            {"program": 100003, "version": 3, "protocol": "tcp", "port": 2049},
            {"program": 100005, "version": 3, "protocol": "udp", "port": 20048}
        ]}),
        "-> portmapper {mappings}",
    )
}

pub fn accept_action() -> ActionDefinition {
    action(
        ACCEPT,
        "Accept the registration or removal (the caller is told it succeeded).",
        vec![],
        json!({"type": ACCEPT}),
        "-> portmapper accept",
    )
}

pub fn reject_action() -> ActionDefinition {
    action(
        REJECT,
        "Refuse the registration or removal (the caller is told it failed).",
        vec![],
        json!({"type": REJECT}),
        "-> portmapper reject",
    )
}

fn common() -> Vec<Parameter> {
    vec![
        p(
            "transport",
            "string",
            "tcp or udp: how the call arrived",
            true,
        ),
        p(
            "rpc_version",
            "number",
            "The portmapper version asked: 2 (PMAP), 3 or 4 (RPCBIND)",
            true,
        ),
    ]
}

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common();
    params.extend([
        p(
            "procedure",
            "string",
            "dump, getport, getaddr, getversaddr or getaddrlist",
            true,
        ),
        p(
            "program",
            "number",
            "The program looked up (absent for dump)",
            false,
        ),
        p(
            "program_name",
            "string",
            "Its well-known name, when it has one (nfs, mountd, …)",
            false,
        ),
        p("program_version", "number", "The version looked up", false),
        p(
            "protocol",
            "string",
            "The transport looked up: tcp, udp, tcp6 or udp6",
            false,
        ),
    ]);
    EventType::new(
        "sunrpc_query",
        "A client asks which programs are registered (dump) or where one program is (getport/getaddr). Answer sunrpc_mappings.",
        mappings_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![mappings_action()])
});

pub static REGISTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common();
    params.extend([
        p(
            "operation",
            "string",
            "set (register) or unset (remove)",
            true,
        ),
        p(
            "program",
            "number",
            "The program being registered or removed",
            true,
        ),
        p(
            "program_name",
            "string",
            "Its well-known name, when it has one",
            false,
        ),
        p(
            "program_version",
            "number",
            "The version of the program being registered",
            true,
        ),
        p(
            "protocol",
            "string",
            "tcp, udp, tcp6 or udp6 (empty on an unset: every transport)",
            true,
        ),
        p("port", "number", "The port it listens on (set only)", false),
        p(
            "owner",
            "string",
            "The owner the caller claims (RPCBIND only)",
            false,
        ),
        p(
            "credentials",
            "object",
            "The call's credentials: {flavor: none} or AUTH_SYS {uid, gid, machine}",
            true,
        ),
    ]);
    EventType::new(
        "sunrpc_register",
        "A program registers itself (set) or is removed (unset). Accept or reject; remember what you accept, since you answer later lookups.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(params)
    .with_actions(vec![accept_action(), reject_action()])
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        MAPPINGS => {
            let list = v["mappings"]
                .as_array()
                .context("mappings must be an array")?;
            ensure!(
                list.len() <= wire::MAX_MAPPINGS,
                "at most {} mappings",
                wire::MAX_MAPPINGS
            );
            for m in list {
                wire::mapping_from_json(m)?;
            }
            Ok(())
        }
        ACCEPT | REJECT => Ok(()),
        other => bail!("Unknown portmapper action {other:?}"),
    }
}

impl Protocol for SunRpcProtocol {
    fn protocol_name(&self) -> &'static str {
        "SunRPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP|UDP>ONC-RPC>Portmapper"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "sunrpc",
            "onc rpc",
            "portmapper",
            "portmap",
            "rpcbind",
            "rpcinfo",
            "111",
        ]
    }
    fn description(&self) -> &'static str {
        "ONC RPC portmapper/rpcbind (PMAP v2, RPCBIND v3 and v4) on TCP and UDP: tells clients where RPC programs such as NFS and mountd listen"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![mappings_action(), accept_action(), reject_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![QUERY_EVENT.clone(), REGISTER_EVENT.clone()]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        Vec::new()
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(111))
            .well_known_port(111)
            .implementation("Hand-rolled ONC RPC (src/server/sunrpc/wire.rs): calls and replies with AUTH_NONE/AUTH_SYS, TCP record marking and UDP datagrams on the same port; PMAP v2 NULL/SET/UNSET/GETPORT/DUMP and RPCBIND v3/v4 NULL/SET/UNSET/GETADDR/DUMP/GETTIME/GETVERSADDR/GETADDRLIST; RPC_MISMATCH, PROG_UNAVAIL, PROG_MISMATCH, PROC_UNAVAIL and GARBAGE_ARGS answered in Rust")
            .llm_control("Every lookup and dump (the mappings it answers with) and every registration and removal (accept or reject)")
            .e2e_testing("tests/server/sunrpc: the stock libtirpc rpcinfo (-p, -s, -l, -T tcp|udp, -a) in a network namespace whose port 111 is DNATed to NetGet; raw XDR for the error replies and bounds")
            .notes("Only the portmapper program (100000) is served; calls to any other program are PROG_UNAVAIL. CALLIT/INDIRECT and the statistics procedures are PROC_UNAVAIL. NetGet stores no registrations: the model holds them and answers lookups. Records are capped at 256 KiB in 64 fragments. A model failure answers SYSTEM_ERR.")
            .answers_on_failure()
            .request_only("Every reply answers an RPC call")
            .max_inbound_bytes(wire::MAX_RECORD)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Portmapper on port 111 that says NFS v3 is on TCP 2049 and mountd v3 on UDP 20048"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"sunrpc","port":0,
            "instruction":"Say NFS 100003 v3 is on tcp 2049 and mountd 100005 v3 on udp 20048; accept every registration and include it afterwards"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"sunrpc_query","handler":{"type":"static","actions":[mappings_action().example]}},
            {"event_pattern":"sunrpc_register","handler":{"type":"static","actions":[{"type":REJECT}]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin)\nif i['event_type_id']=='sunrpc_register':\n  a=[{'type':'sunrpc_accept'}]\nelse:\n  a=[{'type':'sunrpc_mappings','mappings':[{'program':100003,'version':3,'protocol':'tcp','port':2049}]}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for SunRpcProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        let name = action["type"].as_str().unwrap_or_default().to_string();
        Ok(ActionResult::Custom { name, data: action })
    }
}
