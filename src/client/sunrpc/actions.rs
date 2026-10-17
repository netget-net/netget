//! What the model asks a portmapper/rpcbind: what is registered (dump), where one program is
//! (getport, getaddr), to register or remove a program (set, unset), and the time.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::sunrpc::{actions::p, wire};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SunRpcClientProtocol;
impl SunRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<crate::llm::actions::Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!(
            "-> portmapper {}",
            name.trim_start_matches("sunrpc_")
        ))),
    }
}

fn version_param(default: u32) -> crate::llm::actions::Parameter {
    p(
        "version",
        "number",
        &format!("Portmapper version to speak: 2 (PMAP), 3 or 4 (RPCBIND); default {default}"),
        false,
    )
}

fn program_params() -> Vec<crate::llm::actions::Parameter> {
    vec![
        p(
            "program",
            "number",
            "The RPC program number, e.g. 100003 for NFS",
            true,
        ),
        p(
            "program_version",
            "number",
            "The program's version, e.g. 3",
            true,
        ),
    ]
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut getport = program_params();
    getport.push(p("protocol", "string", "tcp (default) or udp", false));
    let mut getaddr = program_params();
    getaddr.push(p(
        "protocol",
        "string",
        "Network id: tcp (default), udp, tcp6 or udp6",
        false,
    ));
    getaddr.push(version_param(4));
    let mut set = program_params();
    set.extend([
        p(
            "protocol",
            "string",
            "tcp (default), udp, tcp6 or udp6 (version 2: tcp or udp)",
            false,
        ),
        p("port", "number", "The port the program listens on", true),
        version_param(2),
    ]);
    let mut unset = program_params();
    unset.extend([
        p(
            "protocol",
            "string",
            "tcp or udp (version 2, default tcp); version 3-4: empty for every transport",
            false,
        ),
        version_param(2),
    ]);
    vec![
        action(
            "sunrpc_null",
            "Ping the portmapper (procedure 0).",
            vec![version_param(2)],
            json!({"type": "sunrpc_null"}),
        ),
        action(
            "sunrpc_dump",
            "List every registered program.",
            vec![version_param(4)],
            json!({"type": "sunrpc_dump", "version": 4}),
        ),
        action(
            "sunrpc_getport",
            "Ask where a program listens (PMAP v2 GETPORT): a port, 0 if not registered.",
            getport,
            json!({"type": "sunrpc_getport", "program": 100003, "program_version": 3, "protocol": "tcp"}),
        ),
        action(
            "sunrpc_getaddr",
            "Ask a program's universal address (RPCBIND GETADDR): empty if not registered.",
            getaddr,
            json!({"type": "sunrpc_getaddr", "program": 100003, "program_version": 3, "protocol": "tcp"}),
        ),
        action(
            "sunrpc_set",
            "Register a program at a port.",
            set,
            json!({"type": "sunrpc_set", "program": 536870913, "program_version": 1, "protocol": "tcp", "port": 4242}),
        ),
        action(
            "sunrpc_unset",
            "Remove a program's registration.",
            unset,
            json!({"type": "sunrpc_unset", "program": 536870913, "program_version": 1, "protocol": "tcp"}),
        ),
        action(
            "sunrpc_gettime",
            "Ask the server's time (RPCBIND GETTIME).",
            vec![],
            json!({"type": "sunrpc_gettime"}),
        ),
        action(
            "disconnect",
            "Close the connection.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sunrpc_connected",
        "Connected to the portmapper over TCP.",
        json!({"type": "sunrpc_dump", "version": 4}),
    )
    .with_parameters(vec![p(
        "remote_addr",
        "string",
        "The portmapper's address and port",
        true,
    )])
    .with_actions(actions())
});

pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sunrpc_reply",
        "The portmapper answered a call.",
        json!({"type": "sunrpc_getport", "program": 100003, "program_version": 3}),
    )
    .with_parameters(vec![
        p("operation", "string", "The action that was performed", true),
        p("ok", "boolean", "Whether the call was accepted and succeeded", true),
        p("result", "any", "dump: the mappings; getport: the port; getaddr: the address; set/unset: true or false; gettime: unix seconds", true),
        p("error", "string", "Why the call failed, e.g. PROG_UNAVAIL or PROC_UNAVAIL", false),
    ])
    .with_actions(actions())
});

fn version(v: &Value, default: u32) -> Result<u32> {
    let n = v["version"].as_u64().unwrap_or(u64::from(default));
    ensure!((2..=4).contains(&n), "version must be 2, 3 or 4");
    Ok(n as u32)
}

fn u32_of(v: &Value, k: &str) -> Result<u32> {
    let n = v[k]
        .as_u64()
        .with_context(|| format!("{k} must be a number"))?;
    u32::try_from(n).with_context(|| format!("{k} is a 32-bit number"))
}

/// The call one action makes: (portmapper version, procedure, XDR arguments).
pub fn call(v: &Value) -> Result<(u32, u32, Vec<u8>)> {
    let protocol = v["protocol"].as_str().unwrap_or("tcp");
    let mut w = wire::Writer::default();
    Ok(match v["type"].as_str().unwrap_or_default() {
        "sunrpc_null" => (version(v, 2)?, 0, Vec::new()),
        "sunrpc_dump" => (version(v, 4)?, 4, Vec::new()),
        "sunrpc_gettime" => (4, 6, Vec::new()),
        "sunrpc_getport" => {
            let prot = wire::protocol_of(protocol)
                .filter(|_| !protocol.ends_with('6'))
                .context("getport protocol must be tcp or udp")?;
            w.u32(u32_of(v, "program")?)
                .u32(u32_of(v, "program_version")?)
                .u32(prot)
                .u32(0);
            (2, 3, w.0)
        }
        "sunrpc_getaddr" => {
            let ver = version(v, 4)?;
            ensure!(ver >= 3, "getaddr is RPCBIND: version 3 or 4");
            wire::write_rpcb(
                &mut w,
                &wire::Rpcb {
                    program: u32_of(v, "program")?,
                    version: u32_of(v, "program_version")?,
                    netid: protocol.into(),
                    addr: String::new(),
                    owner: String::new(),
                },
            );
            (ver, 3, w.0)
        }
        t @ ("sunrpc_set" | "sunrpc_unset") => {
            let set = t == "sunrpc_set";
            let ver = version(v, 2)?;
            let port = if set {
                let port = v["port"].as_u64().context("port is required")?;
                ensure!(port > 0 && port <= 65535, "port must be 1-65535");
                port as u16
            } else {
                0
            };
            if ver == 2 {
                let prot = wire::protocol_of(protocol)
                    .filter(|_| !protocol.ends_with('6'))
                    .context("version 2 registers tcp or udp")?;
                w.u32(u32_of(v, "program")?)
                    .u32(u32_of(v, "program_version")?)
                    .u32(prot)
                    .u32(u32::from(port));
            } else {
                ensure!(
                    protocol.is_empty() || wire::protocol_of(protocol).is_some(),
                    "protocol must be tcp, udp, tcp6 or udp6"
                );
                let host = if protocol.ends_with('6') {
                    "::1"
                } else {
                    "127.0.0.1"
                };
                wire::write_rpcb(
                    &mut w,
                    &wire::Rpcb {
                        program: u32_of(v, "program")?,
                        version: u32_of(v, "program_version")?,
                        netid: protocol.into(),
                        addr: if set {
                            wire::uaddr(host.parse()?, port)
                        } else {
                            String::new()
                        },
                        owner: "netget".into(),
                    },
                );
            }
            (ver, if set { 1 } else { 2 }, w.0)
        }
        t => bail!("Unknown portmapper client action {t:?}"),
    })
}

/// A successful call's result body, as the handler reads it.
pub fn result(v: &Value, version: u32, body: &[u8]) -> Result<Value> {
    let mut r = wire::Reader::new(body);
    Ok(match v["type"].as_str().unwrap_or_default() {
        "sunrpc_null" => Value::Null,
        "sunrpc_dump" if version == 2 => Value::Array(
            wire::read_pmaplist(body)?
                .iter()
                .map(wire::mapping_json)
                .collect(),
        ),
        "sunrpc_dump" => Value::Array(wire::read_rpcblist(body)?),
        "sunrpc_getport" | "sunrpc_gettime" => json!(r.u32()?),
        "sunrpc_getaddr" => {
            let a = r.string()?;
            let port = wire::parse_uaddr(&a).map(|s| s.port()).ok();
            json!({"address": a, "port": port})
        }
        "sunrpc_set" | "sunrpc_unset" => json!(r.bool()?),
        _ => Value::Null,
    })
}

impl Protocol for SunRpcClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SunRPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ONC-RPC>Portmapper"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sunrpc", "portmapper", "rpcbind", "rpcinfo", "onc rpc"]
    }
    fn description(&self) -> &'static str {
        "ONC RPC portmapper/rpcbind client over TCP: dump, getport, getaddr, set, unset, gettime"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), REPLY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's ONC RPC codec as a caller: one TCP connection with record marking, AUTH_NONE calls to program 100000 (PMAP v2, RPCBIND v3/v4), replies matched by xid")
            .llm_control("Which programs to look up, register and remove, and what to do with each answer")
            .e2e_testing("tests/client/sunrpc: the system rpcbind (libtirpc) on 127.0.0.1:111, read back with rpcinfo")
            .notes("TCP only, AUTH_NONE only. Replies are capped at 256 KiB. A call waits at most 10 s. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the portmapper at 127.0.0.1:111 where NFS v3 listens over TCP"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"sunrpc","remote_addr":"127.0.0.1:111",
            "instruction":"List every registered program"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"sunrpc_connected","handler":{"type":"static","actions":[{"type":"sunrpc_dump","version":4}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\na=[{'type':'sunrpc_getport','program':100003,'program_version':3}] if i['event_type_id']=='sunrpc_connected' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for SunRpcClientProtocol {
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
        call(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
