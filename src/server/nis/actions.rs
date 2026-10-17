//! What the model decides as a NIS server: which domains it serves, which maps each holds,
//! and every entry of every map, answered per request. Rust owns ONC RPC, XDR, the
//! `ypresp_all` stream, walking a map for FIRST/NEXT, and rendering structured entries into
//! the canonical lines (`alice:x:1000:1000:Alice:/home/alice:/bin/bash`).
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

pub const DOMAIN: &str = "nis_domain";
pub const ENTRIES: &str = "nis_entries";
pub const ERROR: &str = "nis_error";
pub const MAP_INFO: &str = "nis_map_info";
pub const MAPS: &str = "nis_maps";

#[derive(Default, Clone)]
pub struct NisProtocol;

impl NisProtocol {
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

pub fn domain_action() -> ActionDefinition {
    action(
        DOMAIN,
        "Say whether this server serves the domain. A client binds only to a server that says true.",
        vec![p("served", "boolean", "true to serve the domain, false to refuse it", true)],
        json!({"type": DOMAIN, "served": true}),
        "-> nis domain served={served}",
    )
}

const ENTRY_FORMS: &str = "Each entry is an object whose fields depend on the map: \
passwd.byname/passwd.byuid {name, password?, uid, gid, gecos?, home, shell} (password defaults to \"x\", meaning the hash is not served; NIS has no confidentiality, so anything you put there is readable by anyone who asks); \
group.byname/group.bygid {name, password?, gid, members?: [user]}; \
hosts.byname/hosts.byaddr {address, names: [name, alias…]}; \
netgroup {name, members: [{host?, user?, domain?} or another netgroup's name]}; \
any other map (or to spell a line yourself) {key, value} as text. \
NetGet renders the canonical line and derives the key (name, uid, gid, each host name or the address). \
Fields may not contain the line's separators (':' in passwd/group) or control characters";

pub fn entries_action() -> ActionDefinition {
    action(
        ENTRIES,
        "Answer with the map's entries: for a match the one entry asked for is enough; for first/next/all give every entry, in the order to enumerate them. An empty list is an empty map (a match then finds no key).",
        vec![p("entries", "array", ENTRY_FORMS, true)],
        json!({"type": ENTRIES, "entries": [
            {"name": "alice", "password": "x", "uid": 1000, "gid": 1000, "gecos": "Alice", "home": "/home/alice", "shell": "/bin/bash"},
            {"name": "bob", "uid": 1001, "gid": 1001, "home": "/home/bob", "shell": "/bin/sh"}
        ]}),
        "-> nis entries",
    )
}

pub fn error_action() -> ActionDefinition {
    action(
        ERROR,
        "Refuse the request with a NIS status: no_domain (the domain is not served), no_map (no such map in the domain), no_key (no such key, for a match), bad_args, bad_database, error.",
        vec![p(
            "status",
            "string",
            "no_domain, no_map, no_key, bad_args, bad_database or error",
            true,
        )],
        json!({"type": ERROR, "status": "no_key"}),
        "-> nis error {status}",
    )
}

pub fn map_info_action() -> ActionDefinition {
    action(
        MAP_INFO,
        "Answer a master or order request: the map's master server and its order number (a version, conventionally the time it was built, in Unix seconds).",
        vec![
            p("master", "string", "The master server's host name (needed for master)", false),
            p("order", "number", "The map's order number (needed for order)", false),
        ],
        json!({"type": MAP_INFO, "master": "nis-master", "order": 1_790_000_000}),
        "-> nis map master={master} order={order}",
    )
}

pub fn maps_action() -> ActionDefinition {
    action(
        MAPS,
        "Answer a maplist request with the names of the maps the domain holds.",
        vec![p(
            "maps",
            "array",
            "Map names, e.g. passwd.byname, group.bygid, hosts.byname, netgroup",
            true,
        )],
        json!({"type": MAPS, "maps": ["passwd.byname", "passwd.byuid", "group.byname", "hosts.byname"]}),
        "-> nis maps {maps}",
    )
}

fn transport() -> Parameter {
    p(
        "transport",
        "string",
        "tcp or udp: how the call arrived",
        true,
    )
}

fn domain_param() -> Parameter {
    p("domain", "string", "The NIS domain asked for", true)
}

fn map_param() -> Parameter {
    p(
        "map",
        "string",
        "The map asked for, e.g. passwd.byname",
        true,
    )
}

pub static DOMAIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_domain_query",
        "A client asks whether this server serves a NIS domain (ypbind does before binding). Answer nis_domain.",
        domain_action().example.clone(),
    )
    .with_parameters(vec![
        domain_param(),
        p(
            "procedure",
            "string",
            "domain, or domain_nonack (a refusal there is answered with silence, as the protocol says)",
            true,
        ),
        transport(),
    ])
    .with_actions(vec![domain_action()])
});

pub static MATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_match",
        "A client looks up one key in a map (ypmatch, getpwnam over NIS). Answer nis_entries with the entry, or nis_error.",
        json!({"type": ENTRIES, "entries": [{"name": "alice", "uid": 1000, "gid": 1000, "gecos": "Alice", "home": "/home/alice", "shell": "/bin/bash"}]}),
    )
    .with_parameters(vec![
        domain_param(),
        map_param(),
        p("key", "string", "The key looked up: a user name, a uid, a host name…", true),
        transport(),
    ])
    .with_actions(vec![entries_action(), error_action()])
});

pub static MAP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_map_read",
        "A client reads a whole map (all, as ypcat does) or walks it (first, then next after a key). Answer nis_entries with every entry, or nis_error. NetGet picks the entry each procedure returns.",
        entries_action().example.clone(),
    )
    .with_parameters(vec![
        domain_param(),
        map_param(),
        p("procedure", "string", "all, first or next", true),
        p("key", "string", "For next: the key the client is at", false),
        transport(),
    ])
    .with_actions(vec![entries_action(), error_action()])
});

pub static MAP_INFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_map_info",
        "A client asks a map's master server (master) or its order number (order), as yppoll and ypwhich -m do. Answer nis_map_info, or nis_error.",
        map_info_action().example.clone(),
    )
    .with_parameters(vec![
        domain_param(),
        map_param(),
        p("procedure", "string", "master or order", true),
        transport(),
    ])
    .with_actions(vec![map_info_action(), error_action()])
});

pub static MAPLIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_maplist",
        "A client asks which maps a domain holds. Answer nis_maps, or nis_error.",
        maps_action().example.clone(),
    )
    .with_parameters(vec![domain_param(), transport()])
    .with_actions(vec![maps_action(), error_action()])
});

/// The shape of one answer, before it is rendered against the map it answers.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DOMAIN => {
            v["served"]
                .as_bool()
                .context("served must be true or false")?;
        }
        ENTRIES => {
            let list = v["entries"]
                .as_array()
                .context("entries must be an array")?;
            ensure!(
                list.len() <= wire::MAX_ENTRIES,
                "at most {} entries",
                wire::MAX_ENTRIES
            );
            ensure!(list.iter().all(Value::is_object), "each entry is an object");
        }
        ERROR => {
            let s = v["status"].as_str().unwrap_or_default();
            ensure!(
                wire::Stat::from_model(s).is_some(),
                "status must be one of {}",
                wire::Stat::MODEL_NAMES.join(", ")
            );
        }
        MAP_INFO => {
            ensure!(
                !v["master"].is_null() || !v["order"].is_null(),
                "give master, order or both"
            );
            if let Some(m) = v["master"].as_str() {
                wire::model_name(m, wire::YPMAXPEER, "master server name")?;
            } else {
                ensure!(v["master"].is_null(), "master must be text");
            }
            if !v["order"].is_null() {
                let n = v["order"].as_u64().context("order must be a number")?;
                ensure!(n <= u64::from(u32::MAX), "order is a 32-bit number");
            }
        }
        MAPS => {
            let list = v["maps"].as_array().context("maps must be an array")?;
            ensure!(
                list.len() <= wire::MAX_MAPS,
                "at most {} maps",
                wire::MAX_MAPS
            );
            for m in list {
                wire::model_name(
                    m.as_str().context("maps are names")?,
                    wire::YPMAXMAP,
                    "map name",
                )?;
            }
        }
        other => bail!("Unknown NIS action {other:?}"),
    }
    Ok(())
}

pub fn portmapper_param() -> ParameterDefinition {
    ParameterDefinition {
        name: "portmapper".into(),
        type_hint: "string".into(),
        description: "Register with this portmapper (host:port, normally 127.0.0.1:111 — the \
                      system rpcbind or a NetGet sunrpc server) as ypserv, program 100004 \
                      version 2 on tcp and udp, so clients that ask the portmapper (ypcat -h, \
                      ypbind, rpcinfo) find it. Removed again when the server stops. Without \
                      it nothing is registered and clients must be told the port"
            .into(),
        required: false,
        example: json!("127.0.0.1:111"),
        default: None,
    }
}

impl Protocol for NisProtocol {
    fn protocol_name(&self) -> &'static str {
        "NIS"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP|UDP>ONC-RPC>NIS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "nis",
            "ypserv",
            "yellow pages",
            "network information service",
            "ypcat",
            "ypmatch",
        ]
    }
    fn description(&self) -> &'static str {
        "NIS/YP server (ypserv, ONC RPC program 100004 v2) on TCP and UDP: the model decides the domains it serves and every entry of passwd, group, hosts, netgroup and any other map"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            domain_action(),
            entries_action(),
            error_action(),
            map_info_action(),
            maps_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DOMAIN_EVENT.clone(),
            MATCH_EVENT.clone(),
            MAP_EVENT.clone(),
            MAP_INFO_EVENT.clone(),
            MAPLIST_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![portmapper_param()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written YP v2 (src/server/nis/wire.rs) over the portmapper's ONC RPC codec (src/server/sunrpc/wire.rs): TCP record marking and UDP datagrams on one port; NULL, DOMAIN, DOMAIN_NONACK, MATCH, FIRST, NEXT, ALL (the ypresp_all stream, ended as Linux ypserv 4.2 ends it), CLEAR, MASTER, ORDER and MAPLIST; RPC_MISMATCH, PROG_UNAVAIL, PROG_MISMATCH, PROC_UNAVAIL (XFR) and GARBAGE_ARGS answered in Rust. Optional PMAP v2 SET with a portmapper at start and UNSET at stop")
            .llm_control("Which domains it serves, which maps each holds, every entry of every map (structured passwd/group/hosts/netgroup fields that Rust renders into canonical lines, or raw key/value text), master servers and order numbers. Nothing is stored: each request asks again")
            .e2e_testing("tests/server/nis: yp-tools 4.2 (ypcat -h, yppoll -h, ypmatch, ypwhich -m, yptest) and ypbind-mt 2.7 on Linux against NetGet registered with the system rpcbind, rpcinfo -p/-t/-u reading the registration; tshark's rpc/ypserv dissectors over both directions; python-assembled XDR for the RPC errors, YP statuses and bounds; registration with NetGet's own sunrpc server")
            .notes("Experimental: one client family (yp-tools and ypbind-mt share libnsl/libtirpc), exercised on Linux only (yp-tools is not packaged for macOS), and its pair job had not run in CI when it landed. SECURITY: NIS has no authentication and no confidentiality — any host that can reach the port can read every map, and a password field holding a hash serves it to anyone (the historical NIS weakness). The model decides what goes in the password field; NetGet defaults it to \"x\". No yppasswdd (100009), no XFR/map push, no securenets. A model failure answers YP_YPERR (DOMAIN: false; DOMAIN_NONACK: no reply), never an invented entry. Bounds: calls ≤ 8 KiB in ≤ 8 fragments, keys and values ≤ YPMAXRECORD (1024), domain and map names ≤ 64, ≤ 10 000 entries per map, ≤ 256 maps, replies ≤ 4 MiB")
            .answers_on_failure()
            .request_only("Every reply answers an RPC call")
            .max_inbound_bytes(wire::MAX_CALL)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "NIS server for domain example.lan with users alice (uid 1000) and bob (uid 1001), group staff, and hosts.byname for gateway 10.0.0.1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        // No `portmapper` here: an example has to start on a machine with no rpcbind running.
        // Add {"startup_params": {"portmapper": "127.0.0.1:111"}} to be found through one.
        let base = json!({"type":"open_server","base_stack":"nis","port":0,
            "instruction":"Serve NIS domain example.lan only. passwd.byname and passwd.byuid hold alice (uid 1000, gid 1000, /home/alice, /bin/bash) and bob (uid 1001, gid 1001, /home/bob, /bin/sh), password field x. The master is nis-master."});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"nis_domain_query","handler":{"type":"static","actions":[{"type":DOMAIN,"served":true}]}},
            {"event_pattern":"nis_maplist","handler":{"type":"static","actions":[maps_action().example]}},
            {"event_pattern":"nis_map_info","handler":{"type":"static","actions":[map_info_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[entries_action().example]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nusers=[{'name':'alice','uid':1000,'gid':1000,'home':'/home/alice','shell':'/bin/bash'}]\nif e['domain']!='example.lan':\n  a=[{'type':'nis_domain','served':False}] if t=='nis_domain_query' else [{'type':'nis_error','status':'no_domain'}]\nelif t=='nis_domain_query':\n  a=[{'type':'nis_domain','served':True}]\nelif t=='nis_maplist':\n  a=[{'type':'nis_maps','maps':['passwd.byname']}]\nelif e['map']!='passwd.byname':\n  a=[{'type':'nis_error','status':'no_map'}]\nelif t=='nis_map_info':\n  a=[{'type':'nis_map_info','master':'nis-master','order':1}]\nelse:\n  a=[{'type':'nis_entries','entries':users}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for NisProtocol {
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
