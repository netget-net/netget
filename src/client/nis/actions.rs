//! What the model asks a NIS server once bound to a domain: one key (match), a whole map
//! (cat, ALL), a walk (first/next), a map's master and order, the domain's maps, and whether
//! a domain is served. Every answer comes back as `nis_reply` with the entries decoded.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::nis::{
    actions::p,
    wire::{self, proc_},
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct NisClientProtocol;
impl NisClientProtocol {
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
        log_template: Some(
            LogTemplate::new().with_info(format!("-> ypserv {}", name.trim_start_matches("nis_"))),
        ),
    }
}

fn domain_param() -> crate::llm::actions::Parameter {
    p(
        "domain",
        "string",
        "The NIS domain; default the one the client bound to",
        false,
    )
}

fn map_param() -> crate::llm::actions::Parameter {
    p(
        "map",
        "string",
        "The full map name, e.g. passwd.byname, group.bygid, hosts.byname, netgroup (no nicknames: passwd is passwd.byname)",
        true,
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "nis_match",
            "Look up one key in a map (YPPROC_MATCH), as ypmatch does.",
            vec![
                map_param(),
                p(
                    "key",
                    "string",
                    "The key: a user name, uid, host name…",
                    true,
                ),
                domain_param(),
            ],
            json!({"type": "nis_match", "map": "passwd.byname", "key": "alice"}),
        ),
        action(
            "nis_cat",
            "Read every entry of a map (YPPROC_ALL over TCP), as ypcat does.",
            vec![map_param(), domain_param()],
            json!({"type": "nis_cat", "map": "passwd.byname"}),
        ),
        action(
            "nis_first",
            "Read a map's first entry (YPPROC_FIRST).",
            vec![map_param(), domain_param()],
            json!({"type": "nis_first", "map": "hosts.byname"}),
        ),
        action(
            "nis_next",
            "Read the entry after a key (YPPROC_NEXT); YP_NOMORE after the last.",
            vec![
                map_param(),
                p("key", "string", "The key to continue after", true),
                domain_param(),
            ],
            json!({"type": "nis_next", "map": "hosts.byname", "key": "gateway"}),
        ),
        action(
            "nis_master",
            "Ask which server is a map's master (YPPROC_MASTER).",
            vec![map_param(), domain_param()],
            json!({"type": "nis_master", "map": "passwd.byname"}),
        ),
        action(
            "nis_order",
            "Ask a map's order number, its version (YPPROC_ORDER).",
            vec![map_param(), domain_param()],
            json!({"type": "nis_order", "map": "passwd.byname"}),
        ),
        action(
            "nis_maplist",
            "List the maps the domain holds (YPPROC_MAPLIST).",
            vec![domain_param()],
            json!({"type": "nis_maplist"}),
        ),
        action(
            "nis_domain",
            "Ask whether the server serves a domain (YPPROC_DOMAIN).",
            vec![domain_param()],
            json!({"type": "nis_domain", "domain": "example.lan"}),
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
        "nis_connected",
        "Bound to a NIS server: connected over TCP and asked whether it serves the domain.",
        json!({"type": "nis_maplist"}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The ypserv address and port", true),
        p(
            "portmapper",
            "string",
            "The portmapper ypserv's port was looked up with, when one was",
            false,
        ),
        p("domain", "string", "The domain bound to", true),
        p(
            "served",
            "boolean",
            "Whether the server says it serves the domain",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nis_reply",
        "The NIS server answered a request.",
        json!({"type": "nis_match", "map": "group.byname", "key": "staff"}),
    )
    .with_parameters(vec![
        p("operation", "string", "The action performed", true),
        p("domain", "string", "The domain asked", true),
        p("map", "string", "The map asked, when there was one", false),
        p("ok", "boolean", "Whether the server answered YP_TRUE (or, for cat, read the map to its end)", true),
        p("status", "string", "The YP status: YP_TRUE, YP_NOMORE, YP_NOKEY, YP_NOMAP, YP_NODOM, YP_YPERR…", true),
        p("entry", "object", "match/first/next: {key, value, fields?} — fields parsed from passwd, group, hosts and netgroup lines", false),
        p("entries", "array", "cat: every {key, value, fields?}", false),
        p("master", "string", "master: the master server", false),
        p("order", "number", "order: the order number", false),
        p("maps", "array", "maplist: the map names", false),
        p("served", "boolean", "domain: whether it is served", false),
        p("error", "string", "Why there is no YP answer at all (an RPC error such as PROG_UNAVAIL)", false),
    ])
    .with_actions(actions())
});

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("{k} is required"))
}

/// The domain an action names, or the bound one.
pub fn domain_of(v: &Value, bound: &str) -> Result<String> {
    match v["domain"].as_str() {
        Some(d) => wire::model_name(d, wire::YPMAXDOMAIN, "domain"),
        None => Ok(bound.to_string()),
    }
}

fn map_of(v: &Value) -> Result<String> {
    wire::model_name(text(v, "map")?, wire::YPMAXMAP, "map name")
}

fn key_of(v: &Value) -> Result<String> {
    let k = text(v, "key")?;
    ensure!(
        !k.is_empty() && k.len() <= wire::YPMAXRECORD,
        "a key is 1-{} bytes",
        wire::YPMAXRECORD
    );
    ensure!(
        !crate::utils::sanitize::has_controls(k),
        "a key has no control characters"
    );
    Ok(k.to_string())
}

/// One YP call an action makes.
pub struct YpCall {
    pub procedure: u32,
    pub args: Vec<u8>,
    pub domain: String,
    pub map: Option<String>,
    pub key: Option<String>,
}

/// The call one action makes, validated before anything is sent.
pub fn call(v: &Value, bound: &str) -> Result<YpCall> {
    let domain = domain_of(v, bound)?;
    let (procedure, map, key) = match v["type"].as_str().unwrap_or_default() {
        t @ ("nis_match" | "nis_next") => {
            let procedure = if t == "nis_match" {
                proc_::MATCH
            } else {
                proc_::NEXT
            };
            (procedure, Some(map_of(v)?), Some(key_of(v)?))
        }
        t @ ("nis_cat" | "nis_first" | "nis_master" | "nis_order") => {
            let procedure = match t {
                "nis_cat" => proc_::ALL,
                "nis_first" => proc_::FIRST,
                "nis_master" => proc_::MASTER,
                _ => proc_::ORDER,
            };
            (procedure, Some(map_of(v)?), None)
        }
        "nis_maplist" => (proc_::MAPLIST, None, None),
        "nis_domain" => (proc_::DOMAIN, None, None),
        t => bail!("Unknown NIS client action {t:?}"),
    };
    let args = match (&map, &key) {
        (Some(m), Some(k)) => wire::req_key(&domain, m, k),
        (Some(m), None) => wire::req_nokey(&domain, m),
        _ => wire::req_domain(&domain),
    };
    Ok(YpCall {
        procedure,
        args,
        domain,
        map,
        key,
    })
}

/// A successful call's result body, as the handler reads it: (ok, status, fields to merge).
pub fn result(c: &YpCall, body: &[u8]) -> Result<(bool, String, Value)> {
    let map = c.map.as_deref().unwrap_or_default();
    Ok(match c.procedure {
        proc_::MATCH => {
            let (stat, val) = wire::read_resp_val(body)?;
            let mut out = json!({});
            if stat == wire::Stat::True {
                out["entry"] = wire::entry_json(map, c.key.as_deref().unwrap_or_default(), &val);
            }
            (stat == wire::Stat::True, stat.name().into(), out)
        }
        proc_::FIRST | proc_::NEXT => {
            let (stat, key, val) = wire::read_resp_key_val(body)?;
            let mut out = json!({});
            if stat == wire::Stat::True {
                out["entry"] = wire::entry_json(map, &key, &val);
            }
            (stat == wire::Stat::True, stat.name().into(), out)
        }
        proc_::ALL => {
            let (pairs, stat) = wire::read_resp_all(body)?;
            let entries: Vec<Value> = pairs
                .iter()
                .map(|(k, v)| wire::entry_json(map, k, v))
                .collect();
            let ok = stat == wire::Stat::NoMore;
            let status = if ok { "YP_TRUE" } else { stat.name() };
            (ok, status.into(), json!({"entries": entries}))
        }
        proc_::MASTER => {
            let (stat, peer) = wire::read_resp_master(body)?;
            let mut out = json!({});
            if stat == wire::Stat::True {
                out["master"] = json!(crate::utils::sanitize::token(&peer, wire::YPMAXPEER));
            }
            (stat == wire::Stat::True, stat.name().into(), out)
        }
        proc_::ORDER => {
            let (stat, order) = wire::read_resp_order(body)?;
            let mut out = json!({});
            if stat == wire::Stat::True {
                out["order"] = json!(order);
            }
            (stat == wire::Stat::True, stat.name().into(), out)
        }
        proc_::MAPLIST => {
            let (stat, maps) = wire::read_resp_maplist(body)?;
            let maps: Vec<String> = maps
                .iter()
                .map(|m| crate::utils::sanitize::token(m, wire::YPMAXMAP))
                .collect();
            (
                stat == wire::Stat::True,
                stat.name().into(),
                json!({"maps": maps}),
            )
        }
        proc_::DOMAIN => {
            let served = wire::read_bool(body)?;
            (
                true,
                if served { "YP_TRUE" } else { "YP_FALSE" }.into(),
                json!({"served": served}),
            )
        }
        p => bail!("procedure {p} has no result here"),
    })
}

pub fn startup_parameters() -> Vec<ParameterDefinition> {
    vec![
        ParameterDefinition {
            name: "domain".into(),
            type_hint: "string".into(),
            description: "The NIS domain to bind to (asked with YPPROC_DOMAIN on connect, and \
                          used by every action that names none)"
                .into(),
            required: true,
            example: json!("example.lan"),
            default: None,
        },
        ParameterDefinition {
            name: "use_portmapper".into(),
            type_hint: "boolean".into(),
            description: "Treat remote_addr as a portmapper and ask it where ypserv (program \
                          100004 v2, tcp) listens, as ypbind and ypcat -h do. Without it, true \
                          when remote_addr's port is 111 and false otherwise (remote_addr is \
                          then ypserv itself)"
                .into(),
            required: false,
            example: json!(true),
            default: None,
        },
    ]
}

impl Protocol for NisClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NIS"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ONC-RPC>NIS"
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
        "NIS/YP client (ONC RPC program 100004 v2 over TCP): bind to a domain, then match, cat, first/next, master, order and maplist"
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
        startup_parameters()
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's YP codec (src/server/nis/wire.rs) over the portmapper's ONC RPC codec as a caller: optional PMAP v2 GETPORT for ypserv, one TCP connection with record marking, AUTH_NONE calls, replies matched by xid; DOMAIN on connect, then MATCH, ALL (the ypresp_all stream, iterative and capped), FIRST, NEXT, MASTER, ORDER, MAPLIST and DOMAIN")
            .llm_control("Which maps and keys to read and what to do with each answer; passwd, group, hosts and netgroup lines arrive parsed into fields")
            .e2e_testing("tests/client/nis: Linux ypserv 4.2 with maps built by makedbm in a temporary domain, registered with the system rpcbind and found through it; NetGet's own server as a regression only")
            .notes("Experimental: one independent server (Linux ypserv), on Linux only, and its pair job had not run in CI when it landed. TCP only, AUTH_NONE only, no ypbind protocol (it binds to the server it is given). NIS carries passwd entries, hashes included when a server serves them, in clear text. Replies are capped at 4 MiB in 1024 fragments and 10 000 entries; a call waits at most 10 s; a handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Bind to NIS domain example.lan through the portmapper at 127.0.0.1:111 and list every account in passwd.byname"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"nis","remote_addr":"127.0.0.1:111",
            "startup_params": {"domain": "example.lan"},
            "instruction":"List the maps, then read passwd.byname and look up group staff"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"nis_connected","handler":{"type":"static","actions":[{"type":"nis_cat","map":"passwd.byname"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\na=[{'type':'nis_match','map':'passwd.byname','key':'alice'}] if i['event_type_id']=='nis_connected' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for NisClientProtocol {
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
        // The bound domain is only known to the session; a placeholder stands in for it here.
        call(&v, "bound")?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
