//! What the model can do as a WS-Discovery client: probe for services by type and scope,
//! resolve one service's addresses, and hear announcements.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::wsdiscovery::actions::{action, p};
use crate::server::wsdiscovery::wire::{self, QName};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How long a probe or resolve collects answers, by default (the specification's
/// MATCH_TIMEOUT for a multicast probe is 4 s; most devices answer within 500 ms).
pub const DEFAULT_WAIT_MS: u64 = 2000;
pub const MAX_WAIT_MS: u64 = 30_000;
pub const DEFAULT_VERSION: &str = "2005/04";

#[derive(Default)]
pub struct WsDiscoveryClientProtocol;
impl WsDiscoveryClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn probe_action() -> ActionDefinition {
    action(
        "wsd_probe",
        "Probe for services; every match that arrives within wait_ms is reported together as wsd_probe_matches.",
        vec![
            p("types", "array", "Types to look for, as {namespace}LocalName (or wsdp:Device, dn:NetworkVideoTransmitter); omit for any", false),
            p("scopes", "array", "Scope URIs the services must have, e.g. onvif://www.onvif.org/location/office", false),
            p("match_by", "string", "Scope matching rule URI (default: RFC 3986 prefix match)", false),
            p("wait_ms", "number", "How long to collect answers, 100-30000 (default 2000)", false),
        ],
        json!({"type":"wsd_probe","types":["{http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter"],"wait_ms":2000}),
    )
}

fn resolve_action() -> ActionDefinition {
    action(
        "wsd_resolve",
        "Ask for one service's transport addresses by its endpoint reference; the answer arrives as wsd_resolve_matches.",
        vec![
            p("endpoint_reference", "string", "The service's identity URI from a probe match, e.g. urn:uuid:...", true),
            p("wait_ms", "number", "How long to wait for the answer, 100-30000 (default 2000)", false),
        ],
        json!({"type":"wsd_resolve","endpoint_reference":"urn:uuid:9d8f7e6c-0000-4000-8000-000000000001"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop the client and close its sockets.",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![probe_action(), resolve_action(), disconnect_action()]
}

fn ev(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(id, description, probe_action().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

fn matches_params() -> Vec<crate::llm::actions::Parameter> {
    vec![
        p("matches", "array", "Each service that answered: endpoint_reference, types, scopes, xaddrs, metadata_version", true),
        p("count", "number", "How many distinct services answered", true),
        p("responders", "array", "The addresses the answers came from", true),
    ]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "wsd_ready",
        "The client is ready to probe.",
        vec![
            p(
                "target",
                "string",
                "Where probes go: the multicast group 239.255.255.250:3702 or the directed address",
                true,
            ),
            p(
                "version",
                "string",
                "The WS-Discovery version probes are sent in, 2005/04 or 2009/01",
                true,
            ),
        ],
    )
});

pub static PROBE_MATCHES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = matches_params();
    params.push(p("types", "array", "The types this probe asked for", true));
    params.push(p(
        "scopes",
        "array",
        "The scopes this probe asked for",
        true,
    ));
    ev(
        "wsd_probe_matches",
        "A probe's collection time ended; these services answered (possibly none).",
        params,
    )
});

pub static RESOLVE_MATCHES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = matches_params();
    params.push(p(
        "endpoint_reference",
        "string",
        "The service that was resolved",
        true,
    ));
    ev(
        "wsd_resolve_matches",
        "A resolve's wait ended; the service answered with its addresses, or nobody did.",
        params,
    )
});

pub static ANNOUNCEMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "wsd_announcement",
        "A service announced itself (Hello) or its departure (Bye) on the multicast group.",
        vec![
            p(
                "message",
                "string",
                "Hello or Bye, as the announcing service sent it",
                true,
            ),
            p(
                "service",
                "object",
                "The service: endpoint_reference, types, scopes, xaddrs",
                true,
            ),
            p("source", "string", "The announcer's address and port", true),
        ],
    )
});

pub fn wait_ms(v: &Value) -> Result<u64> {
    match v.get("wait_ms") {
        None | Some(Value::Null) => Ok(DEFAULT_WAIT_MS),
        Some(x) => {
            let n = x.as_u64().context("wait_ms must be a whole number")?;
            ensure!(
                (100..=MAX_WAIT_MS).contains(&n),
                "wait_ms must be between 100 and {MAX_WAIT_MS}"
            );
            Ok(n)
        }
    }
}

pub fn strings(v: &Value, key: &str) -> Result<Vec<String>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => {
            ensure!(
                a.len() <= wire::MAX_ITEMS,
                "{key} has more than {} entries",
                wire::MAX_ITEMS
            );
            a.iter()
                .map(|x| {
                    let s = x.as_str().with_context(|| format!("{key} holds strings"))?;
                    ensure!(
                        !s.is_empty() && !s.chars().any(char::is_whitespace),
                        "{key} entries contain no spaces: {s:?}"
                    );
                    Ok(s.to_string())
                })
                .collect()
        }
        Some(_) => bail!("{key} must be an array of strings"),
    }
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        "wsd_probe" => {
            for t in strings(v, "types")? {
                QName::parse(&t)?;
            }
            strings(v, "scopes")?;
            wait_ms(v)?;
        }
        "wsd_resolve" => {
            let e = v["endpoint_reference"]
                .as_str()
                .context("endpoint_reference is required")?;
            ensure!(
                !e.is_empty() && !e.chars().any(char::is_whitespace),
                "endpoint_reference is one URI"
            );
            wait_ms(v)?;
        }
        other => bail!("Unknown WS-Discovery client action {other:?}"),
    }
    Ok(())
}

impl Protocol for WsDiscoveryClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "WS-Discovery"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>WS-Discovery"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ws-discovery",
            "wsdiscovery",
            "wsd",
            "onvif discovery",
            "find cameras",
            "find printers",
        ]
    }
    fn description(&self) -> &'static str {
        "WS-Discovery client: probes the network (or one address) for services such as ONVIF cameras, WSD printers and Windows hosts, and resolves their addresses"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            PROBE_MATCHES_EVENT.clone(),
            RESOLVE_MATCHES_EVENT.clone(),
            ANNOUNCEMENT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "version".into(),
                type_hint: "string".into(),
                description: "WS-Discovery version to probe in: 2005/04 (Windows, ONVIF, wsdd) or 2009/01".into(),
                required: false,
                example: json!("2009/01"),
                default: Some(json!(DEFAULT_VERSION)),
            },
            ParameterDefinition {
                name: "listen_announcements".into(),
                type_hint: "boolean".into(),
                description: "Also listen on the group (UDP 3702) for Hello and Bye, reported as wsd_announcement".into(),
                required: false,
                example: json!(true),
                default: Some(json!(super::DEFAULT_LISTEN_ANNOUNCEMENTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's SOAP-over-UDP codec: Probe and Resolve to the multicast group (or remote_addr for a directed probe) from an ephemeral port, answers collected by RelatesTo until wait_ms and reported once, duplicates by endpoint merged; Hello/Bye heard on 3702 when listen_announcements is set")
            .llm_control("What to look for (types, scopes), which services to resolve, and what to do with what answered")
            .e2e_testing("tests/client/wsdiscovery: wsdd (the Linux WSD host daemon) and python WSDiscovery publishing services; NetGet's own target service for the directed path")
            .notes("A probe is sent once; on a lossy network a missed answer is a missing match, not an error. Answers whose RelatesTo names no probe of ours are dropped. No discovery-proxy mode.")
            .max_inbound_bytes(wire::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Find the ONVIF cameras on the network and resolve the first one's address"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"wsdiscovery","remote_addr":"","instruction":"Find every ONVIF camera and list their addresses"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"wsd_ready","handler":{"type":"static","actions":[probe_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"wsd_probe_matches","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'wsd_resolve','endpoint_reference':m['endpoint_reference']} for m in e['matches'] if not m['xaddrs']]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Discovery"
    }
}

impl Client for WsDiscoveryClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
