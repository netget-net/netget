//! What the model answers when a WS-Discovery client probes or resolves. A target service
//! answers only with a match: there is no negative reply in WS-Discovery, so saying nothing is
//! how a target declines. Announcements (Hello, Bye) go to the multicast group.
use super::wire::{self, Kind, Version};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

pub const ANNOUNCE: &str = "wsd_announce";

/// What an answer needs from the request it answers.
#[derive(Clone)]
pub struct RequestContext {
    pub version: Version,
    pub message_id: String,
    pub instance_id: u64,
    pub numbers: Arc<AtomicU64>,
}

#[derive(Default, Clone)]
pub struct WsDiscoveryProtocol {
    request: Option<RequestContext>,
}

impl WsDiscoveryProtocol {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn for_request(ctx: RequestContext) -> Self {
        Self { request: Some(ctx) }
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

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let info = match name {
        "wsd_probe_match" => "-> WS-Discovery ProbeMatches".to_string(),
        "wsd_resolve_match" => "-> WS-Discovery ResolveMatch {endpoint_reference}".to_string(),
        "wsd_send_hello" => "-> WS-Discovery Hello {endpoint_reference}".to_string(),
        "wsd_send_bye" => "-> WS-Discovery Bye {endpoint_reference}".to_string(),
        _ => format!("-> WS-Discovery {}", name.trim_start_matches("wsd_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn target_params() -> Vec<Parameter> {
    vec![
        p("endpoint_reference", "string", "The service's stable identity, a URI such as urn:uuid:5a7c...", true),
        p("types", "array", "Service types as {namespace}LocalName, e.g. {http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter", false),
        p("scopes", "array", "Scope URIs, e.g. onvif://www.onvif.org/name/Camera1", false),
        p("xaddrs", "array", "Transport addresses where the service is reached, e.g. http://192.0.2.10/onvif/device_service", false),
        p("metadata_version", "number", "Incremented when the service's metadata changes (default 1)", false),
    ]
}

fn example_target() -> Value {
    json!({"endpoint_reference":"urn:uuid:9d8f7e6c-0000-4000-8000-000000000001",
           "types":["{http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter"],
           "scopes":["onvif://www.onvif.org/name/Camera1"],
           "xaddrs":["http://192.0.2.10/onvif/device_service"],
           "metadata_version":1})
}

pub fn probe_match_action() -> ActionDefinition {
    let mut example = json!({"type":"wsd_probe_match"});
    example["matches"] = json!([example_target()]);
    action(
        "wsd_probe_match",
        "Answer the probe with ProbeMatches, one entry per service of yours that matches. To decline, answer nothing: WS-Discovery has no negative reply.",
        vec![p("matches", "array", "The matching services, each with endpoint_reference, types, scopes, xaddrs and metadata_version", true)],
        example,
    )
}

pub fn resolve_match_action() -> ActionDefinition {
    let mut example = example_target();
    example["type"] = json!("wsd_resolve_match");
    action(
        "wsd_resolve_match",
        "Answer the resolve with this service's current transport addresses.",
        target_params(),
        example,
    )
}

pub fn hello_action() -> ActionDefinition {
    let mut example = example_target();
    example["type"] = json!("wsd_send_hello");
    action(
        "wsd_send_hello",
        "Announce a service to the multicast group (Hello).",
        target_params(),
        example,
    )
}

pub fn bye_action() -> ActionDefinition {
    action(
        "wsd_send_bye",
        "Announce to the multicast group that a service is leaving (Bye).",
        vec![p(
            "endpoint_reference",
            "string",
            "The leaving service's identity URI, e.g. urn:uuid:...",
            true,
        )],
        json!({"type":"wsd_send_bye","endpoint_reference":"urn:uuid:9d8f7e6c-0000-4000-8000-000000000001"}),
    )
}

fn probe_params() -> Vec<Parameter> {
    vec![
        p(
            "version",
            "string",
            "WS-Discovery version the client spoke: 2005/04 or 2009/01",
            true,
        ),
        p(
            "message_id",
            "string",
            "The probe's MessageID, which the answer relates to",
            true,
        ),
        p(
            "types",
            "array",
            "Types asked for, as {namespace}LocalName; empty means any",
            true,
        ),
        p(
            "scopes",
            "array",
            "Scope URIs asked for; empty means any",
            true,
        ),
        p(
            "match_by",
            "string",
            "The scope matching rule URI, when the client named one",
            false,
        ),
        p("source", "string", "The client's address and port", true),
    ]
}

pub static PROBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wsd_probe",
        "A client is looking for services with these types and scopes. Answer wsd_probe_match for each of yours that matches, or nothing.",
        probe_match_action().example.clone(),
    )
    .with_parameters(probe_params())
    .with_actions(vec![probe_match_action(), hello_action(), bye_action()])
});

pub static RESOLVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wsd_resolve",
        "A client wants the transport addresses of one service. Answer wsd_resolve_match if it is yours, or nothing.",
        resolve_match_action().example.clone(),
    )
    .with_parameters(vec![
        p("version", "string", "WS-Discovery version the client spoke: 2005/04 or 2009/01", true),
        p("endpoint_reference", "string", "The service asked about, a URI such as urn:uuid:...", true),
        p("source", "string", "The client's address and port", true),
    ])
    .with_actions(vec![resolve_match_action(), hello_action(), bye_action()])
});

pub static ANNOUNCEMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wsd_announcement",
        "Another service announced itself (Hello) or its departure (Bye) on the group.",
        hello_action().example.clone(),
    )
    .with_parameters(vec![
        p(
            "message",
            "string",
            "Hello or Bye, as the announcing service sent it",
            true,
        ),
        p(
            "service",
            "object",
            "The announced service: endpoint_reference, types, scopes, xaddrs",
            true,
        ),
        p("source", "string", "The announcer's address and port", true),
    ])
    .with_actions(vec![hello_action(), bye_action()])
});

impl WsDiscoveryProtocol {
    fn next_number(&self) -> (u64, u64) {
        match &self.request {
            Some(r) => (r.instance_id, r.numbers.fetch_add(1, Ordering::Relaxed)),
            None => (super::instance_id(), 1),
        }
    }
    fn version(&self) -> Version {
        self.request.as_ref().map_or(Version::V2005, |r| r.version)
    }
}

impl Protocol for WsDiscoveryProtocol {
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
            "soap-over-udp",
            "3702",
        ]
    }
    fn description(&self) -> &'static str {
        "WS-Discovery target service: answers Probe and Resolve over SOAP/UDP multicast (ONVIF cameras, WSD printers, Windows network discovery) and announces Hello/Bye"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        // A datagram server owns no socket in its registry instance; announcements are made
        // as answers (wsd_send_hello / wsd_send_bye), routed to the group by the server.
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            probe_match_action(),
            resolve_match_action(),
            hello_action(),
            bye_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            PROBE_EVENT.clone(),
            RESOLVE_EVENT.clone(),
            ANNOUNCEMENT_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // Loopback by default like every server here; host 0.0.0.0 is what lets multicast
        // probes from the network arrive. The port is 0 so `protocol::default_port` applies the
        // declared well-known 3702 (or an OS-assigned one when 3702 cannot be bound).
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "join_multicast".into(),
                type_hint: "boolean".into(),
                description: "Join 239.255.255.250 to hear multicast probes; directed (unicast) probes are answered either way".into(),
                required: false,
                example: json!(false),
                default: Some(json!(super::DEFAULT_JOIN_MULTICAST)),
            },
            ParameterDefinition {
                name: "multicast_interface".into(),
                type_hint: "string".into(),
                description: "IPv4 address of the interface to join the group on (default: the system's choice)".into(),
                required: false,
                example: json!("192.0.2.10"),
                default: None,
            },
            ParameterDefinition {
                name: "announce_target".into(),
                type_hint: "string".into(),
                description: "Where Hello and Bye go instead of 239.255.255.250:3702, as ip:port".into(),
                required: false,
                example: json!("127.0.0.1:3702"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(3702)
            .connectionless()
            .deliberately_silent()
            .implementation("Hand-rolled SOAP-over-UDP (src/server/wsdiscovery/wire.rs, quick-xml): Probe, ProbeMatches, Resolve, ResolveMatches, Hello and Bye in the April 2005 (Windows, ONVIF, wsdd) and OASIS 2009 versions, answered in the version asked; types in Clark notation; SO_REUSEADDR so it shares port 3702 with other discovery daemons on the host")
            .llm_control("Which probes and resolves to answer and with which services (types, scopes, addresses), and which Hello/Bye announcements to make")
            .e2e_testing("tests/server/wsdiscovery: python WSDiscovery (directed and multicast probes, the resolve it sends for a match without addresses, and both protocol versions by raw socket); raw tests for the bounds")
            .notes("DELIBERATELY SILENT: WS-Discovery has no negative reply, so a probe the model does not answer, or a backend failure, sends nothing (logged decision=model_silent / fail_closed_*). Each answer goes unicast to the asker. No WS-Discovery proxy mode, no metadata exchange (WS-Transfer Get) — that is HTTP on the XAddrs.")
            .max_inbound_bytes(wire::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Pretend to be an ONVIF camera on the network: answer WS-Discovery probes for NetworkVideoTransmitter"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"wsdiscovery","port":0,"startup_params":{"join_multicast":false},
            "instruction":"You are an ONVIF camera urn:uuid:9d8f7e6c-0000-4000-8000-000000000001 at http://192.0.2.10/onvif/device_service. Answer probes for NetworkVideoTransmitter or for any type."});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"wsd_probe","handler":{"type":"static","actions":[probe_match_action().example]}}]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"wsd_probe","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nm={'endpoint_reference':'urn:uuid:9d8f7e6c-0000-4000-8000-000000000001','types':['{http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter'],'xaddrs':['http://192.0.2.10/onvif/device_service']}\nok=not e['types'] or m['types'][0] in e['types']\nprint(json.dumps({'actions':[{'type':'wsd_probe_match','matches':[m]}] if ok else []}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Discovery"
    }
}

impl Server for WsDiscoveryProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action["type"].as_str().unwrap_or_default();
        let version = self.version();
        match kind {
            "wsd_probe_match" | "wsd_resolve_match" => {
                let targets = if kind == "wsd_probe_match" {
                    let list = action["matches"]
                        .as_array()
                        .context("wsd_probe_match needs matches, an array of services")?;
                    list.iter()
                        .map(wire::target_from_json)
                        .collect::<Result<Vec<_>>>()?
                } else {
                    vec![wire::target_from_json(&action)?]
                };
                let Some(request) = &self.request else {
                    // The registry's instance answers no request: the shape is checked, and
                    // nothing is sent.
                    return Ok(ActionResult::NoAction);
                };
                let (instance, number) = self.next_number();
                let message_kind = if kind == "wsd_probe_match" {
                    Kind::ProbeMatches
                } else {
                    Kind::ResolveMatches
                };
                let xml = wire::matches(
                    version,
                    message_kind,
                    &request.message_id,
                    &targets,
                    instance,
                    number,
                )?;
                Ok(ActionResult::Output(xml.into_bytes()))
            }
            "wsd_send_hello" => {
                let target = wire::target_from_json(&action)?;
                let (instance, number) = self.next_number();
                Ok(ActionResult::Custom {
                    name: ANNOUNCE.into(),
                    data: json!({"xml": wire::hello(version, &target, instance, number)}),
                })
            }
            "wsd_send_bye" => {
                let endpoint = action["endpoint_reference"]
                    .as_str()
                    .context("wsd_send_bye needs endpoint_reference")?;
                let (instance, number) = self.next_number();
                Ok(ActionResult::Custom {
                    name: ANNOUNCE.into(),
                    data: json!({"xml": wire::bye(version, endpoint, instance, number)}),
                })
            }
            other => bail!("Unknown WS-Discovery action {other:?}"),
        }
    }
}
