//! What the model decides as an H.323 gatekeeper and as a called endpoint.
//!
//! Gatekeeper (`H323-Gatekeeper`, RAS on UDP): who may use this gatekeeper (GRQ), who may
//! register and with which aliases and for how long (RRQ), which calls are admitted and where
//! they are routed (ARQ), and where an alias is (LRQ). Endpoint (`H323`, call signalling on
//! TCP): whether an incoming call is answered, rejected, left ringing or forwarded.
//!
//! Rust owns everything under that: PER encoding and decoding of H.225.0 and H.245, Q.931
//! framing, call references and identifiers, fastStart, tunnelled H.245, time-to-live,
//! retransmissions and every bound.
use super::call::{self, cause, RELEASE_REASONS};
use super::gatekeeper::{
    self, ADMISSION_REASONS, GATEKEEPER_REASONS, LOCATION_REASONS, REGISTRATION_REASONS,
};
use super::{endpoint, h225, h245};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::LazyLock;

/// The gatekeeper identifier when none is configured.
pub const DEFAULT_GATEKEEPER_ID: &str = "NetGet";
/// The most bandwidth (in units of 100 bit/s, as H.225.0 counts it) a call is granted unless
/// configured otherwise: 10 Mbit/s.
pub const DEFAULT_MAX_BANDWIDTH: u64 = 100_000;

pub const CONFIRM_GATEKEEPER: &str = "h323_confirm_gatekeeper";
pub const REJECT_GATEKEEPER: &str = "h323_reject_gatekeeper";
pub const CONFIRM_REGISTRATION: &str = "h323_confirm_registration";
pub const REJECT_REGISTRATION: &str = "h323_reject_registration";
pub const CONFIRM_ADMISSION: &str = "h323_confirm_admission";
pub const REJECT_ADMISSION: &str = "h323_reject_admission";
pub const CONFIRM_LOCATION: &str = "h323_confirm_location";
pub const REJECT_LOCATION: &str = "h323_reject_location";

pub const CALL_PROCEEDING: &str = "h323_call_proceeding";
pub const ALERTING: &str = "h323_alerting";
pub const CONNECT: &str = "h323_connect";
pub const RELEASE_COMPLETE: &str = "h323_release_complete";
pub const FORWARD_CALL: &str = "h323_forward_call";

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
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("H.323 {name}"))
                .with_debug(format!("H.323 {name}: {{json(.)}}")),
        ),
    }
}

fn reason_of(action: &Value, allowed: &[&str], default: &str) -> Result<String> {
    let r = action
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or(default)
        .to_string();
    if !allowed.contains(&r.as_str()) {
        bail!("reason {r:?} is not one of {allowed:?}");
    }
    Ok(r)
}

// ---------------------------------------------------------------------------------------------
// Gatekeeper
// ---------------------------------------------------------------------------------------------

/// One gatekeeper decision.
#[derive(Debug, Clone)]
pub enum GkCommand {
    ConfirmGatekeeper,
    RejectGatekeeper(String),
    ConfirmRegistration {
        aliases: Option<Vec<Value>>,
        ttl: Option<u64>,
    },
    RejectRegistration {
        reason: String,
        duplicates: Option<Vec<Value>>,
    },
    ConfirmAdmission {
        destination: Option<String>,
        bandwidth: Option<u64>,
    },
    RejectAdmission(String),
    ConfirmLocation {
        destination: Option<String>,
    },
    RejectLocation(String),
}

fn destination_of(a: &Value) -> Result<Option<String>> {
    match a.get("destination") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.parse::<SocketAddr>().is_err() {
                h225::alias(s)?;
            }
            Ok(Some(s.clone()))
        }
        Some(other) => bail!("destination {other} is not a string"),
    }
}

pub fn parse_gk_command(a: &Value) -> Result<GkCommand> {
    let kind = a
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("missing 'type'"))?;
    Ok(match kind {
        CONFIRM_GATEKEEPER => GkCommand::ConfirmGatekeeper,
        REJECT_GATEKEEPER => {
            GkCommand::RejectGatekeeper(reason_of(a, GATEKEEPER_REASONS, "terminalExcluded")?)
        }
        CONFIRM_REGISTRATION => {
            let aliases = match a.get("aliases") {
                None | Some(Value::Null) => None,
                Some(v) => Some(h225::aliases(v)?),
            };
            let ttl = match a.get("time_to_live") {
                None | Some(Value::Null) => None,
                Some(t) => Some(
                    t.as_u64()
                        .filter(|t| (1..=gatekeeper::MAX_TTL_SECS).contains(t))
                        .ok_or_else(|| {
                            anyhow!("time_to_live is 1 to {} seconds", gatekeeper::MAX_TTL_SECS)
                        })?,
                ),
            };
            GkCommand::ConfirmRegistration { aliases, ttl }
        }
        REJECT_REGISTRATION => {
            let reason = reason_of(a, REGISTRATION_REASONS, "undefinedReason")?;
            let duplicates = match a.get("aliases") {
                Some(v) if reason == "duplicateAlias" => Some(h225::aliases(v)?),
                _ => None,
            };
            GkCommand::RejectRegistration { reason, duplicates }
        }
        CONFIRM_ADMISSION => GkCommand::ConfirmAdmission {
            destination: destination_of(a)?,
            bandwidth: match a.get("bandwidth") {
                None | Some(Value::Null) => None,
                Some(b) => Some(
                    b.as_u64()
                        .filter(|b| *b <= u32::MAX as u64)
                        .ok_or_else(|| anyhow!("bandwidth is a number of 100 bit/s units"))?,
                ),
            },
        },
        REJECT_ADMISSION => {
            GkCommand::RejectAdmission(reason_of(a, ADMISSION_REASONS, "requestDenied")?)
        }
        CONFIRM_LOCATION => GkCommand::ConfirmLocation {
            destination: destination_of(a)?,
        },
        REJECT_LOCATION => {
            GkCommand::RejectLocation(reason_of(a, LOCATION_REASONS, "requestDenied")?)
        }
        other => bail!("{other} is not an H.323 gatekeeper action"),
    })
}

fn confirm_gatekeeper_action() -> ActionDefinition {
    action(
        CONFIRM_GATEKEEPER,
        "Answer a GRQ with GCF: this gatekeeper will serve the endpoint, which normally \
         registers next.",
        vec![],
        json!({"type": CONFIRM_GATEKEEPER}),
    )
}

fn reject_gatekeeper_action() -> ActionDefinition {
    action(
        REJECT_GATEKEEPER,
        "Answer a GRQ with GRJ: this gatekeeper will not serve the endpoint.",
        vec![p(
            "reason",
            "string",
            &format!("One of {}", GATEKEEPER_REASONS.join(", ")),
            false,
        )],
        json!({"type": REJECT_GATEKEEPER, "reason": "terminalExcluded"}),
    )
}

fn confirm_registration_action() -> ActionDefinition {
    action(
        CONFIRM_REGISTRATION,
        "Answer an RRQ with RCF: register the endpoint. NetGet assigns its endpoint identifier \
         and remembers the registration (aliases → call signalling address) until its \
         time-to-live runs out; ARQ and LRQ then find it by alias.",
        vec![
            p(
                "aliases",
                "array",
                "The aliases it is registered under, as \"kind:value\" (h323-ID:alice, \
                 dialledDigits:1001) or bare values; default the ones it asked for. An alias \
                 another endpoint holds is refused.",
                false,
            ),
            p(
                "time_to_live",
                "number",
                "Seconds the registration lasts before the endpoint must refresh it \
                 (default: what it asked for, else the configured default)",
                false,
            ),
        ],
        json!({"type": CONFIRM_REGISTRATION, "aliases": ["h323-ID:alice", "dialledDigits:1001"], "time_to_live": 300}),
    )
}

fn reject_registration_action() -> ActionDefinition {
    action(
        REJECT_REGISTRATION,
        "Answer an RRQ with RRJ: refuse to register the endpoint.",
        vec![
            p(
                "reason",
                "string",
                &format!("One of {}", REGISTRATION_REASONS.join(", ")),
                false,
            ),
            p(
                "aliases",
                "array",
                "With reason duplicateAlias: the aliases already taken",
                false,
            ),
        ],
        json!({"type": REJECT_REGISTRATION, "reason": "securityDenial"}),
    )
}

fn confirm_admission_action() -> ActionDefinition {
    action(
        CONFIRM_ADMISSION,
        "Answer an ARQ with ACF: admit the call and tell the caller where to send its Setup. \
         The destination is an alias of a registered endpoint (its registered call signalling \
         address is used) or an explicit ip:port. Default: for answer_call the endpoint \
         itself, otherwise the first registered destination alias, else the address the ARQ \
         named.",
        vec![
            p(
                "destination",
                "string",
                "A registered alias (h323-ID:bob, 1002) or ip:port",
                false,
            ),
            p(
                "bandwidth",
                "number",
                "Bandwidth granted in units of 100 bit/s (default: what was asked, capped)",
                false,
            ),
        ],
        json!({"type": CONFIRM_ADMISSION, "destination": "h323-ID:bob"}),
    )
}

fn reject_admission_action() -> ActionDefinition {
    action(
        REJECT_ADMISSION,
        "Answer an ARQ with ARJ: the call may not proceed.",
        vec![p(
            "reason",
            "string",
            &format!("One of {}", ADMISSION_REASONS.join(", ")),
            false,
        )],
        json!({"type": REJECT_ADMISSION, "reason": "calledPartyNotRegistered"}),
    )
}

fn confirm_location_action() -> ActionDefinition {
    action(
        CONFIRM_LOCATION,
        "Answer an LRQ with LCF: say where the alias can be called. Destination as for \
         h323_confirm_admission; default the first registered destination alias.",
        vec![p(
            "destination",
            "string",
            "A registered alias or ip:port",
            false,
        )],
        json!({"type": CONFIRM_LOCATION, "destination": "h323-ID:bob"}),
    )
}

fn reject_location_action() -> ActionDefinition {
    action(
        REJECT_LOCATION,
        "Answer an LRQ with LRJ: this gatekeeper cannot locate the alias.",
        vec![p(
            "reason",
            "string",
            &format!("One of {}", LOCATION_REASONS.join(", ")),
            false,
        )],
        json!({"type": REJECT_LOCATION, "reason": "notRegistered"}),
    )
}

pub fn gatekeeper_actions() -> Vec<ActionDefinition> {
    vec![
        confirm_gatekeeper_action(),
        reject_gatekeeper_action(),
        confirm_registration_action(),
        reject_registration_action(),
        confirm_admission_action(),
        reject_admission_action(),
        confirm_location_action(),
        reject_location_action(),
    ]
}

pub static GRQ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_gatekeeper_request",
        "An endpoint is looking for a gatekeeper (GRQ). Accept with h323_confirm_gatekeeper or \
         refuse with h323_reject_gatekeeper; anything else is answered GRJ",
        json!({"type": CONFIRM_GATEKEEPER}),
    )
    .with_parameters(vec![
        p("from", "string", "Where the GRQ came from", true),
        p(
            "ras_address",
            "string",
            "The RAS address it asks to be answered on",
            false,
        ),
        p(
            "endpoint",
            "object",
            "What it is (terminal, gateway, mcu) and its product and version",
            true,
        ),
        p("aliases", "array", "Aliases it named", true),
        p(
            "requested_gatekeeper",
            "string",
            "The gatekeeper identifier it asked for, if any",
            false,
        ),
        p(
            "this_gatekeeper",
            "string",
            "This gatekeeper's identifier",
            true,
        ),
    ])
    .with_actions(vec![
        confirm_gatekeeper_action(),
        reject_gatekeeper_action(),
    ])
    .with_alternative_example(json!({"type": REJECT_GATEKEEPER, "reason": "terminalExcluded"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 GRQ from {from}")
            .with_debug("H.323 GRQ: {json(.)}"),
    )
});

pub static RRQ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_registration_request",
        "An endpoint asks to register (full RRQ). Register it with h323_confirm_registration \
         (choosing its aliases and time-to-live) or refuse with h323_reject_registration; \
         anything else is answered RRJ",
        json!({"type": CONFIRM_REGISTRATION}),
    )
    .with_parameters(vec![
        p("from", "string", "Where the RRQ came from", true),
        p(
            "aliases",
            "array",
            "The aliases it asks for, as kind:value",
            true,
        ),
        p(
            "call_signal_addresses",
            "array",
            "Where it takes calls (ip:port)",
            true,
        ),
        p("ras_addresses", "array", "Its RAS addresses", true),
        p(
            "endpoint",
            "object",
            "What it is (terminal, gateway, mcu) and its product and version",
            true,
        ),
        p(
            "vendor",
            "object",
            "endpointVendor: product and version",
            true,
        ),
        p(
            "requested_time_to_live",
            "number",
            "The time-to-live it asked for, if any",
            false,
        ),
        p(
            "already_registered_as",
            "string",
            "Its endpoint identifier if it is re-registering",
            false,
        ),
        p(
            "aliases_held_by_other_endpoints",
            "array",
            "Requested aliases another endpoint already holds",
            true,
        ),
        p(
            "registered_endpoints",
            "number",
            "How many endpoints are registered now",
            true,
        ),
    ])
    .with_actions(vec![
        confirm_registration_action(),
        reject_registration_action(),
    ])
    .with_alternative_example(json!({"type": REJECT_REGISTRATION, "reason": "securityDenial"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 RRQ from {from} for {aliases}")
            .with_debug("H.323 RRQ: {json(.)}"),
    )
});

pub static ARQ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_admission_request",
        "A registered endpoint asks to place (or, with answer_call, to answer) a call (ARQ). \
         Admit it with h323_confirm_admission, choosing the destination, or refuse with \
         h323_reject_admission; anything else is answered ARJ",
        json!({"type": CONFIRM_ADMISSION}),
    )
    .with_parameters(vec![
        p("from", "string", "Where the ARQ came from", true),
        p(
            "endpoint_id",
            "string",
            "The caller's endpoint identifier",
            true,
        ),
        p(
            "caller_aliases",
            "array",
            "The aliases it is registered under",
            true,
        ),
        p("source_info", "array", "srcInfo aliases in the ARQ", true),
        p("destination_aliases", "array", "Who it wants to call", true),
        p(
            "destination_address",
            "string",
            "An address it named directly, if any",
            false,
        ),
        p(
            "registered_destinations",
            "array",
            "Destination aliases that are registered here, with their endpoint and address",
            true,
        ),
        p(
            "answer_call",
            "boolean",
            "True when the endpoint asks to answer an incoming call",
            true,
        ),
        p(
            "bandwidth",
            "number",
            "Bandwidth asked for, in 100 bit/s units",
            true,
        ),
        p("call_reference", "number", "The call reference value", true),
        p("call_id", "string", "The call identifier (GUID, hex)", true),
        p(
            "conference_id",
            "string",
            "The conference identifier (hex)",
            true,
        ),
    ])
    .with_actions(vec![confirm_admission_action(), reject_admission_action()])
    .with_alternative_example(
        json!({"type": REJECT_ADMISSION, "reason": "calledPartyNotRegistered"}),
    )
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 ARQ from {endpoint_id} to {destination_aliases}")
            .with_debug("H.323 ARQ: {json(.)}"),
    )
});

pub static LRQ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_location_request",
        "Another gatekeeper or an endpoint asks where an alias can be called (LRQ). Answer with \
         h323_confirm_location or h323_reject_location; anything else is answered LRJ",
        json!({"type": CONFIRM_LOCATION}),
    )
    .with_parameters(vec![
        p("from", "string", "Where the LRQ came from", true),
        p(
            "destination_aliases",
            "array",
            "The aliases looked for",
            true,
        ),
        p("source_info", "array", "Who is asking, as aliases", true),
        p(
            "reply_address",
            "string",
            "Where the answer is wanted",
            false,
        ),
        p(
            "registered_destinations",
            "array",
            "Which of the aliases are registered here",
            true,
        ),
    ])
    .with_actions(vec![confirm_location_action(), reject_location_action()])
    .with_alternative_example(json!({"type": REJECT_LOCATION, "reason": "notRegistered"}))
    .with_log_template(
        LogTemplate::new().with_info("H.323 LRQ from {from} for {destination_aliases}"),
    )
});

fn gatekeeper_event_types() -> Vec<EventType> {
    vec![
        GRQ_EVENT.clone(),
        RRQ_EVENT.clone(),
        ARQ_EVENT.clone(),
        LRQ_EVENT.clone(),
    ]
}

#[derive(Clone, Default)]
pub struct H323GatekeeperProtocol;

impl H323GatekeeperProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for H323GatekeeperProtocol {
    fn protocol_name(&self) -> &'static str {
        "H323-Gatekeeper"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>H.225.0 RAS"
    }
    fn description(&self) -> &'static str {
        "H.323 gatekeeper (H.225.0 RAS) whose discovery, registration, admission and location answers the LLM decides"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an H.323 gatekeeper on port 1719; register anyone whose alias starts with 10, and admit calls only between registered endpoints"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "h323 gatekeeper",
            "h.323 gatekeeper",
            "gatekeeper",
            "h.225 ras",
            "h225 ras",
            "ras",
            "rrq",
            "arq",
        ]
    }
    fn group_name(&self) -> &'static str {
        "VoIP & Media"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_udp_port(1719)
            .connectionless()
            .answers_on_failure()
            .max_inbound_bytes(gatekeeper::MAX_RAS_DATAGRAM)
            .implementation(
                "Hand-written ALIGNED PER (X.691) interpreted over schema tables generated from \
                 the ITU H.225.0 (12/2009), H.235.0 and H.245 ASN.1 modules \
                 (scripts/h323_asn1_schema.py): every RAS message decodes, and NetGet answers \
                 GRQ, RRQ (full and keep-alive), URQ, ARQ, DRQ, LRQ, BRQ, IRR (IACK), RAI and \
                 retransmissions (cached answer, or RIP while the model decides). \
                 Registrations and admitted calls are bounded runtime state with time-to-live",
            )
            .llm_control(
                "GCF/GRJ, RCF (aliases, time-to-live)/RRJ, ACF (destination: a registered alias \
                 or ip:port, bandwidth)/ARJ and LCF/LRJ",
            )
            .e2e_testing(
                "tests/server/h323: Asterisk's chan_ooh323 (ooh323c) and H323Plus's simph323 \
                 each register with NetGet's gatekeeper and are admitted to call NetGet's \
                 endpoint; a refused registration shows in the peer's own log; tshark's h225 \
                 dissector reads every RAS message both ways from a live capture",
            )
            .notes(
                "Experimental: two independent H.323 implementations (ooh323c and H323Plus) \
                 complete registration and admission against it, but no fuzz target exists for \
                 its PER decoder and nobody has reviewed it against H.225.0 clause by clause. \
                 Direct call model only (ACF names the destination; the gatekeeper does not route \
                 signalling). No H.235 security: tokens are decoded past by length and never \
                 checked. No alternate gatekeepers, no inter-gatekeeper LRQ forwarding.",
            )
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "gatekeeper_id".into(),
                type_hint: "string".into(),
                description: "The gatekeeper identifier sent in GCF, RCF and rejects".into(),
                required: false,
                example: json!("NetGetGK"),
                default: Some(json!(DEFAULT_GATEKEEPER_ID)),
            },
            ParameterDefinition {
                name: "time_to_live".into(),
                type_hint: "number".into(),
                description: "Registration time-to-live in seconds when neither the endpoint nor \
                              the model chooses one"
                    .into(),
                required: false,
                example: json!(600),
                default: Some(json!(gatekeeper::DEFAULT_TTL_SECS)),
            },
            ParameterDefinition {
                name: "max_bandwidth".into(),
                type_hint: "number".into(),
                description: "The most bandwidth one call is granted, in units of 100 bit/s".into(),
                required: false,
                example: json!(1280),
                default: Some(json!(DEFAULT_MAX_BANDWIDTH)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        gatekeeper_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        gatekeeper_event_types()
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 1719,
                "base_stack": "H323-Gatekeeper",
                "startup_params": {"gatekeeper_id": "NetGetGK"},
                "instruction": "Accept every GRQ. Register endpoints whose aliases are digits starting with 10; refuse others with securityDenial. Admit calls to registered aliases only."
            }),
            json!({
                "type": "open_server",
                "port": 1719,
                "base_stack": "H323-Gatekeeper",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='h323_gatekeeper_request': a=[{'type':'h323_confirm_gatekeeper'}]\nelif t=='h323_registration_request': a=[{'type':'h323_confirm_registration'}]\nelif t=='h323_admission_request':\n    a=[{'type':'h323_confirm_admission'}] if e.get('registered_destinations') or e.get('answer_call') else [{'type':'h323_reject_admission','reason':'calledPartyNotRegistered'}]\nelif t=='h323_location_request': a=[{'type':'h323_reject_location','reason':'notRegistered'}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 1719,
                "base_stack": "H323-Gatekeeper",
                "event_handlers": [
                    {"event_pattern": "h323_gatekeeper_request", "handler": {"type": "static", "actions": [{"type": CONFIRM_GATEKEEPER}]}},
                    {"event_pattern": "h323_registration_request", "handler": {"type": "static", "actions": [{"type": CONFIRM_REGISTRATION, "time_to_live": 300}]}},
                    {"event_pattern": "h323_admission_request", "handler": {"type": "static", "actions": [{"type": CONFIRM_ADMISSION}]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": [{"type": REJECT_LOCATION, "reason": "notRegistered"}]}}
                ]
            }),
        )
    }
}

impl Server for H323GatekeeperProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let gatekeeper_id = params
                .map(|p| p.get_optional_string("gatekeeper_id"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| DEFAULT_GATEKEEPER_ID.to_string());
            gatekeeper::validate_gatekeeper_id(&gatekeeper_id)?;
            let default_ttl = params
                .map(|p| p.get_optional_u64("time_to_live"))
                .transpose()?
                .flatten()
                .unwrap_or(gatekeeper::DEFAULT_TTL_SECS);
            anyhow::ensure!(
                (1..=gatekeeper::MAX_TTL_SECS).contains(&default_ttl),
                "time_to_live is 1 to {} seconds",
                gatekeeper::MAX_TTL_SECS
            );
            let max_bandwidth = params
                .map(|p| p.get_optional_u64("max_bandwidth"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_MAX_BANDWIDTH)
                .min(u32::MAX as u64);
            gatekeeper::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                gatekeeper::GatekeeperConfig {
                    gatekeeper_id,
                    default_ttl,
                    max_bandwidth,
                },
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        parse_gk_command(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Endpoint (called side)
// ---------------------------------------------------------------------------------------------

/// One call-control decision on the called side.
#[derive(Debug, Clone)]
pub enum CallCommand {
    Proceeding,
    Alerting,
    Connect {
        codecs: Vec<h245::Codec>,
        display: Option<String>,
    },
    Release {
        cause: u8,
        reason: Option<String>,
    },
    Forward {
        address: Option<SocketAddr>,
        aliases: Vec<Value>,
    },
}

impl CallCommand {
    pub fn name(&self) -> &'static str {
        match self {
            CallCommand::Proceeding => "CallProceeding",
            CallCommand::Alerting => "Alerting",
            CallCommand::Connect { .. } => "Connect",
            CallCommand::Release { .. } => "ReleaseComplete",
            CallCommand::Forward { .. } => "Facility (callForwarded)",
        }
    }
}

/// A display string the model wrote: refused, not rewritten, if it holds a control character.
pub fn display_of(a: &Value) -> Result<Option<String>> {
    match a.get("display") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() || s.chars().count() > 80 || !s.is_ascii() {
                bail!("display is 1 to 80 ASCII characters");
            }
            if crate::utils::sanitize::has_controls(s) {
                bail!("display contains a control character");
            }
            Ok(Some(s.clone()))
        }
        Some(other) => bail!("display {other} is not a string"),
    }
}

/// A Q.850 cause and optional H.225.0 reason from a release action.
pub fn release_of(a: &Value) -> Result<(u8, Option<String>)> {
    let c = match a.get("cause") {
        None | Some(Value::Null) => cause::NORMAL_CLEARING,
        Some(v) => v
            .as_u64()
            .filter(|c| (1..=127).contains(c))
            .map(|c| c as u8)
            .ok_or_else(|| anyhow!("cause is a Q.850 cause value, 1 to 127"))?,
    };
    let reason = match a.get("reason") {
        None | Some(Value::Null) => None,
        Some(Value::String(r)) => {
            if !RELEASE_REASONS.contains(&r.as_str()) {
                bail!("reason {r:?} is not one of {RELEASE_REASONS:?}");
            }
            Some(r.clone())
        }
        Some(other) => bail!("reason {other} is not a string"),
    };
    Ok((c, reason))
}

pub fn parse_call_command(a: &Value) -> Result<CallCommand> {
    let kind = a
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("missing 'type'"))?;
    Ok(match kind {
        CALL_PROCEEDING => CallCommand::Proceeding,
        ALERTING => CallCommand::Alerting,
        CONNECT => CallCommand::Connect {
            codecs: match a.get("codec") {
                None | Some(Value::Null) => Vec::new(),
                v => call::codecs_from(v)?,
            },
            display: display_of(a)?,
        },
        RELEASE_COMPLETE => {
            let (cause, reason) = release_of(a)?;
            CallCommand::Release { cause, reason }
        }
        FORWARD_CALL => {
            let to = a
                .get("destination")
                .and_then(|d| d.as_str())
                .context("destination (an alias or ip:port) is required")?;
            match to.parse::<SocketAddr>() {
                Ok(addr) => CallCommand::Forward {
                    address: Some(addr),
                    aliases: Vec::new(),
                },
                Err(_) => CallCommand::Forward {
                    address: None,
                    aliases: vec![h225::alias(to)?],
                },
            }
        }
        other => bail!("{other} is not an H.323 call action"),
    })
}

fn proceeding_action() -> ActionDefinition {
    action(
        CALL_PROCEEDING,
        "Send CallProceeding: the call is being handled (stops the caller's Setup timer).",
        vec![],
        json!({"type": CALL_PROCEEDING}),
    )
}

fn alerting_action() -> ActionDefinition {
    action(
        ALERTING,
        "Send Alerting: the called party is ringing. A call left ringing is released after \
         two minutes unless h323_connect follows (later, from the dashboard or MCP).",
        vec![],
        json!({"type": ALERTING}),
    )
}

fn connect_action() -> ActionDefinition {
    action(
        CONNECT,
        "Answer the call (Connect). NetGet accepts the caller's fastStart offer in the first \
         codec both sides have and runs tunnelled H.245 (capability exchange, master-slave \
         determination, logical channels) itself.",
        vec![
            p(
                "codec",
                "string",
                "Preferred codec, g711u or g711a, or a list in order (default: as configured)",
                false,
            ),
            p(
                "display",
                "string",
                "Display name sent with the Connect (ASCII, up to 80 characters)",
                false,
            ),
        ],
        json!({"type": CONNECT, "codec": "g711u"}),
    )
}

pub fn release_action() -> ActionDefinition {
    action(
        RELEASE_COMPLETE,
        "End or refuse the call with Release Complete.",
        vec![
            p(
                "cause",
                "number",
                "Q.850 cause: 16 normal clearing (default), 17 user busy, 19 no answer, 21 call \
                 rejected, 1 unallocated number, 31 normal unspecified",
                false,
            ),
            p(
                "reason",
                "string",
                &format!("H.225.0 reason, one of {}", RELEASE_REASONS.join(", ")),
                false,
            ),
        ],
        json!({"type": RELEASE_COMPLETE, "cause": 17, "reason": "inConf"}),
    )
}

fn forward_action() -> ActionDefinition {
    action(
        FORWARD_CALL,
        "Deflect the call elsewhere: Facility (callForwarded) naming the new destination, then \
         Release Complete. The caller places a new call there.",
        vec![p(
            "destination",
            "string",
            "An alias (h323-ID:bob, 1002) or ip:port to call instead",
            true,
        )],
        json!({"type": FORWARD_CALL, "destination": "h323-ID:voicemail"}),
    )
}

pub fn endpoint_actions() -> Vec<ActionDefinition> {
    vec![
        proceeding_action(),
        alerting_action(),
        connect_action(),
        release_action(),
        forward_action(),
    ]
}

pub static SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_setup",
        "A caller sent Setup. Answer with h323_connect (h323_call_proceeding and h323_alerting \
         may come first), refuse with h323_release_complete, or deflect with h323_forward_call. \
         An answer with none of these releases the call",
        json!({"type": CONNECT}),
    )
    .with_parameters(vec![
        p("remote", "string", "The caller's address", true),
        p("crv", "number", "The Q.931 call reference value", true),
        p(
            "call_id",
            "string",
            "The H.225.0 call identifier (GUID, hex)",
            true,
        ),
        p(
            "conference_id",
            "string",
            "The conference identifier (hex)",
            true,
        ),
        p(
            "calling_number",
            "string",
            "Calling party number IE, if present",
            false,
        ),
        p(
            "called_number",
            "string",
            "Called party number IE, if present",
            false,
        ),
        p("display", "string", "Display IE, if present", false),
        p(
            "source_aliases",
            "array",
            "The caller's aliases (kind:value)",
            true,
        ),
        p(
            "destination_aliases",
            "array",
            "Who it is calling (kind:value)",
            true,
        ),
        p(
            "source_endpoint",
            "object",
            "What the caller is (terminal, gateway, ...) and its product and version",
            true,
        ),
        p(
            "source_call_signal_address",
            "string",
            "The caller's signalling address, if given",
            false,
        ),
        p(
            "fast_start",
            "array",
            "fastStart proposals: direction and codec of each",
            true,
        ),
        p(
            "h245_tunnelling",
            "boolean",
            "Whether the caller tunnels H.245",
            true,
        ),
        p(
            "h245_address",
            "string",
            "A separate H.245 address the caller offered, if any",
            false,
        ),
        p(
            "endpoint_identifier",
            "string",
            "The caller's endpoint identifier at its gatekeeper, if given",
            false,
        ),
    ])
    .with_actions(endpoint_actions())
    .with_alternative_example(
        json!({"type": RELEASE_COMPLETE, "cause": 21, "reason": "destinationRejection"}),
    )
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 Setup from {remote}: {calling_number} → {called_number}")
            .with_debug("H.323 Setup: {json(.)}"),
    )
});

pub static USER_INPUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_user_input",
        "The caller sent user input (DTMF) over H.245 during the call. Hang up with \
         h323_release_complete, or do nothing",
        json!({"type": RELEASE_COMPLETE}),
    )
    .with_parameters(vec![
        p("input", "string", "The digit or text", true),
        p("call_id", "string", "The call identifier", true),
        p("state", "string", "The call's state", true),
    ])
    .with_actions(vec![release_action()])
    .with_log_template(LogTemplate::new().with_info("H.323 user input {input}"))
});

#[derive(Clone, Default)]
pub struct H323EndpointProtocol;

impl H323EndpointProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn codecs_parameter() -> ParameterDefinition {
    ParameterDefinition {
        name: "codecs".into(),
        type_hint: "array".into(),
        description: "Audio codecs NetGet negotiates, in order of preference: g711u, g711a".into(),
        required: false,
        example: json!(["g711a", "g711u"]),
        default: Some(json!(h245::ALL_CODECS
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>())),
    }
}

pub fn codecs_from_params(
    params: Option<&crate::protocol::StartupParams>,
) -> Result<Vec<h245::Codec>> {
    let v = params
        .map(|p| p.get_optional_array("codecs"))
        .transpose()?
        .flatten();
    call::codecs_from(v.map(|a| Value::Array(a.clone())).as_ref())
}

impl Protocol for H323EndpointProtocol {
    fn protocol_name(&self) -> &'static str {
        "H323"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TPKT>Q.931>H.225.0"
    }
    fn description(&self) -> &'static str {
        "H.323 endpoint (H.225.0 call signalling over Q.931) that answers, rejects or forwards calls as the LLM decides, with fastStart and tunnelled H.245 for G.711"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an H.323 endpoint on port 1720; answer calls to 1001 and reject everything else as busy"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "h323",
            "h.323",
            "h.225",
            "h225",
            "q.931",
            "q931",
            "h.245",
            "voip",
            "video conferencing",
            "netmeeting",
        ]
    }
    fn group_name(&self) -> &'static str {
        "VoIP & Media"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(1720)
            .answers_on_failure()
            .max_inbound_bytes(super::q931::MAX_TPKT)
            .implementation(
                "TPKT and the H.225.0 profile of Q.931 by hand, H.225.0 UUIEs and H.245 in \
                 hand-written ALIGNED PER over schema tables generated from the ITU ASN.1 \
                 (scripts/h323_asn1_schema.py). The called side of one call per connection: \
                 Setup → CallProceeding/Alerting/Connect or Release Complete or a Facility \
                 forward; fastStart answered in G.711; tunnelled H.245 (TerminalCapabilitySet, \
                 MasterSlaveDetermination, OpenLogicalChannel, CloseLogicalChannel, \
                 RoundTripDelay, EndSession, user input); RTP/RTCP sockets bound and counted, \
                 no media sent",
            )
            .llm_control(
                "Whether each call is answered (and in which codec), left ringing, rejected with \
                 which Q.850 cause and H.225.0 reason, or forwarded to an alias or address; \
                 hanging up on user input",
            )
            .e2e_testing(
                "tests/server/h323: Asterisk's chan_ooh323 (ooh323c) and H323Plus's simph323 \
                 call NetGet's endpoint and see the call connected with fastStart media, or \
                 released with the model's cause; tshark's q931, h225 and h245 dissectors read \
                 every message both ways from a live capture",
            )
            .notes(
                "Experimental: two independent H.323 stacks (ooh323c and H323Plus) complete \
                 calls with it in tests that fail rather than skip, but no fuzz target exists for \
                 the PER decoder and nobody has reviewed the H.245 subset against the \
                 specification. No separate H.245 channel (tunnelling or fastStart only; a \
                 caller that offers neither still connects at the Q.931 level, with no media \
                 negotiated). G.711 only. No media is sent and none is decoded. No H.235 \
                 security, no H.450 supplementary services, no overlap sending.",
            )
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![codecs_parameter()]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        endpoint_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![SETUP_EVENT.clone(), USER_INPUT_EVENT.clone()]
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 1720,
                "base_stack": "H323",
                "instruction": "Answer calls whose called number or destination alias is 1001. Reject everything else with cause 17 (busy)."
            }),
            json!({
                "type": "open_server",
                "port": 1720,
                "base_stack": "H323",
                "event_handlers": [{
                    "event_pattern": "h323_setup",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ne=json.load(sys.stdin)['event']\nwanted='dialledDigits:1001' in e.get('destination_aliases',[]) or e.get('called_number')=='1001'\na=[{'type':'h323_alerting'},{'type':'h323_connect'}] if wanted else [{'type':'h323_release_complete','cause':17,'reason':'inConf'}]\nprint(json.dumps({'actions':a}))"
                    }
                }, {"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
            }),
            json!({
                "type": "open_server",
                "port": 1720,
                "base_stack": "H323",
                "event_handlers": [
                    {"event_pattern": "h323_setup", "handler": {"type": "static", "actions": [
                        {"type": CALL_PROCEEDING}, {"type": ALERTING}, {"type": CONNECT, "codec": "g711u"}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                ]
            }),
        )
    }
}

impl Server for H323EndpointProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            let codecs = codecs_from_params(ctx.startup_params.as_ref())?;
            endpoint::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                endpoint::EndpointConfig { codecs },
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        parse_call_command(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }
}
