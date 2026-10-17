//! What the model can do as an H.323 endpoint that places calls: register (and re-register or
//! unregister) with a gatekeeper, place a call — admission first when registered — and hang
//! up. Every result comes back decoded: the gatekeeper's confirm or reject with its reason,
//! the call's progress, the codec and media addresses agreed, and who released it and why.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::h323::actions::{codecs_parameter, display_of, p};
use crate::server::h323::{call, gatekeeper, h225};
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::LazyLock;

pub const PLACE_CALL: &str = "h323_place_call";
pub const HANGUP: &str = "h323_hangup";
pub const REGISTER: &str = "h323_register";
pub const UNREGISTER: &str = "h323_unregister";

/// The alias NetGet registers under when none is configured.
pub const DEFAULT_ALIAS: &str = "h323-ID:NetGet";
/// What the remote address is when `mode` is not given: decided by its port.
pub const DEFAULT_MODE: &str = "auto";
/// Whether to send GRQ before RRQ when none is configured.
pub const DEFAULT_DISCOVER: bool = true;

#[derive(Debug, Clone)]
pub enum ClientCommand {
    PlaceCall {
        destination: String,
        codecs: Vec<crate::server::h323::h245::Codec>,
        display: Option<String>,
    },
    Hangup {
        cause: u8,
        reason: Option<String>,
    },
    Register {
        aliases: Option<Vec<Value>>,
        ttl: Option<u64>,
    },
    Unregister,
}

impl ClientCommand {
    pub fn name(&self) -> &'static str {
        match self {
            ClientCommand::PlaceCall { .. } => PLACE_CALL,
            ClientCommand::Hangup { .. } => HANGUP,
            ClientCommand::Register { .. } => REGISTER,
            ClientCommand::Unregister => UNREGISTER,
        }
    }
}

pub fn parse_command(a: &Value) -> Result<ClientCommand> {
    let kind = a
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("missing 'type'"))?;
    Ok(match kind {
        PLACE_CALL => {
            let destination = a
                .get("destination")
                .and_then(|d| d.as_str())
                .context("destination (an alias, a number or ip:port) is required")?
                .to_string();
            if destination.parse::<SocketAddr>().is_err() {
                h225::alias(&destination)?;
            }
            ClientCommand::PlaceCall {
                destination,
                codecs: call::codecs_from(a.get("codec"))?,
                display: display_of(a)?,
            }
        }
        HANGUP => {
            let (cause, reason) = crate::server::h323::actions::release_of(a)?;
            ClientCommand::Hangup { cause, reason }
        }
        REGISTER => ClientCommand::Register {
            aliases: match a.get("aliases") {
                None | Some(Value::Null) => None,
                Some(v) => Some(h225::aliases(v)?),
            },
            ttl: match a.get("time_to_live") {
                None | Some(Value::Null) => None,
                Some(t) => Some(
                    t.as_u64()
                        .filter(|t| (1..=gatekeeper::MAX_TTL_SECS).contains(t))
                        .ok_or_else(|| {
                            anyhow!("time_to_live is 1 to {} seconds", gatekeeper::MAX_TTL_SECS)
                        })?,
                ),
            },
        },
        UNREGISTER => ClientCommand::Unregister,
        other => bail!("{other} is not an H.323 client action"),
    })
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
            LogTemplate::new()
                .with_info(format!("H.323 {name}"))
                .with_debug(format!("H.323 {name}: {{json(.)}}")),
        ),
    }
}

pub fn client_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            PLACE_CALL,
            "Place a call. Registered with a gatekeeper, NetGet asks admission first (ARQ) and \
             calls the address the ACF names; otherwise it calls the remote endpoint directly. \
             It offers G.711 by fastStart and tunnels H.245. The outcome arrives as \
             h323_call_connected, h323_call_released, h323_call_forwarded or h323_call_failed. \
             One call at a time.",
            vec![
                p(
                    "destination",
                    "string",
                    "Who to call: an alias (h323-ID:bob), a number (1002) or ip:port",
                    true,
                ),
                p(
                    "codec",
                    "string",
                    "g711u or g711a, or a list in order of preference (default both)",
                    false,
                ),
                p(
                    "display",
                    "string",
                    "Display name sent in the Setup (ASCII, up to 80 characters)",
                    false,
                ),
            ],
            json!({"type": PLACE_CALL, "destination": "1002"}),
        ),
        action(
            HANGUP,
            "Hang up the current call with Release Complete (and tell the gatekeeper, DRQ).",
            vec![
                p(
                    "cause",
                    "number",
                    "Q.850 cause (default 16, normal clearing)",
                    false,
                ),
                p(
                    "reason",
                    "string",
                    "H.225.0 release reason, e.g. undefinedReason",
                    false,
                ),
            ],
            json!({"type": HANGUP}),
        ),
        action(
            REGISTER,
            "Register (again) with the gatekeeper (RRQ), optionally under other aliases. The \
             result arrives as h323_registration.",
            vec![
                p(
                    "aliases",
                    "array",
                    "Aliases as kind:value or bare values (default: the configured ones)",
                    false,
                ),
                p(
                    "time_to_live",
                    "number",
                    "Time-to-live to ask for, in seconds",
                    false,
                ),
            ],
            json!({"type": REGISTER, "aliases": ["h323-ID:netget", "1003"]}),
        ),
        action(
            UNREGISTER,
            "Unregister from the gatekeeper (URQ). The result arrives as h323_registration.",
            vec![],
            json!({"type": UNREGISTER}),
        ),
    ]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_client_ready",
        "The client is up. With a gatekeeper, registration has run and its result is here \
         (confirmed or rejected, with the reason). Place a call with h323_place_call, \
         (re)register, or do nothing",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p(
            "mode",
            "string",
            "gatekeeper or endpoint: what the remote address is",
            true,
        ),
        p("remote", "string", "The remote address", true),
        p(
            "gatekeeper",
            "object",
            "GCF/GRJ: the gatekeeper's identifier and RAS address, or the reject reason",
            false,
        ),
        p(
            "registration",
            "object",
            "RCF/RRJ: endpoint identifier, aliases, time-to-live, or the reject reason",
            false,
        ),
        p(
            "local_call_signal_address",
            "string",
            "Where this endpoint takes calls",
            false,
        ),
    ])
    .with_actions(client_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 client ready ({mode}) at {remote}")
            .with_debug("H.323 client ready: {json(.)}"),
    )
});

pub static REGISTRATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_registration",
        "The gatekeeper answered a registration or unregistration request (RCF/RRJ, UCF/URJ), \
         or unregistered this endpoint itself (URQ)",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p(
            "request",
            "string",
            "RRQ, URQ, or gatekeeper_urq when the gatekeeper ended it",
            true,
        ),
        p("result", "string", "confirmed, rejected or timeout", true),
        p("reason", "string", "The reject reason, if rejected", false),
        p(
            "endpoint_id",
            "string",
            "The endpoint identifier assigned",
            false,
        ),
        p("aliases", "array", "The aliases registered", false),
        p(
            "time_to_live",
            "number",
            "Seconds before NetGet must refresh it",
            false,
        ),
    ])
    .with_actions(client_actions())
    .with_log_template(LogTemplate::new().with_info("H.323 {request}: {result} {reason}"))
});

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_call_connected",
        "The called endpoint answered (Connect). The codec and media addresses agreed and how \
         are in media. Hang up with h323_hangup, or leave the call up",
        json!({"type": HANGUP}),
    )
    .with_parameters(vec![
        p(
            "destination",
            "string",
            "The destination the call was placed to: an alias, a number or ip:port",
            true,
        ),
        p(
            "address",
            "string",
            "The call signalling address called",
            true,
        ),
        p(
            "progress",
            "array",
            "Messages the callee sent before Connect",
            true,
        ),
        p(
            "call",
            "object",
            "crv, call and conference identifiers, H.245 state and media",
            true,
        ),
        p(
            "admission",
            "object",
            "The gatekeeper's ACF, when admission ran",
            false,
        ),
    ])
    .with_actions(client_actions())
    .with_log_template(LogTemplate::new().with_info("H.323 call to {destination} connected"))
});

pub static RELEASED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_call_released",
        "The call ended: the callee released it (Release Complete, with its Q.850 cause and \
         H.225.0 reason), this client hung up, or the connection closed",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p(
            "destination",
            "string",
            "The destination the call was placed to: an alias, a number or ip:port",
            true,
        ),
        p("released_by", "string", "remote, local or connection", true),
        p("cause", "number", "Q.850 cause, if any", false),
        p("reason", "string", "H.225.0 release reason, if any", false),
        p(
            "reached",
            "string",
            "How far the call got: offered, proceeding, alerting, connected",
            true,
        ),
        p("progress", "array", "Messages the callee sent", true),
        p(
            "call",
            "object",
            "The call's identifiers, H.245 state and media",
            true,
        ),
        p(
            "disengage",
            "string",
            "The gatekeeper's answer to DRQ, when registered",
            false,
        ),
    ])
    .with_actions(client_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("H.323 call to {destination} released by {released_by}, cause {cause}"),
    )
});

pub static FAILED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_call_failed",
        "A call could not be placed: the gatekeeper refused admission (ARJ, with its reason), \
         did not answer, or the destination could not be reached",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p("destination", "string", "The destination the call was placed to: an alias, a number or ip:port", true),
        p("stage", "string", "admission, connect or signalling", true),
        p("reason", "string", "Why the call could not be placed: the ARJ reason, no answer from the gatekeeper, or the connect error", true),
    ])
    .with_actions(client_actions())
    .with_log_template(LogTemplate::new().with_info("H.323 call to {destination} failed at {stage}: {reason}"))
});

pub static FORWARDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_call_forwarded",
        "The callee deflected the call (Facility callForwarded / routeCallToGatekeeper) and \
         named somewhere else to call. Call it with h323_place_call, or do nothing",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p(
            "destination",
            "string",
            "The destination the call was placed to: an alias, a number or ip:port",
            true,
        ),
        p(
            "forward_address",
            "string",
            "The address named, if any",
            false,
        ),
        p(
            "forward_aliases",
            "array",
            "The aliases named, if any",
            true,
        ),
    ])
    .with_actions(client_actions())
    .with_log_template(LogTemplate::new().with_info("H.323 call to {destination} forwarded"))
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_error",
        "An action could not be carried out; nothing was sent for it",
        json!({"type": PLACE_CALL, "destination": "1002"}),
    )
    .with_parameters(vec![
        p("action", "string", "The action's type", true),
        p("message", "string", "Why it was refused", true),
    ])
    .with_actions(client_actions())
    .with_log_template(LogTemplate::new().with_info("H.323 {action} refused: {message}"))
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "h323_client_stopped",
        "The client stopped. Nothing more can be sent",
        json!({"type": "show_message", "message": "H.323 client stopped"}),
    )
    .with_parameters(vec![p(
        "reason",
        "string",
        "Why the client stopped: the operator stopped it, or its session ended",
        true,
    )])
    .with_no_actions()
    .with_log_template(LogTemplate::new().with_info("H.323 client stopped: {reason}"))
});

#[derive(Default)]
pub struct H323ClientProtocol;

impl H323ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for H323ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "H323"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TPKT>Q.931>H.225.0"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "h323",
            "h.323",
            "h.225",
            "q.931",
            "gatekeeper",
            "h323 client",
        ]
    }
    fn description(&self) -> &'static str {
        "H.323 endpoint that registers with a gatekeeper (GRQ/RRQ), asks admission (ARQ), places calls with fastStart G.711 and tunnelled H.245, and hangs up, reporting every result decoded"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        client_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            REGISTRATION_EVENT.clone(),
            CONNECTED_EVENT.clone(),
            RELEASED_EVENT.clone(),
            FAILED_EVENT.clone(),
            FORWARDED_EVENT.clone(),
            ERROR_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "mode".into(),
                type_hint: "string".into(),
                description: "What remote_addr is: gatekeeper (register and ask admission, RAS on \
                              UDP), endpoint (call it directly), or auto (gatekeeper on port 1719, \
                              endpoint otherwise)"
                    .into(),
                required: false,
                example: json!("gatekeeper"),
                default: Some(json!(DEFAULT_MODE)),
            },
            ParameterDefinition {
                name: "aliases".into(),
                type_hint: "array".into(),
                description: "Aliases to register under and call from, as kind:value \
                              (h323-ID:alice, dialledDigits:1001) or bare values"
                    .into(),
                required: false,
                example: json!(["h323-ID:netget", "1003"]),
                default: Some(json!([DEFAULT_ALIAS])),
            },
            ParameterDefinition {
                name: "time_to_live".into(),
                type_hint: "number".into(),
                description: "Registration time-to-live to ask the gatekeeper for, in seconds"
                    .into(),
                required: false,
                example: json!(120),
                default: Some(json!(gatekeeper::DEFAULT_TTL_SECS)),
            },
            ParameterDefinition {
                name: "discover".into(),
                type_hint: "boolean".into(),
                description: "Send GRQ before registering (some gatekeepers require discovery)"
                    .into(),
                required: false,
                example: json!(false),
                default: Some(json!(DEFAULT_DISCOVER)),
            },
            codecs_parameter(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The H.323 server's PER codec, Q.931 framing and call leg as the calling side: GRQ, RRQ (full, then keep-alive before the time-to-live runs out), ARQ, DRQ and URQ over a RAS socket, Setup with fastStart G.711 proposals and tunnelled H.245 over TPKT, Release Complete; IRQ from the gatekeeper answered with IRR, its URQ with UCF. Incoming calls on the registered call signalling address are refused")
            .llm_control("When to register and under which aliases, who to call (alias, number or address) in which codec, when to hang up, and what to do after a reject, a forward or a release")
            .e2e_testing("tests/client/h323: GNU Gatekeeper (H323Plus) confirms NetGet's GRQ and RRQ, lists it in its status port's registrations and admits its ARQ; Asterisk's chan_ooh323 (ooh323c) and H323Plus's simph323 answer NetGet's Setup and the call connects with fastStart media; tshark's h225, q931 and h245 dissectors read every message both ways")
            .notes("Experimental: one gatekeeper implementation (GNU Gatekeeper) and two call peers (ooh323c, H323Plus) drive it in tests that fail rather than skip, but nobody has reviewed it against H.225.0 and its pair job had not run in CI when it landed. One call at a time. No H.235 security, no separate H.245 channel, G.711 only, no media sent.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Register with the H.323 gatekeeper at 127.0.0.1:1719 as 1003, call 1002, and hang up once it connects"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "H323", "remote_addr": "127.0.0.1:1719",
            "startup_params": {"aliases": ["1003"]},
            "instruction": "Once registered, call 1002. When it connects, hang up and report the codec agreed."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "h323_client_ready", "handler": {"type": "static", "actions": [
                {"type": PLACE_CALL, "destination": "1002"}
            ]}},
            {"event_pattern": "h323_call_connected", "handler": {"type": "static", "actions": [
                {"type": HANGUP}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0] = json!({"event_pattern": "h323_client_ready", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nreg=(e.get('registration') or {})\na=[{'type':'h323_place_call','destination':'1002'}] if reg.get('result')!='rejected' else [{'type':'h323_register','aliases':['1004']}]\nprint(json.dumps({'actions':a}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "VoIP & Media"
    }
}

impl Client for H323ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::connect(ctx))
    }

    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        parse_command(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
