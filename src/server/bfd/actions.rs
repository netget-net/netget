//! What the model decides for a BFD speaker: which peers get a session and with what timers,
//! and what to do when a session changes state. The packets themselves — every few hundred
//! milliseconds, with jitter, Poll and Final — are Rust's job (`runner.rs`); a model cannot
//! keep a 300 ms clock.
use super::packet;
use super::session::{self, Timers};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT: &str = "bfd_accept_session";
pub const DEFAULT_AUTH_KEY_ID: u8 = 1;
/// Sessions one server holds at once; a new peer past this is not asked about.
pub const MAX_SESSIONS: usize = 64;

#[derive(Default, Clone)]
pub struct BfdProtocol;

impl BfdProtocol {
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

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let info = match name {
        "bfd_accept_session" => "-> BFD session accepted".to_string(),
        "bfd_set_timers" => {
            "-> BFD timers tx {desired_min_tx_ms} ms rx {required_min_rx_ms} ms".to_string()
        }
        "bfd_admin_down" => "-> BFD session AdminDown".to_string(),
        "bfd_admin_up" => "-> BFD session back from AdminDown".to_string(),
        other => format!("-> BFD {}", other.trim_start_matches("bfd_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn timer_params() -> Vec<Parameter> {
    vec![
        p("desired_min_tx_ms", "number", "How often this side wants to send, in ms (10-60000; at least 1000 is sent while the session is not Up)", false),
        p("required_min_rx_ms", "number", "The fastest this side accepts packets, in ms (10-60000)", false),
        p("detect_mult", "number", "Packets the peer may miss before the session is declared down (1-255)", false),
    ]
}

pub fn accept_action() -> ActionDefinition {
    action(
        ACCEPT,
        "Bring up a BFD session with this peer, optionally with its own timers (otherwise the server's). To refuse, answer nothing: BFD has no refusal message.",
        timer_params(),
        json!({"type":ACCEPT,"desired_min_tx_ms":300,"required_min_rx_ms":300,"detect_mult":3}),
    )
}

pub fn set_timers_action() -> ActionDefinition {
    action(
        "bfd_set_timers",
        "Change this session's timers; while Up the change is negotiated with a Poll Sequence.",
        timer_params(),
        json!({"type":"bfd_set_timers","desired_min_tx_ms":500,"required_min_rx_ms":500,"detect_mult":3}),
    )
}

pub fn admin_down_action() -> ActionDefinition {
    action(
        "bfd_admin_down",
        "Take this session administratively down; the peer sees AdminDown and goes Down.",
        vec![p(
            "diag",
            "string",
            "Diagnostic to send, e.g. administratively_down (default) or path_down",
            false,
        )],
        json!({"type":"bfd_admin_down","diag":"administratively_down"}),
    )
}

pub fn admin_up_action() -> ActionDefinition {
    action(
        "bfd_admin_up",
        "Return an AdminDown session to Down, so it comes back up with the peer.",
        vec![],
        json!({"type":"bfd_admin_up"}),
    )
}

pub fn session_actions() -> Vec<ActionDefinition> {
    vec![set_timers_action(), admin_down_action(), admin_up_action()]
}

pub static SESSION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bfd_session_request",
        "A BFD peer with no session here is sending Control packets. Answer bfd_accept_session to bring a session up, or nothing to ignore it.",
        accept_action().example.clone(),
    )
    .with_parameters(vec![
        p("peer", "string", "The peer's IP address", true),
        p("peer_discriminator", "number", "The peer's My Discriminator for the session", true),
        p("peer_state", "string", "The state the peer reports: Down, Init, Up or AdminDown", true),
        p("desired_min_tx_ms", "number", "How often the peer wants to send, in ms", true),
        p("required_min_rx_ms", "number", "The fastest the peer accepts packets, in ms", true),
        p("detect_mult", "number", "The peer's detection multiplier", true),
        p("authentication", "string", "The authentication type the peer used (simple, keyed_md5, keyed_sha1, ...), or null", false),
        p("multihop", "boolean", "Whether this is a multihop session (RFC 5883) rather than single-hop (RFC 5881)", true),
    ])
    .with_actions(vec![accept_action()])
});

pub fn state_params() -> Vec<Parameter> {
    vec![
        p("peer", "string", "The peer's IP address", true),
        p("state", "string", "The session's new state: AdminDown, Down, Init or Up", true),
        p("previous_state", "string", "The state before", true),
        p("diag", "string", "Why, as a diagnostic name, e.g. control_detection_time_expired, neighbor_signaled_session_down", true),
        p("remote_state", "string", "The state the peer last reported", true),
        p("local_discriminator", "number", "This side's discriminator", true),
        p("remote_discriminator", "number", "The peer's discriminator (0 once the peer has gone silent)", true),
        p("tx_interval_ms", "number", "The interval this side is sending at", true),
        p("detection_time_ms", "number", "How long silence takes to bring the session down", true),
        p("remote_desired_min_tx_ms", "number", "How often the peer wants to send", true),
        p("remote_required_min_rx_ms", "number", "The fastest the peer accepts packets", true),
    ]
}

pub static STATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bfd_session_state",
        "A BFD session changed state. Optionally answer bfd_set_timers, bfd_admin_down or bfd_admin_up.",
        set_timers_action().example.clone(),
    )
    .with_parameters(state_params())
    .with_actions(session_actions())
});

/// The authentication startup parameters, shared with the client.
pub fn auth_params() -> Vec<ParameterDefinition> {
    vec![
        ParameterDefinition {
            name: "auth_type".into(),
            type_hint: "string".into(),
            description: "Authenticate every packet: simple, keyed_md5, meticulous_keyed_md5, keyed_sha1 or meticulous_keyed_sha1 (default: none)".into(),
            required: false,
            example: json!("keyed_sha1"),
            default: None,
        },
        ParameterDefinition {
            name: "auth_key_id".into(),
            type_hint: "number".into(),
            description: "The Auth Key ID both sides use, 0-255".into(),
            required: false,
            example: json!(1),
            default: Some(json!(DEFAULT_AUTH_KEY_ID)),
        },
        ParameterDefinition {
            name: "auth_password".into(),
            type_hint: "string".into(),
            description: "The shared key: up to 16 bytes (simple, MD5) or 20 (SHA1)".into(),
            required: false,
            example: json!("netget-bfd-key"),
            default: None,
        },
    ]
}

/// The timer startup parameters, shared with the client.
pub fn timer_startup_params() -> Vec<ParameterDefinition> {
    vec![
        ParameterDefinition {
            name: "desired_min_tx_ms".into(),
            type_hint: "number".into(),
            description: "How often to send once Up, in ms (10-60000)".into(),
            required: false,
            example: json!(100),
            default: Some(json!(session::DEFAULT_DESIRED_MIN_TX_MS)),
        },
        ParameterDefinition {
            name: "required_min_rx_ms".into(),
            type_hint: "number".into(),
            description: "The fastest the peer may send, in ms (10-60000)".into(),
            required: false,
            example: json!(100),
            default: Some(json!(session::DEFAULT_REQUIRED_MIN_RX_MS)),
        },
        ParameterDefinition {
            name: "detect_mult".into(),
            type_hint: "number".into(),
            description: "Missed packets before the session goes down (1-255)".into(),
            required: false,
            example: json!(5),
            default: Some(json!(session::DEFAULT_DETECT_MULT)),
        },
    ]
}

/// The authentication configured in startup parameters, if any.
pub fn auth_from(
    params: Option<&crate::protocol::StartupParams>,
) -> Result<Option<packet::AuthConfig>> {
    let Some(params) = params else {
        return Ok(None);
    };
    let kind = params.get_optional_string("auth_type")?;
    let password = params.get_optional_string("auth_password")?;
    let key_id = params
        .get_optional_u64("auth_key_id")?
        .unwrap_or(DEFAULT_AUTH_KEY_ID as u64);
    match (kind, password) {
        (None, None) => Ok(None),
        (Some(kind), Some(password)) => {
            anyhow::ensure!(key_id <= 255, "auth_key_id must be 0-255");
            Ok(Some(packet::AuthConfig::new(
                packet::AuthType::parse(&kind)?,
                key_id as u8,
                &password,
            )?))
        }
        _ => bail!("auth_type and auth_password are given together"),
    }
}

/// The session timers configured in startup parameters.
pub fn timers_from(params: Option<&crate::protocol::StartupParams>) -> Result<Timers> {
    let mut v = json!({});
    if let Some(params) = params {
        for key in ["desired_min_tx_ms", "required_min_rx_ms", "detect_mult"] {
            if let Some(n) = params.get_optional_u64(key)? {
                v[key] = json!(n);
            }
        }
    }
    Timers::from_json(&v, Timers::default())
}

impl Protocol for BfdProtocol {
    fn protocol_name(&self) -> &'static str {
        "BFD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BFD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bfd",
            "bidirectional forwarding detection",
            "rfc 5880",
            "liveness",
            "3784",
            "4784",
        ]
    }
    fn description(&self) -> &'static str {
        "BFD speaker (RFC 5880/5881/5883): accepts sessions from routers such as BIRD and FRR, keeps them Up with periodic Control packets, and reports every state change"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        // Sessions are driven through their own events, or per session from the dashboard
        // (each live session takes bfd_set_timers / bfd_admin_down / bfd_admin_up).
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut all = vec![accept_action()];
        all.extend(session_actions());
        all
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![SESSION_REQUEST_EVENT.clone(), STATE_EVENT.clone()]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut params = vec![
            ParameterDefinition {
                name: "multihop".into(),
                type_hint: "boolean".into(),
                description: "Multihop BFD (RFC 5883, port 4784): no TTL-255 check on what arrives. Defaults to true when the server listens on 4784".into(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "max_sessions".into(),
                type_hint: "number".into(),
                description: "Sessions held at once; a new peer past this is ignored".into(),
                required: false,
                example: json!(16),
                default: Some(json!(MAX_SESSIONS)),
            },
        ];
        params.extend(timer_startup_params());
        params.extend(auth_params());
        params
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(3784)
            .deliberately_silent()
            .implementation("Hand-rolled RFC 5880 Asynchronous mode (src/server/bfd/): the Control packet and all five authentication types, the state machine, jittered periodic transmission, Poll/Final, the Detection Time, and the RFC 5881 TTL-255 check read with IP_RECVTTL; one task per session, sending from a source port in 49152-65535 with TTL 255; passive role (silent until a peer speaks)")
            .llm_control("Which peers get a session and with what timers, and what to do when a session goes up or down (change timers, take it administratively down or back up)")
            .e2e_testing("tests/server/bfd: BIRD 2 (multihop sessions brought Up and read back with birdc, timers renegotiated by Poll Sequence, AdminDown, keyed SHA1 with a right and a wrong key); a raw-socket peer for the TTL check and the bounds; the pcap oracle (tshark's bfd dissector) over the packets NetGet sent")
            .notes("DELIBERATELY SILENT: BFD has no refusal; a peer the model does not accept (or a backend failure) is never answered, so its session stays Down (logged decision=model_silent / fail_closed_*). The model is consulted per session and per state change, never per packet. No Demand mode, no Echo function, no IPv6 TTL (hop limit) check.")
            .max_inbound_bytes(packet::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Run BFD on port 4784 and accept sessions from 192.0.2.1 with 300 ms timers"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"bfd","port":0,"startup_params":{"multihop":true},
            "instruction":"Accept BFD sessions from 127.0.0.1 only, with 300 ms timers"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"bfd_session_request","handler":{"type":"static","actions":[accept_action().example]}},
            {"event_pattern":"bfd_session_state","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"bfd_session_request","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'bfd_accept_session'}] if e['peer']=='127.0.0.1' else []}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Server for BfdProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action["type"].as_str().unwrap_or_default();
        match kind {
            ACCEPT => {
                Timers::from_json(&action, Timers::default())?;
            }
            "bfd_set_timers" | "bfd_admin_down" | "bfd_admin_up" => {
                super::runner::check_action(&action)?;
            }
            other => bail!("Unknown BFD action {other:?}"),
        }
        // The server applies it to the session the event was about.
        Ok(ActionResult::Custom {
            name: kind.into(),
            data: action,
        })
    }
}
