//! STP / RSTP protocol actions, events, and the bridge configuration read from startup
//! parameters.
//!
//! Everything the model sees is structured: bridge priority and system ID extension are two
//! numbers, the flags octet is seven named booleans and an enum, and the timers are seconds.
//! No hex string, no byte blob, and nothing in an action or an event that a model would have
//! to encode by hand. [`super::codec`] turns those values into wire octets.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::protocol::StartupParams;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::codec::{
    self, BpduFlags, BridgeId, ConfigBpdu, PortId, PortRole, BPDU_TYPE_CONFIG, BPDU_TYPE_RST,
    VERSION_RSTP, VERSION_STP,
};

/// Name of the loopback interface on this platform.
///
/// Only relevant to the raw transport's default binding. Loopback is a deliberately useless
/// default for STP — there is no bridged segment there — but it is the one interface that
/// exists everywhere, and `spawn()` refuses with a clear message rather than pretending.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo";

/// Which wire this server speaks on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpTransport {
    /// Real 802.3 frames through libpcap. Needs `CAP_NET_RAW` / `/dev/bpf*`.
    Raw,
    /// Complete 802.3 frames carried one-per-datagram over UDP.
    ///
    /// This exists so the event → LLM → action → frame path can be exercised without
    /// privilege; the frame in the datagram is byte-identical to the frame the raw transport
    /// would put on the wire, so the codec and the decision path are the real ones. Only the
    /// link layer is simulated. See `src/server/stp/CLAUDE.md`.
    Udp,
}

impl StpTransport {
    fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "raw" | "raw802.3" | "ethernet" | "pcap" => Ok(StpTransport::Raw),
            "udp" | "test" => Ok(StpTransport::Udp),
            other => bail!("unknown transport '{other}' (expected 'raw' or 'udp')"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StpTransport::Raw => "raw",
            StpTransport::Udp => "udp",
        }
    }
}

/// This bridge's own identity and timers, from the startup parameters.
///
/// Two things read it, which is what makes every declared parameter live:
///
/// 1. [`StpBridgeConfig::apply_defaults`] fills in every field the model's action left out,
///    immediately before the frame is built. An action that names a field keeps its own value,
///    so a prompt can still deliberately advertise a different bridge from the configured one.
/// 2. [`StpBridgeConfig::local_summary`] is attached to every event as `local_*`, so the model
///    can compare what arrived against what this bridge is configured to claim — which is the
///    whole root-election question.
#[derive(Debug, Clone, PartialEq)]
pub struct StpBridgeConfig {
    pub transport: StpTransport,
    pub bridge_mac: [u8; 6],
    pub bridge_priority: u16,
    pub system_id_extension: u16,
    pub port_priority: u8,
    pub port_number: u16,
    /// 0 (STP) or 2 (RSTP).
    pub protocol_version: u8,
    pub hello_time_seconds: f64,
    pub max_age_seconds: f64,
    pub forward_delay_seconds: f64,
}

impl Default for StpBridgeConfig {
    fn default() -> Self {
        Self {
            transport: StpTransport::Raw,
            // Locally administered, so it cannot collide with a real vendor OUI.
            bridge_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            // 802.1D-2004 §17.14 default bridge priority.
            bridge_priority: 32768,
            system_id_extension: 0,
            port_priority: 128,
            port_number: 1,
            protocol_version: VERSION_RSTP,
            // 802.1D-2004 Table 17-1 recommended values.
            hello_time_seconds: 2.0,
            max_age_seconds: 20.0,
            forward_delay_seconds: 15.0,
        }
    }
}

impl StpBridgeConfig {
    /// Read every declared startup parameter. Errors propagate; nothing is unwrapped.
    pub fn from_startup_params(params: Option<&StartupParams>) -> Result<Self> {
        let mut config = Self::default();
        let Some(params) = params else {
            return Ok(config);
        };

        if let Some(v) = params.get_optional_string("transport")? {
            config.transport = StpTransport::from_name(&v)?;
        }
        if let Some(v) = params.get_optional_string("bridge_mac")? {
            config.bridge_mac = codec::parse_mac(&v).context("invalid bridge_mac")?;
        }
        if let Some(v) = params.get_optional_i64("bridge_priority")? {
            let priority = u16::try_from(v)
                .map_err(|_| anyhow::anyhow!("bridge_priority must be 0..=61440, got {v}"))?;
            // Validated here rather than at send time so a misconfigured bridge refuses to
            // start instead of failing on every BPDU it tries to emit.
            BridgeId::new(priority, 0, config.bridge_mac)?;
            config.bridge_priority = priority;
        }
        if let Some(v) = params.get_optional_i64("system_id_extension")? {
            let ext = u16::try_from(v)
                .map_err(|_| anyhow::anyhow!("system_id_extension must be 0..=4095, got {v}"))?;
            BridgeId::new(config.bridge_priority, ext, config.bridge_mac)?;
            config.system_id_extension = ext;
        }
        if let Some(v) = params.get_optional_i64("port_priority")? {
            let priority = u8::try_from(v)
                .map_err(|_| anyhow::anyhow!("port_priority must be 0..=240, got {v}"))?;
            PortId::new(priority, config.port_number)?;
            config.port_priority = priority;
        }
        if let Some(v) = params.get_optional_i64("port_number")? {
            let number = u16::try_from(v)
                .map_err(|_| anyhow::anyhow!("port_number must be 0..=4095, got {v}"))?;
            PortId::new(config.port_priority, number)?;
            config.port_number = number;
        }
        if let Some(v) = params.get_optional_string("protocol_version")? {
            config.protocol_version = match v.trim().to_ascii_lowercase().as_str() {
                "stp" | "802.1d" | "0" => VERSION_STP,
                "rstp" | "802.1w" | "2" => VERSION_RSTP,
                other => bail!("unknown protocol_version '{other}' (expected 'stp' or 'rstp')"),
            };
        }
        if let Some(v) = params.get_optional_i64("hello_time")? {
            config.hello_time_seconds = validated_timer("hello_time", v)?;
        }
        if let Some(v) = params.get_optional_i64("max_age")? {
            config.max_age_seconds = validated_timer("max_age", v)?;
        }
        if let Some(v) = params.get_optional_i64("forward_delay")? {
            config.forward_delay_seconds = validated_timer("forward_delay", v)?;
        }

        Ok(config)
    }

    /// This bridge's own identifier, as it would appear on the wire.
    pub fn bridge_id(&self) -> Result<BridgeId> {
        BridgeId::new(
            self.bridge_priority,
            self.system_id_extension,
            self.bridge_mac,
        )
    }

    pub fn port_id(&self) -> Result<PortId> {
        PortId::new(self.port_priority, self.port_number)
    }

    fn version_name(&self) -> &'static str {
        if self.protocol_version >= VERSION_RSTP {
            "rstp"
        } else {
            "stp"
        }
    }

    /// The `local_*` block attached to every event.
    pub fn local_summary(&self) -> serde_json::Value {
        json!({
            "local_transport": self.transport.as_str(),
            "local_bridge_mac": codec::format_mac(&self.bridge_mac),
            "local_bridge_priority": self.bridge_priority,
            "local_system_id_extension": self.system_id_extension,
            "local_port_priority": self.port_priority,
            "local_port_number": self.port_number,
            "local_protocol_version": self.version_name(),
            "local_hello_time": self.hello_time_seconds,
            "local_max_age": self.max_age_seconds,
            "local_forward_delay": self.forward_delay_seconds,
        })
    }

    /// Fill in whatever the model's action left out, from this bridge's configuration.
    ///
    /// Without this the builder would fall back to protocol constants and the operator's
    /// configured identity would never reach the wire — the defect `ospf` had for four of its
    /// six parameters.
    pub fn apply_defaults(&self, action: &mut serde_json::Value) {
        let Some(object) = action.as_object_mut() else {
            return;
        };
        let mut set = |key: &str, value: serde_json::Value| {
            object.entry(key.to_string()).or_insert(value);
        };
        set("protocol_version", json!(self.version_name()));
        set("source_mac", json!(codec::format_mac(&self.bridge_mac)));
        set("bridge_mac", json!(codec::format_mac(&self.bridge_mac)));
        set("bridge_priority", json!(self.bridge_priority));
        set(
            "bridge_system_id_extension",
            json!(self.system_id_extension),
        );
        // With no better information this bridge claims itself as root, which is what a
        // freshly started bridge does before it hears anything.
        set(
            "root_bridge_mac",
            json!(codec::format_mac(&self.bridge_mac)),
        );
        set("root_priority", json!(self.bridge_priority));
        set("root_system_id_extension", json!(self.system_id_extension));
        set("root_path_cost", json!(0));
        set("port_priority", json!(self.port_priority));
        set("port_number", json!(self.port_number));
        set("message_age", json!(0));
        set("max_age", json!(self.max_age_seconds));
        set("hello_time", json!(self.hello_time_seconds));
        set("forward_delay", json!(self.forward_delay_seconds));
    }
}

fn validated_timer(name: &str, value: i64) -> Result<f64> {
    if !(0..=255).contains(&value) {
        bail!("{name} must be 0..=255 seconds (the wire field is 16 bits of 1/256s), got {value}");
    }
    Ok(value as f64)
}

// ---------------------------------------------------------------------------
// Action JSON -> codec types
// ---------------------------------------------------------------------------

fn field_u16(action: &serde_json::Value, key: &str, default: u16) -> Result<u16> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_i64()
                .with_context(|| format!("'{key}' must be an integer, got {v}"))?;
            u16::try_from(n).map_err(|_| anyhow::anyhow!("'{key}' out of range: {n}"))
        }
    }
}

fn field_u32(action: &serde_json::Value, key: &str, default: u32) -> Result<u32> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_i64()
                .with_context(|| format!("'{key}' must be an integer, got {v}"))?;
            u32::try_from(n).map_err(|_| anyhow::anyhow!("'{key}' out of range: {n}"))
        }
    }
}

fn field_u8(action: &serde_json::Value, key: &str, default: u8) -> Result<u8> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_i64()
                .with_context(|| format!("'{key}' must be an integer, got {v}"))?;
            u8::try_from(n).map_err(|_| anyhow::anyhow!("'{key}' out of range: {n}"))
        }
    }
}

fn field_f64(action: &serde_json::Value, key: &str, default: f64) -> Result<f64> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => v
            .as_f64()
            .with_context(|| format!("'{key}' must be a number of seconds, got {v}")),
    }
}

fn field_bool(action: &serde_json::Value, key: &str) -> Result<bool> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(v) => v
            .as_bool()
            .with_context(|| format!("'{key}' must be true or false, got {v}")),
    }
}

fn field_mac(action: &serde_json::Value, key: &str, default: [u8; 6]) -> Result<[u8; 6]> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let s = v
                .as_str()
                .with_context(|| format!("'{key}' must be a MAC address string, got {v}"))?;
            codec::parse_mac(s).with_context(|| format!("invalid {key}"))
        }
    }
}

impl StpProtocol {
    /// Build the BPDU an action describes.
    ///
    /// Any field the action omits falls back to a protocol default here, so the action's own
    /// declared `example` is executable on its own — `tests/executable_examples_test.rs`
    /// calls `execute_action` with nothing else in scope. `mod.rs` layers the operator's
    /// [`StpBridgeConfig`] defaults on top *before* this runs, so a live server's omissions
    /// come from its configuration rather than from these constants.
    pub fn config_bpdu_from_action(action: &serde_json::Value) -> Result<ConfigBpdu> {
        let defaults = StpBridgeConfig::default();

        let version = match action.get("protocol_version").and_then(|v| v.as_str()) {
            None => defaults.protocol_version,
            Some(name) => match name.trim().to_ascii_lowercase().as_str() {
                "stp" | "802.1d" => VERSION_STP,
                "rstp" | "802.1w" => VERSION_RSTP,
                other => bail!("unknown protocol_version '{other}' (expected 'stp' or 'rstp')"),
            },
        };
        let bpdu_type = if version >= VERSION_RSTP {
            BPDU_TYPE_RST
        } else {
            BPDU_TYPE_CONFIG
        };

        let port_role = match action.get("port_role").and_then(|v| v.as_str()) {
            Some(name) => PortRole::from_name(name)?,
            None if version >= VERSION_RSTP => PortRole::Designated,
            None => PortRole::Unknown,
        };

        let flags = BpduFlags {
            topology_change: field_bool(action, "topology_change")?,
            proposal: field_bool(action, "proposal")?,
            port_role,
            learning: field_bool(action, "learning")?,
            forwarding: field_bool(action, "forwarding")?,
            agreement: field_bool(action, "agreement")?,
            topology_change_ack: field_bool(action, "topology_change_ack")?,
        };

        let bridge_mac = field_mac(action, "bridge_mac", defaults.bridge_mac)?;
        let bridge = BridgeId::new(
            field_u16(action, "bridge_priority", defaults.bridge_priority)?,
            field_u16(
                action,
                "bridge_system_id_extension",
                defaults.system_id_extension,
            )?,
            bridge_mac,
        )?;
        let root = BridgeId::new(
            field_u16(action, "root_priority", bridge.priority)?,
            field_u16(
                action,
                "root_system_id_extension",
                bridge.system_id_extension,
            )?,
            field_mac(action, "root_bridge_mac", bridge_mac)?,
        )?;
        let port = PortId::new(
            field_u8(action, "port_priority", defaults.port_priority)?,
            field_u16(action, "port_number", defaults.port_number)?,
        )?;

        let bpdu = ConfigBpdu {
            version,
            bpdu_type,
            flags,
            root,
            root_path_cost: field_u32(action, "root_path_cost", 0)?,
            bridge,
            port,
            message_age_seconds: field_f64(action, "message_age", 0.0)?,
            max_age_seconds: field_f64(action, "max_age", defaults.max_age_seconds)?,
            hello_time_seconds: field_f64(action, "hello_time", defaults.hello_time_seconds)?,
            forward_delay_seconds: field_f64(
                action,
                "forward_delay",
                defaults.forward_delay_seconds,
            )?,
        };

        // Encode once here so an action that cannot become a frame is rejected at execution
        // time, where the error reaches the model, rather than deep in the transport.
        bpdu.encode()?;
        Ok(bpdu)
    }

    /// The destination MAC an action asks for, defaulting to the Bridge Group Address.
    pub fn destination_from_action(action: &serde_json::Value) -> Result<[u8; 6]> {
        field_mac(action, "destination_mac", codec::STP_MULTICAST_MAC)
    }

    /// The source MAC an action asks for.
    pub fn source_from_action(action: &serde_json::Value, fallback: [u8; 6]) -> Result<[u8; 6]> {
        field_mac(action, "source_mac", fallback)
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// STP / RSTP protocol handler.
pub struct StpProtocol;

impl StpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for StpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // Both transports are described here: the raw transport reads `interface`, the UDP
        // test transport reads `host`/`port`. `BindingDefaults` carries all four, and which
        // pair is consulted is decided by the `transport` startup parameter.
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: Some(DEFAULT_LOOPBACK_INTERFACE.to_string()),
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description: "'raw' (default) sends and receives real 802.3 BPDU frames through \
                              libpcap and needs CAP_NET_RAW or /dev/bpf* access. 'udp' carries \
                              one complete 802.3 frame per UDP datagram on the configured \
                              host/port — the same frames, no privilege, no link layer — for \
                              testing and for driving the protocol from a script."
                    .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
            ParameterDefinition {
                name: "bridge_mac".to_string(),
                type_hint: "string".to_string(),
                description: "MAC address of this bridge, used as the source address of every \
                              frame and as the MAC half of the bridge identifier \
                              (aa:bb:cc:dd:ee:ff)."
                    .to_string(),
                required: false,
                example: json!("02:00:00:00:00:01"),
                default: None,
            },
            ParameterDefinition {
                name: "bridge_priority".to_string(),
                type_hint: "number".to_string(),
                description: "Bridge priority, 0..=61440 in steps of 4096 (default 32768). \
                              LOWER WINS THE ROOT ELECTION: a bridge that advertises 0 claims \
                              to be the root of the whole spanning tree and every switch that \
                              believes it will re-converge around it."
                    .to_string(),
                required: false,
                example: json!(32768),
                default: None,
            },
            ParameterDefinition {
                name: "system_id_extension".to_string(),
                type_hint: "number".to_string(),
                description: "System ID extension, 0..=4095 — the VLAN id in per-VLAN spanning \
                              tree. Occupies the low 12 bits of the same 16-bit field as the \
                              priority."
                    .to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "port_priority".to_string(),
                type_hint: "number".to_string(),
                description: "Port priority, 0..=240 in steps of 16 (default 128). High 4 bits \
                              of the port identifier."
                    .to_string(),
                required: false,
                example: json!(128),
                default: None,
            },
            ParameterDefinition {
                name: "port_number".to_string(),
                type_hint: "number".to_string(),
                description: "Port number, 0..=4095 (default 1). Low 12 bits of the port \
                              identifier."
                    .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
            ParameterDefinition {
                name: "protocol_version".to_string(),
                type_hint: "string".to_string(),
                description: "'rstp' (default, 802.1w, version 2, RST BPDUs) or 'stp' (802.1D, \
                              version 0, configuration BPDUs). Decides what this bridge emits; \
                              received BPDUs of either kind are always understood."
                    .to_string(),
                required: false,
                example: json!("rstp"),
                default: None,
            },
            ParameterDefinition {
                name: "hello_time".to_string(),
                type_hint: "number".to_string(),
                description: "Hello time in whole seconds, 0..=255 (default 2). Encoded on the \
                              wire in units of 1/256 second."
                    .to_string(),
                required: false,
                example: json!(2),
                default: None,
            },
            ParameterDefinition {
                name: "max_age".to_string(),
                type_hint: "number".to_string(),
                description: "Max age in whole seconds, 0..=255 (default 20). Encoded on the \
                              wire in units of 1/256 second."
                    .to_string(),
                required: false,
                example: json!(20),
                default: None,
            },
            ParameterDefinition {
                name: "forward_delay".to_string(),
                type_hint: "number".to_string(),
                description: "Forward delay in whole seconds, 0..=255 (default 15). Encoded on \
                              the wire in units of 1/256 second."
                    .to_string(),
                required: false,
                example: json!(15),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // The same three verbs the model gets on an event: STP has no user-initiated
        // vocabulary distinct from its wire vocabulary, so narrowing here would only hide
        // things.
        stp_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        stp_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "STP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_stp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>LLC>STP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "stp",
            "rstp",
            "spanning tree",
            "bpdu",
            "802.1d",
            "802.1w",
            "bridge",
            "root bridge",
        ]
    }

    fn startup_privilege_requirement(
        &self,

        startup_params: Option<&serde_json::Value>,
    ) -> crate::protocol::metadata::PrivilegeRequirement {
        // The UDP test transport carries the same frames over an ordinary socket.

        crate::llm::actions::protocol_trait::unless_udp_transport(
            self.metadata().privilege_requirement,
            startup_params,
        )
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // libpcap capture/injection, never a SOCK_RAW. RawSockets would refuse to start on
            // a host with /dev/bpf* access but no root - the "don't claim more than you need"
            // rule that ospf got wrong by declaring Root when it wanted CAP_NET_RAW.
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .connectionless()
            // Deliberately silent: STP has no error BPDU. A BPDU asserts a bridge's priority and
            // its view of the root, and neighbours act on it by re-electing the root or blocking
            // ports, so a fabricated one reshapes the topology.
            .deliberately_silent()
            .implementation(
                "Hand-written IEEE 802.1D-2004 / 802.1w BPDU codec (src/server/stp/codec.rs), \
                 pure and I/O-free, under two transports: real 802.3 LLC frames via libpcap, \
                 and a UDP transport carrying one complete 802.3 frame \
                 per datagram for unprivileged use.",
            )
            .llm_control(
                "Every bridge parameter: bridge and root priority, system ID extension (VLAN), \
                 MAC, path cost, port identifier, all four timers, and each RSTP flag \
                 (proposal, agreement, learning, forwarding, port role). The model decides \
                 whether to answer at all — no spanning-tree state machine runs, and nothing is \
                 emitted unprompted.",
            )
            .e2e_testing(
                "tests/server/stp/codec_test.rs asserts the encoder byte-for-byte against \
                 literal specification bytes (including the 1/256-second timer encoding and the \
                 4/12-bit priority packing) and decodes literal config, RST and TCN BPDUs. \
                 tests/server/stp/e2e_test.rs runs the full frame -> event -> mocked LLM -> \
                 action -> frame path over the UDP transport, unprivileged, and asserts that an \
                 LLM failure produces no frame at all.",
            )
            .notes(
                "PROVEN: the BPDU codec, against literal spec bytes in both directions, and the \
                 whole decision path (decode, event, handler/LLM dispatch, action, re-encode, \
                 transmit) over the UDP transport. NOT PROVEN: the raw 802.3 transport has \
                 never been executed — it needs CAP_NET_RAW or /dev/bpf* and no test in this \
                 tree runs privileged — and no third-party STP peer (mstpd, a real switch) has \
                 ever spoken to this server. Also note the privilege gate is protocol-wide: \
                 because this protocol declares RawSockets, server_startup refuses to start it \
                 unprivileged even with transport='udp', so the UDP transport is reachable by \
                 calling spawn() directly, which is what the e2e suite does. ON THE WIRE, \
                 SILENCE IS THE FAILURE MODE: every BPDU is a positive assertion about \
                 topology, and a fabricated one can trigger a real re-convergence, so an LLM \
                 error emits nothing and records decision=fail_closed_* in the log instead.",
            )
            .max_inbound_bytes(crate::server::stp::codec::MAX_8023_LENGTH)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "STP / RSTP (IEEE 802.1D / 802.1w) spanning tree bridge — receives BPDUs and emits \
         LLM-decided ones"
    }

    fn example_prompt(&self) -> &'static str {
        "Listen for spanning tree BPDUs on eth0 and report which bridge is claiming to be root"
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic observer: log every BPDU, answer nothing. This is the safe default for
        // a protocol whose only reply re-shapes somebody's network.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
print(json.dumps({
    "actions": [{"type": "no_bpdu"}],
    "message": "root %s/%s cost %s from %s" % (
        event.get("root_priority"), event.get("root_bridge_mac"),
        event.get("root_path_cost"), event.get("source_mac"))
}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "stp",
                "instruction": "Observe spanning tree BPDUs. Report which bridge is root and \
                                what it claims. Do not send anything.",
                "startup_params": {
                    "bridge_mac": "02:00:00:00:00:01",
                    "bridge_priority": 32768
                }
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "stp",
                "event_handlers": [{
                    "event_pattern": "stp_bpdu_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "stp",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "no_bpdu"}]
                    }
                }]
            }),
        )
    }
}

impl Server for StpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use super::StpServer;

            let config = StpBridgeConfig::from_startup_params(ctx.startup_params.as_ref())?;
            let interface = ctx.interface().map(|s| s.to_string());
            let listen_addr = ctx.legacy_listen_addr();

            StpServer::spawn_with_llm_actions(
                interface,
                listen_addr,
                config,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_stp_bpdu" => {
                // Validate now, build again in the transport once the operator's configured
                // defaults have been layered in. Validating here is what makes the declared
                // example executable and what puts a bad priority in front of the model.
                Self::config_bpdu_from_action(&action)?;
                Self::destination_from_action(&action)?;
                Ok(ActionResult::Custom {
                    name: "stp_action".to_string(),
                    data: action,
                })
            }
            "send_stp_tcn" => {
                Self::destination_from_action(&action)?;
                Ok(ActionResult::Custom {
                    name: "stp_action".to_string(),
                    data: action,
                })
            }
            "no_bpdu" => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown STP action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn stp_actions() -> Vec<ActionDefinition> {
    vec![
        send_stp_bpdu_action(),
        send_stp_tcn_action(),
        no_bpdu_action(),
    ]
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn send_stp_bpdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stp_bpdu".to_string(),
        description:
            "Transmit a spanning tree configuration BPDU (802.1D) or RST BPDU (802.1w). \
             DANGEROUS ON A REAL NETWORK: a BPDU is an assertion about topology, and a \
             root_priority lower than the current root's makes every listening switch \
             re-converge the spanning tree around this bridge, briefly blackholing traffic. \
             Every field is optional; anything omitted comes from the server's startup \
             parameters."
                .to_string(),
        parameters: vec![
            param(
                "protocol_version",
                "string",
                "'rstp' (802.1w, version 2, RST BPDU) or 'stp' (802.1D, version 0, \
                 configuration BPDU). Defaults to the server's configured version.",
                false,
            ),
            param(
                "root_bridge_mac",
                "string",
                "MAC half of the root bridge identifier this BPDU advertises \
                 (aa:bb:cc:dd:ee:ff).",
                false,
            ),
            param(
                "root_priority",
                "number",
                "Priority half of the root bridge identifier, 0..=61440 in steps of 4096. Lower \
                 wins the election — 0 claims the root of the entire spanning tree.",
                false,
            ),
            param(
                "root_system_id_extension",
                "number",
                "System ID extension (VLAN id) of the root identifier, 0..=4095.",
                false,
            ),
            param(
                "root_path_cost",
                "number",
                "Cost of the path from this bridge to the advertised root. 0 means this bridge \
                 is the root.",
                false,
            ),
            param(
                "bridge_mac",
                "string",
                "MAC half of this bridge's own identifier.",
                false,
            ),
            param(
                "bridge_priority",
                "number",
                "Priority half of this bridge's own identifier, 0..=61440 in steps of 4096.",
                false,
            ),
            param(
                "bridge_system_id_extension",
                "number",
                "System ID extension (VLAN id) of this bridge's identifier, 0..=4095.",
                false,
            ),
            param(
                "port_priority",
                "number",
                "Port priority, 0..=240 in steps of 16.",
                false,
            ),
            param("port_number", "number", "Port number, 0..=4095.", false),
            param(
                "message_age",
                "number",
                "Message age in seconds. Wire encoding is 1/256s, handled for you.",
                false,
            ),
            param("max_age", "number", "Max age in seconds (typically 20).", false),
            param(
                "hello_time",
                "number",
                "Hello time in seconds (typically 2).",
                false,
            ),
            param(
                "forward_delay",
                "number",
                "Forward delay in seconds (typically 15).",
                false,
            ),
            param(
                "topology_change",
                "boolean",
                "Topology change flag (bit 0). Tells receivers to age out their forwarding \
                 tables quickly.",
                false,
            ),
            param(
                "topology_change_ack",
                "boolean",
                "Topology change acknowledgement flag (bit 7).",
                false,
            ),
            param(
                "proposal",
                "boolean",
                "RSTP proposal flag (bit 1) — offers the rapid transition handshake.",
                false,
            ),
            param(
                "agreement",
                "boolean",
                "RSTP agreement flag (bit 6) — the answer to a proposal.",
                false,
            ),
            param("learning", "boolean", "RSTP learning flag (bit 4).", false),
            param(
                "forwarding",
                "boolean",
                "RSTP forwarding flag (bit 5).",
                false,
            ),
            param(
                "port_role",
                "string",
                "RSTP port role: 'designated', 'root', 'alternate' (or 'backup'), or 'unknown'.",
                false,
            ),
            param(
                "destination_mac",
                "string",
                "Destination MAC. Defaults to the Bridge Group Address 01:80:c2:00:00:00, which \
                 is where BPDUs belong; override only to target one bridge.",
                false,
            ),
            param(
                "source_mac",
                "string",
                "Source MAC of the frame. Defaults to the server's configured bridge_mac.",
                false,
            ),
        ],
        example: json!({
            "type": "send_stp_bpdu",
            "protocol_version": "rstp",
            "root_bridge_mac": "02:00:00:00:00:01",
            "root_priority": 32768,
            "root_system_id_extension": 0,
            "root_path_cost": 0,
            "bridge_mac": "02:00:00:00:00:01",
            "bridge_priority": 32768,
            "bridge_system_id_extension": 0,
            "port_priority": 128,
            "port_number": 1,
            "message_age": 0,
            "max_age": 20,
            "hello_time": 2,
            "forward_delay": 15,
            "port_role": "designated",
            "learning": true,
            "forwarding": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STP BPDU root {root_priority}/{root_bridge_mac} cost {root_path_cost}")
                .with_debug(
                    "STP send_stp_bpdu: version={protocol_version} root={root_priority}/{root_bridge_mac} \
                     bridge={bridge_priority}/{bridge_mac} port={port_priority}.{port_number} role={port_role}",
                )
                .with_trace("STP BPDU action: {json_pretty(.)}"),
        ),
    }
}

fn send_stp_tcn_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stp_tcn".to_string(),
        description:
            "Transmit a Topology Change Notification BPDU. It carries no fields — its whole \
             content is 'something changed' — and a real bridge answers by flooding the change \
             towards the root, which shortens every switch's MAC ageing timer on the segment. \
             Send it only when you mean to."
                .to_string(),
        parameters: vec![
            param(
                "destination_mac",
                "string",
                "Destination MAC. Defaults to the Bridge Group Address 01:80:c2:00:00:00.",
                false,
            ),
            param(
                "source_mac",
                "string",
                "Source MAC of the frame. Defaults to the server's configured bridge_mac.",
                false,
            ),
        ],
        example: json!({ "type": "send_stp_tcn" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STP topology change notification")
                .with_debug("STP send_stp_tcn: destination={destination_mac}"),
        ),
    }
}

fn no_bpdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_bpdu".to_string(),
        description:
            "Answer with nothing. This is a real decision, not a failure: a spanning tree \
             listener that observes without transmitting cannot perturb the topology, and it is \
             the correct answer whenever you are unsure. Prefer it to guessing a bridge \
             priority."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "no_bpdu" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STP silent (no BPDU)")
                .with_debug("STP no_bpdu: observed, nothing transmitted"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

fn bpdu_event_parameters() -> Vec<Parameter> {
    vec![
        param(
            "bpdu_type",
            "string",
            "'configuration', 'rst' or 'topology_change_notification'.",
            true,
        ),
        param(
            "protocol_version",
            "string",
            "'stp' (version 0) or 'rstp' (version 2); higher versions are reported as their \
             number.",
            true,
        ),
        param(
            "is_rstp",
            "boolean",
            "True for an RST BPDU (type 0x02).",
            true,
        ),
        param(
            "is_tcn",
            "boolean",
            "True for a Topology Change Notification BPDU (type 0x80), which carries no other \
             fields.",
            true,
        ),
        param(
            "source_mac",
            "string",
            "Source MAC of the 802.3 frame — the neighbouring bridge port that sent it.",
            true,
        ),
        param(
            "destination_mac",
            "string",
            "Destination MAC, normally the Bridge Group Address 01:80:c2:00:00:00.",
            true,
        ),
        param(
            "root_bridge_mac",
            "string",
            "MAC half of the root bridge identifier the sender believes in.",
            false,
        ),
        param(
            "root_priority",
            "number",
            "Priority half of the root identifier, a multiple of 4096. Lower wins.",
            false,
        ),
        param(
            "root_system_id_extension",
            "number",
            "System ID extension (VLAN) of the root identifier.",
            false,
        ),
        param(
            "root_path_cost",
            "number",
            "The sender's cost to reach that root. 0 means the sender is the root.",
            false,
        ),
        param(
            "bridge_mac",
            "string",
            "MAC half of the sending bridge's own identifier.",
            false,
        ),
        param(
            "bridge_priority",
            "number",
            "Priority half of the sending bridge's identifier.",
            false,
        ),
        param(
            "bridge_system_id_extension",
            "number",
            "System ID extension (VLAN) of the sending bridge's identifier.",
            false,
        ),
        param(
            "port_priority",
            "number",
            "Priority half of the sender's port identifier.",
            false,
        ),
        param(
            "port_number",
            "number",
            "Port number half of the sender's port identifier.",
            false,
        ),
        param(
            "flags",
            "object",
            "The flags octet decoded: topology_change, topology_change_ack, proposal, \
             agreement, learning, forwarding, port_role.",
            false,
        ),
        param(
            "message_age",
            "number",
            "Message age in seconds (decoded from 1/256s units).",
            false,
        ),
        param("max_age", "number", "Max age in seconds.", false),
        param("hello_time", "number", "Hello time in seconds.", false),
        param(
            "forward_delay",
            "number",
            "Forward delay in seconds.",
            false,
        ),
        param(
            "local_bridge_priority",
            "number",
            "This server's own configured bridge priority, for comparison with root_priority.",
            false,
        ),
        param(
            "local_bridge_mac",
            "string",
            "This server's own configured bridge MAC.",
            false,
        ),
    ]
}

pub static STP_BPDU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stp_bpdu_received",
        "A spanning tree BPDU arrived that does not signal a topology change: a configuration \
         BPDU (802.1D) or an RST BPDU (802.1w) with the topology-change flag clear. Answer with \
         no_bpdu unless you intend to take part in the spanning tree.",
        json!({ "type": "no_bpdu" }),
    )
    .with_parameters(bpdu_event_parameters())
    .with_actions(stp_actions())
    .with_alternative_example(json!({
        "type": "send_stp_bpdu",
        "protocol_version": "rstp",
        "root_bridge_mac": "02:00:00:00:00:01",
        "root_priority": 0,
        "root_path_cost": 0,
        "bridge_mac": "02:00:00:00:00:01",
        "bridge_priority": 0,
        "port_role": "designated",
        "learning": true,
        "forwarding": true
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info(
                "STP {bpdu_type} from {source_mac}: root {root_priority}/{root_bridge_mac} cost {root_path_cost}",
            )
            .with_debug(
                "STP {bpdu_type} from {source_mac}: root={root_priority}/{root_bridge_mac} \
                 bridge={bridge_priority}/{bridge_mac} port={port_priority}.{port_number} \
                 age={message_age} max_age={max_age} hello={hello_time} fwd={forward_delay}",
            )
            .with_trace("STP BPDU: {json_pretty(.)}"),
    )
});

pub static STP_TOPOLOGY_CHANGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stp_topology_change",
        "The segment signalled a topology change: either a Topology Change Notification BPDU \
         (type 0x80), or a configuration/RST BPDU with the topology-change flag set. Downstream \
         switches will shorten their MAC ageing timers. Answer with no_bpdu unless you intend to \
         propagate or acknowledge it.",
        json!({ "type": "no_bpdu" }),
    )
    .with_parameters({
        let mut params = bpdu_event_parameters();
        params.push(param(
            "change_reason",
            "string",
            "'tcn_bpdu' when a Topology Change Notification arrived, 'topology_change_flag' when \
             a configuration or RST BPDU carried the flag.",
            true,
        ));
        params
    })
    .with_actions(stp_actions())
    .with_alternative_example(json!({ "type": "send_stp_tcn" }))
    .with_log_template(
        LogTemplate::new()
            .with_info("STP topology change from {source_mac} ({change_reason})")
            .with_debug(
                "STP topology change from {source_mac}: reason={change_reason} \
                 root={root_priority}/{root_bridge_mac}",
            )
            .with_trace("STP topology change: {json_pretty(.)}"),
    )
});

pub fn get_stp_event_types() -> Vec<EventType> {
    vec![
        STP_BPDU_RECEIVED_EVENT.clone(),
        STP_TOPOLOGY_CHANGE_EVENT.clone(),
    ]
}
