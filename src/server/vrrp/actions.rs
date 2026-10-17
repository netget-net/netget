//! VRRP / CARP vocabulary: what the model sees, the group configuration read from startup
//! parameters, and the translation from one action to one codec value.
//!
//! Everything crossing this boundary is structured. Addresses are dotted quads, intervals are
//! seconds, priority is a number — no hex, no base64, and nothing the model would have to
//! assemble by hand. [`super::codec`] turns those values into wire octets.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::protocol::StartupParams;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

use super::codec::{
    self, CarpAdvertisement, Variant, VrrpAdvertisement, CARP_AUTH_LEN_WORDS, CARP_VERSION,
    VRRP_AUTH_TYPE_NONE, VRRP_MULTICAST_IPV4, VRRP_VERSION_2, VRRP_VERSION_3,
};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Which wire this server speaks on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrrpTransport {
    /// A real `SOCK_RAW` socket on IP protocol 112, joined to `224.0.0.18`. Needs
    /// `CAP_NET_RAW` on Linux or root elsewhere. **Never executed in this tree.**
    Raw,
    /// One complete VRRP (or CARP) message per UDP datagram — the same octets the raw
    /// transport would put on the wire, with only the IP layer simulated.
    ///
    /// This exists so the advertisement → event → model → action → packet path can be
    /// exercised without privilege. It is the compromise `ospf` documents as "requires
    /// root/CAP_NET_RAW, tests use UDP", done inside the protocol rather than by substituting
    /// a generic UDP server in the test.
    Udp,
}

impl VrrpTransport {
    fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "raw" | "rawip" | "ip" | "ip112" => Ok(VrrpTransport::Raw),
            "udp" | "test" => Ok(VrrpTransport::Udp),
            other => bail!("unknown transport '{other}' (expected 'raw' or 'udp')"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VrrpTransport::Raw => "raw",
            VrrpTransport::Udp => "udp",
        }
    }
}

// ---------------------------------------------------------------------------
// Group configuration
// ---------------------------------------------------------------------------

/// This server's own virtual-router identity, from the startup parameters.
///
/// Every declared parameter lands here and is read twice, which is what keeps the declared
/// set and the used set identical:
///
/// 1. [`VrrpGroupConfig::apply_defaults`] fills in whatever the model's action left out,
///    immediately before the packet is built.
/// 2. [`VrrpGroupConfig::local_summary`] is attached to every event as `local_*`, so the
///    model can compare what arrived against what this router is configured to claim — which
///    *is* the election question.
#[derive(Debug, Clone, PartialEq)]
pub struct VrrpGroupConfig {
    pub transport: VrrpTransport,
    pub variant: Variant,
    /// 2 or 3. Ignored when `variant` is CARP, which has its own version number.
    pub version: u8,
    /// Virtual Router Identifier (VRRP) or virtual host id (CARP).
    pub vrid: u8,
    /// VRRP only. 0 resigns, 255 claims address ownership, higher wins.
    pub priority: u8,
    /// Advertisement interval in seconds. CARP reads the whole-second part as `advbase`.
    pub advert_interval_seconds: f64,
    /// The virtual addresses this router advertises.
    pub addresses: Vec<Ipv4Addr>,
    /// CARP only. Lower wins — the inverse of VRRP's priority.
    pub advskew: u8,
    /// CARP only. Zero-padded to 20 octets and used as the HMAC key; empty means no key was
    /// configured, so outgoing advertisements carry an HMAC over an all-zero key and inbound
    /// ones cannot be verified.
    pub carp_passphrase: String,
}

impl Default for VrrpGroupConfig {
    fn default() -> Self {
        Self {
            transport: VrrpTransport::Raw,
            variant: Variant::Vrrp,
            // RFC 5798 is the current VRRP specification, so v3 is the default. v2 remains
            // selectable because most deployed equipment still speaks it.
            version: VRRP_VERSION_3,
            vrid: 1,
            // RFC 3768 §5.3.4: the default priority for a router that is not the address
            // owner. Deliberately not 255 — claiming ownership by default would be a
            // fail-open: the server would assert it holds addresses it does not.
            priority: 100,
            advert_interval_seconds: 1.0,
            addresses: Vec::new(),
            advskew: 0,
            carp_passphrase: String::new(),
        }
    }
}

impl VrrpGroupConfig {
    /// Read every declared startup parameter. Errors propagate with `?`; nothing is unwrapped.
    pub fn from_startup_params(params: Option<&StartupParams>) -> Result<Self> {
        let mut config = Self::default();
        let Some(params) = params else {
            return Ok(config);
        };

        if let Some(v) = params.get_optional_string("transport")? {
            config.transport = VrrpTransport::from_name(&v)?;
        }
        if let Some(v) = params.get_optional_string("variant")? {
            config.variant = Variant::from_name(&v)?;
        }
        if let Some(v) = params.get_optional_i64("version")? {
            config.version = match v {
                2 => VRRP_VERSION_2,
                3 => VRRP_VERSION_3,
                other => bail!(
                    "unsupported VRRP version {other} (expected 2 for RFC 3768 or 3 for RFC 5798)"
                ),
            };
        }
        if let Some(v) = params.get_optional_i64("vrid")? {
            ensure!(
                (1..=255).contains(&v),
                "vrid must be 1..=255 (0 is not a valid virtual router id), got {v}"
            );
            config.vrid = v as u8;
        }
        if let Some(v) = params.get_optional_i64("priority")? {
            ensure!(
                (0..=255).contains(&v),
                "priority must be 0..=255 (0 resigns, 255 claims address ownership), got {v}"
            );
            config.priority = v as u8;
        }
        if let Some(v) = params.get_optional_i64("advert_interval")? {
            // Whole seconds here. `StartupParams` has no fractional accessor, and adding one
            // means editing a shared file; the sub-second intervals VRRPv3 allows are reachable
            // through the `advert_interval` field of `send_vrrp_advertisement`, which is raw
            // JSON. Declared and documented as whole seconds so the limit is visible rather
            // than discovered.
            ensure!(
                (1..=255).contains(&v),
                "advert_interval must be 1..=255 whole seconds as a startup parameter, got {v}"
            );
            config.advert_interval_seconds = v as f64;
        }
        if let Some(v) = params.get_optional_array("addresses")? {
            let mut addresses = Vec::with_capacity(v.len());
            for entry in v {
                let text = entry.as_str().with_context(|| {
                    format!("addresses must be dotted-quad strings, got {entry}")
                })?;
                addresses.push(parse_ipv4(text)?);
            }
            config.addresses = addresses;
        }
        if let Some(v) = params.get_optional_i64("advskew")? {
            ensure!(
                (0..=255).contains(&v),
                "advskew must be 0..=255 (lower wins the CARP election), got {v}"
            );
            config.advskew = v as u8;
        }
        if let Some(v) = params.get_optional_string("carp_passphrase")? {
            config.carp_passphrase = v;
        }

        // Refuse at startup rather than on every advertisement the server later tries to
        // send: a group whose identity cannot be encoded is misconfigured, not unlucky.
        config.template_advertisement()?.validate_shape()?;
        Ok(config)
    }

    /// A representative advertisement built purely from the configuration, used to prove at
    /// startup that this identity can be put on the wire.
    fn template_advertisement(&self) -> Result<ConfiguredAdvertisement> {
        match self.variant {
            Variant::Vrrp => Ok(ConfiguredAdvertisement::Vrrp(VrrpAdvertisement {
                version: self.version,
                vrid: self.vrid,
                priority: self.priority,
                advert_interval_seconds: self.advert_interval_seconds,
                auth_type: VRRP_AUTH_TYPE_NONE,
                addresses: self.addresses.clone(),
                checksum: 0,
            })),
            Variant::Carp => Ok(ConfiguredAdvertisement::Carp(self.carp_template()?)),
        }
    }

    fn carp_template(&self) -> Result<CarpAdvertisement> {
        let advbase = self.advert_interval_seconds.round();
        ensure!(
            (1.0..=255.0).contains(&advbase),
            "CARP advbase is a whole-second octet, so advert_interval must be 1..=255 \
             seconds; got {}",
            self.advert_interval_seconds
        );
        Ok(CarpAdvertisement {
            version: CARP_VERSION,
            vhid: self.vrid,
            advskew: self.advskew,
            auth_length_words: CARP_AUTH_LEN_WORDS,
            demote: 0,
            advbase: advbase as u8,
            counter: 0,
            hmac: codec::carp_hmac(
                self.carp_passphrase.as_bytes(),
                self.vrid,
                &self.addresses,
                0,
            ),
            checksum: 0,
        })
    }

    /// The `local_*` block attached to every event.
    pub fn local_summary(&self) -> serde_json::Value {
        json!({
            "local_transport": self.transport.as_str(),
            "local_variant": self.variant.as_str(),
            "local_version": self.version,
            "local_vrid": self.vrid,
            "local_priority": self.priority,
            "local_advert_interval": self.advert_interval_seconds,
            "local_addresses": self.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "local_advskew": self.advskew,
            // The passphrase itself never reaches the model or the log — only whether one
            // exists, which is what decides if an inbound HMAC can be checked at all.
            "local_carp_passphrase_configured": !self.carp_passphrase.is_empty(),
        })
    }

    /// Fill in whatever the model's action left out.
    ///
    /// An action that names a field keeps its own value, so a prompt can still deliberately
    /// advertise a different identity from the configured one. Without this the builders
    /// would fall back to protocol constants and the operator's configured group would never
    /// reach the wire — the `ospf` defect the root `CLAUDE.md` records for four of its six
    /// parameters.
    pub fn apply_defaults(&self, action: &mut serde_json::Value) {
        let Some(object) = action.as_object_mut() else {
            return;
        };
        let mut set = |key: &str, value: serde_json::Value| {
            object.entry(key.to_string()).or_insert(value);
        };
        set("variant", json!(self.variant.as_str()));
        set("vrid", json!(self.vrid));
        set("advert_interval", json!(self.advert_interval_seconds));
        set(
            "addresses",
            json!(self
                .addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()),
        );
        match self.variant {
            Variant::Vrrp => {
                set("version", json!(self.version));
                set("priority", json!(self.priority));
            }
            Variant::Carp => {
                set("advskew", json!(self.advskew));
            }
        }
    }
}

/// An advertisement of either variant, assembled but not yet checksummed.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfiguredAdvertisement {
    Vrrp(VrrpAdvertisement),
    Carp(CarpAdvertisement),
}

impl ConfiguredAdvertisement {
    /// Every check that does **not** need a pseudo-header, so an action can be rejected where
    /// the error reaches the model rather than only a log.
    pub fn validate_shape(&self) -> Result<()> {
        match self {
            ConfiguredAdvertisement::Vrrp(advertisement) => advertisement.validate(),
            ConfiguredAdvertisement::Carp(advertisement) => advertisement.validate(),
        }
    }

    /// Serialise. `pseudo` is required for VRRPv3 and ignored otherwise.
    pub fn encode(&self, pseudo: Option<&codec::PseudoHeader>) -> Result<Vec<u8>> {
        match self {
            ConfiguredAdvertisement::Vrrp(advertisement) => advertisement.encode(pseudo),
            ConfiguredAdvertisement::Carp(advertisement) => advertisement.encode(),
        }
    }

    pub fn variant(&self) -> Variant {
        match self {
            ConfiguredAdvertisement::Vrrp(_) => Variant::Vrrp,
            ConfiguredAdvertisement::Carp(_) => Variant::Carp,
        }
    }
}

fn parse_ipv4(text: &str) -> Result<Ipv4Addr> {
    text.trim()
        .parse::<Ipv4Addr>()
        .with_context(|| format!("'{text}' is not a dotted-quad IPv4 address"))
}

fn field_u8(
    action: &serde_json::Value,
    key: &str,
    range: std::ops::RangeInclusive<i64>,
) -> Result<Option<u8>> {
    let Some(value) = action.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let number = value
        .as_i64()
        .with_context(|| format!("'{key}' must be a whole number, got {value}"))?;
    ensure!(
        range.contains(&number),
        "'{key}' must be {}..={}, got {number}",
        range.start(),
        range.end()
    );
    Ok(Some(number as u8))
}

fn field_addresses(action: &serde_json::Value, key: &str) -> Result<Option<Vec<Ipv4Addr>>> {
    let Some(value) = action.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let array = value
        .as_array()
        .with_context(|| format!("'{key}' must be an array of dotted-quad strings, got {value}"))?;
    let mut out = Vec::with_capacity(array.len());
    for entry in array {
        let text = entry
            .as_str()
            .with_context(|| format!("'{key}' entries must be strings, got {entry}"))?;
        out.push(parse_ipv4(text)?);
    }
    Ok(Some(out))
}

fn field_seconds(action: &serde_json::Value, key: &str) -> Result<Option<f64>> {
    let Some(value) = action.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let seconds = value
        .as_f64()
        .with_context(|| format!("'{key}' must be a number of seconds, got {value}"))?;
    Ok(Some(seconds))
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// VRRP / CARP protocol handler.
pub struct VrrpProtocol;

impl VrrpProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Which variant an action asks for, defaulting to the server's configured one.
    pub fn variant_from_action(action: &serde_json::Value, default: Variant) -> Result<Variant> {
        match action.get("variant").and_then(|v| v.as_str()) {
            Some(name) => Variant::from_name(name),
            None => Ok(default),
        }
    }

    /// The variant an action implies when the server's configuration is **not** in scope.
    ///
    /// `execute_action` is called with nothing but the action — by the executor, and by
    /// `tests/executable_examples_test.rs` — so it cannot know that a CARP server is asking.
    /// A model talking to a CARP server has no reason to spell `variant` out, and rejecting
    /// its `advskew` as "a CARP field in a VRRP advertisement" would be nonsense.
    ///
    /// So: an explicit `variant` wins; otherwise a CARP-only field with no VRRP-only field
    /// implies CARP. An action carrying **both** families' fields stays VRRP, so the
    /// contradiction is reported rather than silently resolved.
    ///
    /// This is a fallback for validation only. On the wire the configured variant always
    /// decides, because [`VrrpGroupConfig::apply_defaults`] writes it into the action before
    /// the transport re-validates.
    pub fn inferred_variant(action: &serde_json::Value) -> Result<Variant> {
        if let Some(name) = action.get("variant").and_then(|v| v.as_str()) {
            return Variant::from_name(name);
        }
        let present = |key: &str| {
            action
                .get(key)
                .map(|value| !value.is_null())
                .unwrap_or(false)
        };
        let carp_only = ["advskew", "demote", "counter"].iter().any(|k| present(k));
        let vrrp_only = ["priority", "version"].iter().any(|k| present(k));
        Ok(if carp_only && !vrrp_only {
            Variant::Carp
        } else {
            Variant::Vrrp
        })
    }

    /// Where the packet goes: `"multicast"` (224.0.0.18) or a unicast dotted quad.
    ///
    /// This is not cosmetic for VRRPv3 — the destination address is folded into the checksum
    /// through the pseudo-header, so the same message body addressed elsewhere is different
    /// octets.
    pub fn destination_from_action(action: &serde_json::Value) -> Result<Ipv4Addr> {
        match action.get("destination").and_then(|v| v.as_str()) {
            None | Some("multicast") | Some("") => Ok(VRRP_MULTICAST_IPV4),
            Some(text) => parse_ipv4(text),
        }
    }

    /// Build the advertisement one action asks for, layering the configuration underneath.
    ///
    /// Nothing here touches a socket or a checksum, so it is callable from `execute_action`
    /// with no context at all — which is what makes the declared examples executable.
    pub fn advertisement_from_action(
        action: &serde_json::Value,
        config: &VrrpGroupConfig,
    ) -> Result<ConfiguredAdvertisement> {
        let variant = Self::variant_from_action(action, config.variant)?;
        let vrid = field_u8(action, "vrid", 1..=255)?.unwrap_or(config.vrid);
        let addresses =
            field_addresses(action, "addresses")?.unwrap_or_else(|| config.addresses.clone());
        let interval =
            field_seconds(action, "advert_interval")?.unwrap_or(config.advert_interval_seconds);

        match variant {
            Variant::Vrrp => {
                // CARP-only fields on a VRRP advertisement are refused rather than dropped:
                // silently ignoring a field the model deliberately set is how a model's
                // decision becomes invisible.
                for carp_only in ["advskew", "demote", "counter"] {
                    ensure!(
                        action.get(carp_only).map(|v| v.is_null()).unwrap_or(true),
                        "'{carp_only}' is a CARP field and has no place in a VRRP \
                         advertisement. VRRP elects on 'priority' (higher wins); set \
                         variant to 'carp' if you meant CARP."
                    );
                }
                let version = match field_u8(action, "version", 2..=3)? {
                    Some(v) => v,
                    None => config.version,
                };
                let priority = field_u8(action, "priority", 0..=255)?.unwrap_or(config.priority);
                let advertisement = VrrpAdvertisement {
                    version,
                    vrid,
                    priority,
                    advert_interval_seconds: interval,
                    auth_type: VRRP_AUTH_TYPE_NONE,
                    addresses,
                    checksum: 0,
                };
                advertisement.validate()?;
                Ok(ConfiguredAdvertisement::Vrrp(advertisement))
            }
            Variant::Carp => {
                ensure!(
                    action.get("priority").map(|v| v.is_null()).unwrap_or(true),
                    "'priority' is a VRRP field and CARP has no equivalent. CARP elects on \
                     'advskew', where LOWER wins — the opposite direction from VRRP priority."
                );
                ensure!(
                    action.get("version").map(|v| v.is_null()).unwrap_or(true),
                    "'version' selects between VRRPv2 and VRRPv3 and does not apply to CARP, \
                     whose version is fixed at {CARP_VERSION}."
                );
                let advskew = field_u8(action, "advskew", 0..=255)?.unwrap_or(config.advskew);
                let demote = field_u8(action, "demote", 0..=255)?.unwrap_or(0);
                let counter = match action.get("counter") {
                    Some(value) if !value.is_null() => value.as_u64().with_context(|| {
                        format!("'counter' must be a whole number, got {value}")
                    })?,
                    _ => 0,
                };
                let advbase = interval.round();
                ensure!(
                    (1.0..=255.0).contains(&advbase),
                    "CARP's advbase is a whole-second octet, so advert_interval must be \
                     1..=255 seconds; got {interval}"
                );
                let advertisement = CarpAdvertisement {
                    version: CARP_VERSION,
                    vhid: vrid,
                    advskew,
                    auth_length_words: CARP_AUTH_LEN_WORDS,
                    demote,
                    advbase: advbase as u8,
                    counter,
                    hmac: codec::carp_hmac(
                        config.carp_passphrase.as_bytes(),
                        vrid,
                        &addresses,
                        counter,
                    ),
                    checksum: 0,
                };
                advertisement.validate()?;
                Ok(ConfiguredAdvertisement::Carp(advertisement))
            }
        }
    }
}

impl Default for VrrpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for VrrpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // The raw transport reads the host as the interface address it binds the raw socket
        // to; the UDP test transport binds host:port as an ordinary socket.
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: None,
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    fn protocol_name(&self) -> &'static str {
        "VRRP"
    }

    fn description(&self) -> &'static str {
        "VRRP v2/v3 and CARP first-hop redundancy server (IP protocol 112)"
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP(112)>VRRP"
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "vrrp",
            "carp",
            "virtual router redundancy protocol",
            "common address redundancy protocol",
            "first hop redundancy",
            "gateway failover",
        ]
    }

    fn example_prompt(&self) -> &'static str {
        "Listen for VRRP advertisements on 192.168.1.10 for VRID 1 and report which router is \
         master, without advertising anything yourself"
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Nothing here is user-triggered: an advertisement is only ever a response to what
        // arrived on the segment, and there is no periodic transmitter to configure. See the
        // note on `metadata()` about deliberately not owning an election state machine.
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vrrp_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            VRRP_ADVERTISEMENT_RECEIVED_EVENT.clone(),
            VRRP_MASTER_RESIGNED_EVENT.clone(),
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
            // A SOCK_RAW socket on IP protocol 112. CAP_NET_RAW is sufficient on Linux, so
            // declaring Root would refuse a capability-only process that could in fact run it.
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            // The reaper in AppState::cleanup_old_connections exists for exactly this shape:
            // per-remote-address entries with no connection lifecycle that nothing ever closes.
            .connectionless()
            // Deliberately silent: VRRP has no error form. An advertisement asserts mastership of
            // the virtual router's addresses, so a fabricated one can take over the segment's
            // gateway; backups already treat silence as the normal state.
            .deliberately_silent()
            .implementation(
                "Hand-written codec for VRRPv2 (RFC 3768), VRRPv3 (RFC 5798) and OpenBSD CARP, \
                 which share IP protocol 112 and nothing else — CARP's first octet is 0x21, the \
                 same as a VRRPv2 advertisement, so the packet format is selected by the \
                 'variant' startup parameter rather than sniffed. codec.rs is pure (no I/O, no \
                 async) and holds the version-dependent interval scaling (v2 whole seconds, v3 \
                 centiseconds), the RFC 1071 checksum, VRRPv3's RFC 5798 §5.2.8 pseudo-header, \
                 CARP's 36-octet layout and CARP's HMAC-SHA1 authentication field (the sha1 \
                 crate for the hash; the RFC 2104 construction over it is local because no HMAC \
                 crate is reachable from this feature). Two transports sit over it: a raw \
                 IP-protocol-112 socket \
                 joined to 224.0.0.18, and a UDP transport carrying one complete message per \
                 datagram for unprivileged testing.",
            )
            .llm_control(
                "The model chooses the election. Priority, VRID, advertisement interval, virtual \
                 addresses and destination all come from its action, or from the startup \
                 parameters for whatever it omits. There is NO election state machine and no \
                 periodic transmitter: NetGet never advertises on its own, so a model that stops \
                 answering stops speaking rather than continuing to hold a mastership it cannot \
                 serve. Whether to take part at all is policy — with no server instruction and no \
                 event handler the server observes passively and makes no LLM call, which also \
                 keeps a segment carrying one advertisement per second per group from costing one \
                 round-trip per second.",
            )
            .e2e_testing(
                "The codec is proved against literal specification bytes in \
                 tests/server/vrrp/codec_test.rs: complete VRRPv2 and VRRPv3 advertisements \
                 hand-derived from RFC 3768 §5.1 and RFC 5798 §5.1, the one-second interval as \
                 0x01 under v2 and 0x0064 under v3, both checksums (v3 including its \
                 pseudo-header) computed by hand, and CARP's 36-octet layout. The hash is the \
                 sha1 crate's, so the FIPS 180 / RFC 3174 and RFC 2202 vectors are kept to prove \
                 this code DRIVES it correctly — right buffer, no dropped update, correct HMAC \
                 key padding and inner/outer ordering — rather than to prove SHA-1 itself. \
                 tests/server/vrrp/e2e_test.rs drives the \
                 whole advertisement -> event -> model -> action -> packet path over the UDP \
                 transport, unprivileged, and asserts that an LLM failure puts NOTHING on the \
                 wire. No third-party VRRP or CARP peer has ever spoken to this server.",
            )
            .notes(
                "PROVEN: the codec, against literal specification bytes in both directions, and \
                 the full decision path over the UDP transport. UNPROVEN: the raw IP-protocol-112 \
                 transport has NEVER been executed — nothing in this tree runs privileged — and \
                 no keepalived, no OpenBSD carp interface and no real router has ever exchanged a \
                 packet with it. CARP's HMAC construction is derived from reading OpenBSD's \
                 sys/netinet/ip_carp.c, not from any specification (there is no CARP RFC), and no \
                 live peer has accepted it; only the HMAC-SHA1 primitive underneath is pinned to \
                 published vectors. IPv6 (FF02::12) is not implemented in either direction. \
                 THE HAZARD: a sufficiently high priority WINS THE ELECTION and makes NetGet the \
                 default gateway for the segment, so every host's traffic is sent to a router \
                 that does not forward. That is the protocol's point and its danger; use it on an \
                 isolated segment. ON LLM FAILURE THIS SERVER IS SILENT: an advertisement is a \
                 positive assertion of gateway ownership, VRRP has no error or NAK message, and a \
                 fabricated advertisement can black-hole a segment by winning an election NetGet \
                 cannot serve. The peer's own master-down interval already handles a router that \
                 goes quiet. The failure is recorded in the log only, tagged \
                 decision=fail_closed_llm_error / fail_closed_overloaded, distinct from \
                 decision=model_reject (the model chose no_advertisement) and \
                 decision=model_silent (the model returned nothing usable).",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description:
                    "'raw' (default) opens a SOCK_RAW socket on IP protocol 112 and joins \
                     224.0.0.18; it needs CAP_NET_RAW or root. 'udp' carries one complete VRRP \
                     or CARP message per UDP datagram on the configured host/port — the same \
                     octets, no privilege, no IP layer — for testing and for driving the \
                     protocol from a script."
                        .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
            ParameterDefinition {
                name: "variant".to_string(),
                type_hint: "string".to_string(),
                description:
                    "'vrrp' (default, RFC 3768 / RFC 5798) or 'carp' (OpenBSD's Common Address \
                     Redundancy Protocol). They share IP protocol 112 and NOTHING ELSE — even \
                     the first octet is 0x21 for both a VRRPv2 advertisement and a CARP one, so \
                     received packets are decoded according to this setting rather than sniffed."
                        .to_string(),
                required: false,
                example: json!("vrrp"),
                default: None,
            },
            ParameterDefinition {
                name: "version".to_string(),
                type_hint: "number".to_string(),
                description:
                    "2 (RFC 3768) or 3 (RFC 5798, the default). The difference is not cosmetic: \
                     v2 carries the advertisement interval in whole seconds and eight octets of \
                     zeroed authentication data, while v3 carries centiseconds in a 12-bit field \
                     and folds an IP pseudo-header into the checksum. Ignored when variant is \
                     'carp'."
                        .to_string(),
                required: false,
                example: json!(3),
                default: None,
            },
            ParameterDefinition {
                name: "vrid".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Virtual Router Identifier, 1..=255 (default 1). CARP calls the same field \
                     the virtual host id (vhid). Routers only contend with others sharing this \
                     value."
                        .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
            ParameterDefinition {
                name: "priority".to_string(),
                type_hint: "number".to_string(),
                description:
                    "VRRP priority, 0..=255 (default 100). HIGHER WINS THE ELECTION, and the \
                     winner becomes the default gateway for every host on the segment. 255 is \
                     reserved for the router that genuinely owns the virtual addresses; 0 means \
                     'I am resigning' and makes every backup take over immediately. Not used by \
                     CARP, which elects on advskew."
                        .to_string(),
                required: false,
                example: json!(100),
                default: None,
            },
            ParameterDefinition {
                name: "advert_interval".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Advertisement interval in WHOLE SECONDS, 1..=255 (default 1). VRRPv2 encodes \
                     whole seconds in one octet and CARP uses the value as advbase; VRRPv3 \
                     encodes centiseconds in twelve bits, and its sub-second range \
                     (0.01..=40.95) is reachable through the send_vrrp_advertisement action, \
                     which takes a fractional number. NetGet does not transmit on a timer — this \
                     value is what outgoing advertisements advertise, and what a peer uses to \
                     size its master-down interval."
                        .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
            ParameterDefinition {
                name: "addresses".to_string(),
                type_hint: "array".to_string(),
                description:
                    "The virtual IPv4 addresses this router advertises, as dotted quads (e.g. \
                     [\"192.168.1.1\"]). These are the addresses hosts on the segment use as \
                     their default gateway. Empty by default, because advertising an address by \
                     default would claim one nobody asked for."
                        .to_string(),
                required: false,
                example: json!(["192.168.1.1"]),
                default: None,
            },
            ParameterDefinition {
                name: "advskew".to_string(),
                type_hint: "number".to_string(),
                description:
                    "CARP advertisement skew, 0..=255 (default 0). The effective interval is \
                     advbase + advskew/256 seconds, and the host that advertises soonest wins — \
                     so LOWER WINS, the opposite direction from VRRP priority. Ignored when \
                     variant is 'vrrp'."
                        .to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "carp_passphrase".to_string(),
                type_hint: "string".to_string(),
                description:
                    "CARP group passphrase. Zero-padded (or truncated) to 20 octets and used as \
                     the HMAC-SHA1 key over version, type, vhid, the virtual addresses and the \
                     counter, exactly as OpenBSD's ifconfig does. With none configured, outgoing \
                     advertisements are keyed with all zeros and inbound HMACs are reported as \
                     unverifiable rather than as valid. Ignored when variant is 'vrrp'."
                        .to_string(),
                required: false,
                example: json!("lab-passphrase"),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model decides the election.
            json!({
                "type": "open_server",
                "host": "192.168.1.10",
                "base_stack": "vrrp",
                "instruction": "You are VRRP router for VRID 1 on an isolated lab segment. \
                                Answer advertisements from lower-priority routers with your own \
                                at priority 200 for 192.168.1.1. If anything is unclear, answer \
                                with no_advertisement.",
                "startup_params": {"vrid": 1, "priority": 200, "addresses": ["192.168.1.1"]}
            }),
            // Script mode: a deterministic answer, no LLM round-trip per advertisement.
            json!({
                "type": "open_server",
                "host": "192.168.1.10",
                "base_stack": "vrrp",
                "startup_params": {"vrid": 1, "addresses": ["192.168.1.1"]},
                "event_handlers": [{
                    "event_pattern": "vrrp_master_resigned",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {'type': 'send_vrrp_advertisement', 'priority': 200}"
                    }
                }]
            }),
            // Static mode: observe only. The safe default and the one to reach for first.
            json!({
                "type": "open_server",
                "host": "192.168.1.10",
                "base_stack": "vrrp",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "no_advertisement"}]
                    }
                }]
            }),
        )
    }
}

impl Server for VrrpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use super::VrrpServer;

            let config = VrrpGroupConfig::from_startup_params(ctx.startup_params.as_ref())?;
            let listen_addr = ctx.legacy_listen_addr();

            VrrpServer::spawn_with_llm_actions(
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
            "send_vrrp_advertisement" => {
                // Validate now, against the protocol defaults, so a malformed action is
                // rejected where the error reaches the model. The transport rebuilds it with
                // the operator's configured group underneath and computes the checksum there,
                // which is the only step that needs the source and destination addresses.
                let config = VrrpGroupConfig {
                    variant: VrrpProtocol::inferred_variant(&action)?,
                    ..VrrpGroupConfig::default()
                };
                VrrpProtocol::advertisement_from_action(&action, &config)?;
                VrrpProtocol::destination_from_action(&action)?;
                Ok(ActionResult::Custom {
                    name: "vrrp_action".to_string(),
                    data: action,
                })
            }
            "no_advertisement" => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown VRRP action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

/// The actions every VRRP event may be answered with.
pub fn vrrp_actions() -> Vec<ActionDefinition> {
    vec![send_vrrp_advertisement_action(), no_advertisement_action()]
}

fn send_vrrp_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_vrrp_advertisement".to_string(),
        description: "Transmit one VRRP (or CARP) advertisement. DANGEROUS ON A REAL NETWORK: an \
             advertisement is a positive claim to own the virtual gateway address, and a \
             priority higher than the current master's wins the election — every host on the \
             segment then sends its off-link traffic to NetGet, which does not forward it. \
             Every field is optional; anything omitted comes from the server's startup \
             parameters. NetGet sends this once, when you ask; it never advertises on a timer."
            .to_string(),
        parameters: vec![
            param(
                "variant",
                "string",
                "'vrrp' (RFC 3768/5798) or 'carp' (OpenBSD). Defaults to the server's \
                 configured variant. They share IP protocol 112 and no packet fields.",
                false,
            ),
            param(
                "version",
                "number",
                "VRRP only: 2 (RFC 3768) or 3 (RFC 5798). Defaults to the server's configured \
                 version. Note the advertisement interval field differs between them — whole \
                 seconds in v2, centiseconds in v3 — but you always give seconds here and \
                 NetGet scales it.",
                false,
            ),
            param(
                "vrid",
                "number",
                "Virtual Router Identifier, 1..=255 (CARP: the vhid). Only routers sharing \
                 this value contend with each other.",
                false,
            ),
            param(
                "priority",
                "number",
                "VRRP only, 0..=255. HIGHER WINS. 255 asserts this router genuinely owns the \
                 virtual addresses — do not claim it unless that is true. 0 means resign, \
                 which makes every backup take over at once instead of waiting out its \
                 master-down interval. CARP has no equivalent; use advskew.",
                false,
            ),
            param(
                "advert_interval",
                "number",
                "Advertisement interval in seconds. VRRPv2 allows whole seconds 1..=255; \
                 VRRPv3 allows 0.01..=40.95; CARP uses the whole-second part as advbase.",
                false,
            ),
            param(
                "addresses",
                "array",
                "The virtual IPv4 addresses being claimed, as dotted quads, e.g. \
                 [\"192.168.1.1\"].",
                false,
            ),
            param(
                "advskew",
                "number",
                "CARP only, 0..=255. The effective interval is advbase + advskew/256 seconds \
                 and the earliest advertiser wins, so LOWER WINS — the opposite direction from \
                 VRRP priority.",
                false,
            ),
            param(
                "demote",
                "number",
                "CARP only, 0..=255. The sender's demotion counter; a higher value tells peers \
                 this host is less able to serve the group.",
                false,
            ),
            param(
                "counter",
                "number",
                "CARP only. The replay counter covered by the HMAC. Echo back one higher than \
                 the counter you were told about, or leave it out for 0.",
                false,
            ),
            param(
                "destination",
                "string",
                "'multicast' (default, 224.0.0.18) or a unicast dotted quad. This is not \
                 cosmetic under VRRPv3: the destination address is folded into the checksum \
                 through the RFC 5798 pseudo-header.",
                false,
            ),
        ],
        example: json!({
            "type": "send_vrrp_advertisement",
            "variant": "vrrp",
            "version": 3,
            "vrid": 1,
            "priority": 200,
            "advert_interval": 1,
            "addresses": ["192.168.1.1"],
            "destination": "multicast"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> VRRP advertisement vrid={vrid} priority={priority}")
                .with_debug(
                    "VRRP send_vrrp_advertisement: variant={variant} version={version} \
                     vrid={vrid} priority={priority} interval={advert_interval} \
                     addresses={addresses} dest={destination}",
                )
                .with_trace("VRRP advertisement action: {json_pretty(.)}"),
        ),
    }
}

fn no_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_advertisement".to_string(),
        description:
            "Answer with nothing. This is a real decision, not a failure: a VRRP listener that \
             observes without advertising cannot perturb the election, and it is the correct \
             answer whenever you are unsure. Prefer it to guessing a priority — an \
             advertisement that wins an election NetGet cannot serve black-holes every host on \
             the segment."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "no_advertisement" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> VRRP silent (no advertisement)")
                .with_debug("VRRP no_advertisement: observed, nothing transmitted"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

fn advertisement_event_parameters() -> Vec<Parameter> {
    vec![
        param(
            "variant",
            "string",
            "'vrrp' or 'carp' — which of the two protocols sharing IP protocol 112 this was \
             decoded as, per the server's configuration.",
            true,
        ),
        param(
            "version",
            "number",
            "2 or 3 for VRRP; 2 for CARP (its own version number, unrelated to VRRP's).",
            true,
        ),
        param(
            "vrid",
            "number",
            "Virtual Router Identifier (CARP: vhid).",
            true,
        ),
        param(
            "priority",
            "number",
            "VRRP only. 0 = the sender is resigning, 255 = the sender claims to own the \
             addresses, higher wins. Absent for CARP.",
            false,
        ),
        param(
            "advert_interval",
            "number",
            "The interval the sender advertises, in seconds, already converted from whichever \
             unit its version uses.",
            true,
        ),
        param(
            "addresses",
            "array",
            "The virtual IPv4 addresses the sender is claiming, as dotted quads.",
            false,
        ),
        param(
            "source_address",
            "string",
            "Where the advertisement came from.",
            true,
        ),
        param(
            "checksum_valid",
            "boolean",
            "Whether the packet's checksum recomputes. Null when it could not be checked.",
            false,
        ),
        param(
            "checksum_scope",
            "string",
            "'message' for VRRPv2 and CARP; 'pseudo_header_and_message' for VRRPv3, whose \
             checksum covers the IP source and destination too.",
            true,
        ),
        param(
            "auth_type",
            "number",
            "VRRPv2 only. 0 in anything conformant with RFC 3768; non-zero means the sender is \
             using RFC 2338-era authentication.",
            false,
        ),
        param(
            "advskew",
            "number",
            "CARP only. Lower wins the election.",
            false,
        ),
        param(
            "advbase",
            "number",
            "CARP only. Base interval in seconds.",
            false,
        ),
        param(
            "demote",
            "number",
            "CARP only. The sender's demotion counter.",
            false,
        ),
        param(
            "counter",
            "number",
            "CARP only. The sender's replay counter.",
            false,
        ),
        param(
            "hmac_valid",
            "boolean",
            "CARP only. Whether the sender's HMAC matches the configured passphrase. Null when \
             no passphrase is configured, so it could not be checked — never assume true.",
            false,
        ),
        param(
            "local_priority",
            "number",
            "This server's own configured priority, for comparison with the sender's.",
            false,
        ),
        param(
            "local_vrid",
            "number",
            "This server's own configured VRID. An advertisement for a different VRID is not \
             contending with this router at all.",
            false,
        ),
        param(
            "local_addresses",
            "array",
            "The virtual addresses this server is configured to claim.",
            false,
        ),
    ]
}

pub static VRRP_ADVERTISEMENT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vrrp_advertisement_received",
        "A VRRP or CARP advertisement arrived: another router is claiming the virtual gateway \
         address for this group. Compare its priority with local_priority — higher wins, and \
         the winner becomes the default gateway for every host on the segment. Answer with \
         no_advertisement unless you intend to contest the election, because winning it makes \
         NetGet the gateway for traffic it cannot forward.",
        json!({ "type": "no_advertisement" }),
    )
    .with_parameters(advertisement_event_parameters())
    .with_actions(vrrp_actions())
    .with_alternative_example(json!({
        "type": "send_vrrp_advertisement",
        "vrid": 1,
        "priority": 200,
        "addresses": ["192.168.1.1"],
        "destination": "multicast"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("VRRP advertisement from {source_address}: vrid={vrid} priority={priority}")
            .with_debug(
                "VRRP {variant}v{version} from {source_address}: vrid={vrid} \
                 priority={priority} interval={advert_interval} addresses={addresses} \
                 checksum_valid={checksum_valid}",
            )
            .with_trace("VRRP advertisement: {json_pretty(.)}"),
    )
});

pub static VRRP_MASTER_RESIGNED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vrrp_master_resigned",
        "The master resigned: it sent an advertisement with priority 0, which exists precisely \
         so backups take over IMMEDIATELY instead of waiting out their master-down interval \
         (RFC 3768 §6.4.3). The election is open right now. Answering with \
         send_vrrp_advertisement at a high priority will very likely win it — and make NetGet \
         the default gateway for the segment. Answer with no_advertisement unless that is what \
         you intend.",
        json!({ "type": "no_advertisement" }),
    )
    .with_parameters(advertisement_event_parameters())
    .with_actions(vrrp_actions())
    .with_alternative_example(json!({
        "type": "send_vrrp_advertisement",
        "vrid": 1,
        "priority": 200,
        "addresses": ["192.168.1.1"],
        "destination": "multicast"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("VRRP master {source_address} resigned (priority 0) for vrid={vrid}")
            .with_debug(
                "VRRP master resigned: source={source_address} vrid={vrid} \
                 addresses={addresses} local_priority={local_priority}",
            )
            .with_trace("VRRP master resigned: {json_pretty(.)}"),
    )
});
