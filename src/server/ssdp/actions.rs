//! SSDP / UPnP discovery protocol vocabulary and executor.
//!
//! # Every SSDP reply is a positive assertion
//!
//! There is no such thing as an SSDP error message. The protocol has exactly two things a
//! device can put on the wire — a `200 OK` answering an M-SEARCH, and a `NOTIFY` — and both
//! of them mean *"a device of this type exists, and its description is at this URL"*. There
//! is no code for "I do not know", no equivalent of DNS SERVFAIL or HTTP 503.
//!
//! That makes SSDP a member of the deliberately-silent class in the root `CLAUDE.md`, and
//! for the strongest reason in that list. A control point caches what it is told for
//! `CACHE-CONTROL: max-age` seconds — half an hour by convention — and will then go and
//! fetch the `LOCATION` URL. A fabricated advertisement therefore does not merely mislead
//! one peer once; it plants a non-existent device in every listener's device table and sends
//! them all at a URL that answers nothing. Silence, by contrast, is the *normal* SSDP
//! outcome: a device that does not match the search target is required by UDA 1.1 §1.3.3 to
//! say nothing at all, so every control point already handles it.
//!
//! Three structural consequences, each of which a reader can point at:
//!
//! 1. **Nothing here can synthesise a response.** `execute_action` produces only what a
//!    named action asked for. There is no default, no fallback and no "if the model said
//!    nothing, advertise ourselves".
//! 2. **Declining is an action of its own.** `no_response` exists so that "this device does
//!    not match the search target" is a decision the model states, distinguishable in the
//!    log from a model that returned nothing and from a backend that fell over. That is the
//!    `radius` shape applied to a protocol whose safe default is silence rather than denial.
//! 3. **An LLM failure writes nothing.** `mod.rs` logs `decision=fail_closed_llm_error` and
//!    sends no datagram. There is deliberately no `WireFailure` string on the wire, because
//!    there is no header in which SSDP could carry one — anything we emitted would still be
//!    a well-formed advertisement.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::message::{self, NotifyMessage, SearchResponse};

/// `SERVER` header used when neither the action nor the `server_header` startup parameter
/// names one. The UDA 1.1 grammar is `OS/version UPnP/1.1 product/version`.
pub const DEFAULT_SERVER_HEADER: &str = "NetGet/1.0 UPnP/1.1 NetGet-SSDP/1.0";

/// Default `CACHE-CONTROL: max-age`, in seconds. UDA 1.1 §1.2.2 requires at least 1800 and
/// recommends it as the value.
pub const DEFAULT_MAX_AGE: u32 = 1800;

/// Per-request context, built by `mod.rs` from the datagram that provoked the LLM call.
///
/// The registry holds a context-free `SsdpProtocol`; `mod.rs` builds one of these per
/// datagram. It exists for two things the model should not have to restate, and one it
/// cannot know:
///
/// * the search target to echo when the model's action omits `st`;
/// * the operator's `server_header` default;
/// * the `HOST` a NOTIFY must be addressed to, which differs between the IPv4 and IPv6
///   groups.
#[derive(Clone, Debug)]
pub struct RequestContext {
    /// `ST` from the M-SEARCH being answered, if this is an M-SEARCH at all.
    pub search_target: Option<String>,
    /// `SERVER` header default from `server_header`.
    pub server_header: String,
    /// `HOST` for an outbound NOTIFY, e.g. `239.255.255.250:1900` or `[FF02::C]:1900`.
    pub notify_host: String,
}

impl RequestContext {
    /// The IPv4 defaults, for a server that never resolved anything else.
    pub fn ipv4_defaults(search_target: Option<String>) -> Self {
        Self {
            search_target,
            server_header: DEFAULT_SERVER_HEADER.to_string(),
            notify_host: format!("{}:{}", message::SSDP_GROUP_V4, message::SSDP_PORT),
        }
    }
}

/// SSDP protocol handler.
pub struct SsdpProtocol {
    request: Option<RequestContext>,
}

impl Default for SsdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl SsdpProtocol {
    pub fn new() -> Self {
        Self { request: None }
    }

    pub fn for_request(ctx: RequestContext) -> Self {
        Self { request: Some(ctx) }
    }

    fn server_default(&self) -> &str {
        match &self.request {
            Some(ctx) => &ctx.server_header,
            None => DEFAULT_SERVER_HEADER,
        }
    }

    fn notify_host(&self) -> String {
        match &self.request {
            Some(ctx) => ctx.notify_host.clone(),
            None => format!("{}:{}", message::SSDP_GROUP_V4, message::SSDP_PORT),
        }
    }

    /// The `ST` to put in a search response: what the model said, or — when it said nothing
    /// — the target the control point asked for.
    ///
    /// Echoing the request's `ST` is not the server inventing an answer: the answer is the
    /// whole advertisement, and the model has already decided to send one. What the echo
    /// prevents is a response a control point silently discards, which is
    /// indistinguishable from the server being down. The one case where it cannot help is a
    /// wildcard search (`ssdp:all`, `upnp:rootdevice`), because the response has to name the
    /// *concrete* type — see `resolve_st`.
    fn resolve_st(&self, action: &serde_json::Value) -> Result<String> {
        if let Some(st) = action.get("st").and_then(|v| v.as_str()) {
            if !st.trim().is_empty() {
                return Ok(st.trim().to_string());
            }
        }
        let requested = self
            .request
            .as_ref()
            .and_then(|c| c.search_target.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        match requested {
            Some("ssdp:all") | Some("upnp:rootdevice") | None => Err(anyhow::anyhow!(
                "send_ssdp_response needs an 'st'. The search target was {}, which is a \
                 wildcard, so the response must name the concrete device or service type \
                 this answer is for (e.g. \"urn:schemas-upnp-org:device:MediaServer:1\"). \
                 Only a search for a specific type can have its ST echoed automatically.",
                requested
                    .map(|s| format!("'{s}'"))
                    .unwrap_or_else(|| { "not available in this context".to_string() })
            )),
            Some(other) => Ok(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

fn required_str(action: &serde_json::Value, key: &str, why: &str) -> Result<String> {
    let raw = action
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("'{key}' is required: {why}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("'{key}' must not be empty: {why}"));
    }
    message::validate_header_piece("value", key, trimmed)?;
    Ok(trimmed.to_string())
}

fn optional_str(action: &serde_json::Value, key: &str) -> Result<Option<String>> {
    match action.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => {
            let trimmed = s.trim();
            message::validate_header_piece("value", key, trimmed)?;
            Ok(Some(trimmed.to_string()))
        }
        _ => Ok(None),
    }
}

/// `LOCATION` must be a URL a control point can actually fetch.
///
/// This is checked rather than passed through because the whole meaning of a response is
/// "the description document is *there*". A LOCATION that is not an absolute HTTP URL makes
/// the advertisement unusable while still looking valid on the wire, which is exactly the
/// class of failure that is impossible to debug from the client end.
fn parse_location(action: &serde_json::Value, key: &str) -> Result<String> {
    let raw = required_str(
        action,
        key,
        "it is the absolute http(s) URL of the device description document that this \
         advertisement points a control point at",
    )?;
    let url = url::Url::parse(&raw)
        .with_context(|| format!("'{key}' is not a valid absolute URL: {raw:?}"))?;
    match url.scheme() {
        "http" | "https" => Ok(raw),
        other => Err(anyhow::anyhow!(
            "'{key}' has scheme '{other}'; a UPnP LOCATION must be http or https because a \
             control point fetches the description document over HTTP"
        )),
    }
}

fn parse_max_age(action: &serde_json::Value) -> Result<u32> {
    match action.get("cache_control_max_age") {
        None | Some(serde_json::Value::Null) => Ok(DEFAULT_MAX_AGE),
        Some(v) => {
            let n = v
                .as_u64()
                .context("'cache_control_max_age' must be a non-negative number of seconds")?;
            u32::try_from(n).context("'cache_control_max_age' is too large for a max-age")
        }
    }
}

/// `extra_headers` as an ordered list, with every name and value checked for CR/LF.
///
/// A map, not a blob — the root `CLAUDE.md` rule. `serde_json::Map` preserves insertion
/// order only with the `preserve_order` feature, which is not enabled here, so the output is
/// sorted; that is deterministic and SSDP attaches no meaning to header order.
fn parse_extra_headers(action: &serde_json::Value) -> Result<Vec<(String, String)>> {
    let Some(value) = action.get("extra_headers") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let obj = value.as_object().context(
        "'extra_headers' must be an object of header name to value, e.g. \
         {\"BOOTID.UPNP.ORG\": \"1\"}",
    )?;

    const RESERVED: &[&str] = &[
        "CACHE-CONTROL",
        "DATE",
        "EXT",
        "LOCATION",
        "SERVER",
        "ST",
        "USN",
    ];

    let mut out = Vec::with_capacity(obj.len());
    for (name, v) in obj {
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow::anyhow!("'extra_headers' has an empty header name"));
        }
        message::validate_header_piece("name", name, name)?;
        if name.contains(':') {
            return Err(anyhow::anyhow!(
                "extra header name '{name}' contains ':', which would produce a malformed \
                 header line"
            ));
        }
        let upper = name.to_ascii_uppercase();
        if RESERVED.contains(&upper.as_str()) {
            return Err(anyhow::anyhow!(
                "'{name}' is one of the mandatory response headers and is set from this \
                 action's own parameters ({}). Setting it again through extra_headers would \
                 emit it twice.",
                RESERVED.join(", ")
            ));
        }
        let value = v
            .as_str()
            .with_context(|| format!("extra header '{name}' must have a string value; got {v}"))?;
        message::validate_header_piece("value", name, value)?;
        out.push((upper, value.trim().to_string()));
    }
    Ok(out)
}

/// The three NTS values UDA 1.1 defines. Anything else is refused rather than forwarded:
/// a control point ignores an unknown NTS, so an unchecked one is a silent no-op.
fn parse_nts(action: &serde_json::Value) -> Result<String> {
    let nts = required_str(
        action,
        "nts",
        "it says which kind of announcement this is: \"ssdp:alive\", \"ssdp:byebye\" or \
         \"ssdp:update\"",
    )?;
    match nts.as_str() {
        "ssdp:alive" | "ssdp:byebye" | "ssdp:update" => Ok(nts),
        other => Err(anyhow::anyhow!(
            "Unknown nts '{other}'. UDA 1.1 defines exactly three: \"ssdp:alive\" (the \
             device is present), \"ssdp:byebye\" (it is leaving) and \"ssdp:update\" (its \
             description changed). A control point ignores anything else."
        )),
    }
}

fn p(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: false,
    }
}

fn required(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: true,
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

fn send_ssdp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ssdp_response".to_string(),
        description: "Answer an M-SEARCH with a unicast HTTP/1.1 200 OK, asserting that a \
                      device of type 'st' exists here and that its description document is \
                      at 'location'. Send this ONLY when the device you are playing actually \
                      matches the search target — a control point will cache what you say \
                      for cache_control_max_age seconds and then fetch the LOCATION URL. If \
                      it does not match, use no_response."
            .to_string(),
        parameters: vec![
            required(
                "st",
                "string",
                "The device or service type this response is for, e.g. \
                 'upnp:rootdevice', 'urn:schemas-upnp-org:device:MediaServer:1' or a \
                 'uuid:...'. It MUST be the concrete type. When the search target was a \
                 specific type it is echoed automatically if you omit this, but a search \
                 for 'ssdp:all' or 'upnp:rootdevice' has no single answer, so name the type",
            ),
            required(
                "usn",
                "string",
                "Unique Service Name: the composite identity of this advertisement, \
                 conventionally 'uuid:<device-uuid>::<st>' (or just 'uuid:<device-uuid>' \
                 when st is that uuid). It is what a control point de-duplicates on",
            ),
            required(
                "location",
                "string",
                "Absolute http(s) URL of the device description XML, e.g. \
                 'http://192.168.1.10:8080/description.xml'. Must be reachable; a control \
                 point fetches it immediately",
            ),
            p(
                "server",
                "string",
                "SERVER header, in the form 'OS/version UPnP/1.1 product/version'. Defaults \
                 to the server's server_header startup parameter",
            ),
            p(
                "cache_control_max_age",
                "number",
                "Seconds a control point may cache this advertisement. UDA 1.1 requires at \
                 least 1800, which is the default",
            ),
            p(
                "extra_headers",
                "object",
                "Additional headers as a name-to-value map, e.g. \
                 {\"BOOTID.UPNP.ORG\": \"1\", \"CONFIGID.UPNP.ORG\": \"7\"}. The mandatory \
                 headers (CACHE-CONTROL, DATE, EXT, LOCATION, SERVER, ST, USN) come from the \
                 parameters above and must not be repeated here",
            ),
        ],
        example: json!({
            "type": "send_ssdp_response",
            "st": "urn:schemas-upnp-org:device:MediaServer:1",
            "usn": "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33::urn:schemas-upnp-org:device:MediaServer:1",
            "location": "http://192.168.1.10:8080/description.xml",
            "server": "Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0",
            "cache_control_max_age": 1800
        }),
        log_template: None,
    }
}

fn send_ssdp_notify_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ssdp_notify".to_string(),
        description: "Announce to the SSDP multicast group with NOTIFY * HTTP/1.1. \
                      'ssdp:alive' asserts the device is present, 'ssdp:byebye' that it is \
                      leaving, 'ssdp:update' that its description changed. This is broadcast \
                      to every listener on the link, so send it only when the announcement \
                      is true of the device you are playing."
            .to_string(),
        parameters: vec![
            required(
                "nt",
                "string",
                "Notification Type: the device or service type being announced, e.g. \
                 'upnp:rootdevice' or 'urn:schemas-upnp-org:device:MediaServer:1'",
            ),
            required(
                "nts",
                "string",
                "'ssdp:alive', 'ssdp:byebye' or 'ssdp:update'",
            ),
            required(
                "usn",
                "string",
                "Unique Service Name, conventionally 'uuid:<device-uuid>::<nt>'",
            ),
            p(
                "location",
                "string",
                "Absolute http(s) URL of the device description XML. Required for \
                 'ssdp:alive' and 'ssdp:update'; omitted from an 'ssdp:byebye', which \
                 carries only HOST, NT, NTS and USN",
            ),
            p(
                "server",
                "string",
                "SERVER header. Defaults to the server_header startup parameter. Not sent \
                 on an ssdp:byebye",
            ),
            p(
                "cache_control_max_age",
                "number",
                "Seconds a control point may cache this announcement; default 1800. Not \
                 sent on an ssdp:byebye",
            ),
        ],
        example: json!({
            "type": "send_ssdp_notify",
            "nt": "urn:schemas-upnp-org:device:MediaServer:1",
            "nts": "ssdp:alive",
            "usn": "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33::urn:schemas-upnp-org:device:MediaServer:1",
            "location": "http://192.168.1.10:8080/description.xml"
        }),
        log_template: None,
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description: "Say nothing, deliberately. This is the CORRECT and most common answer \
                      in SSDP: UDA 1.1 §1.3.3 requires a device whose type does not match \
                      the search target to stay silent, and every control point expects \
                      that. Use it whenever the search target does not describe the device \
                      you are playing. It is a real decision — the server records it as \
                      yours, distinct from you returning nothing at all."
            .to_string(),
        parameters: vec![p(
            "reason",
            "string",
            "Why nothing is being sent, for the log. Not put on the wire",
        )],
        example: json!({
            "type": "no_response",
            "reason": "search target urn:schemas-upnp-org:device:Printer:1 does not match this media server"
        }),
        log_template: None,
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

pub static SSDP_MSEARCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_msearch",
        "A control point is searching for UPnP devices. Answer with send_ssdp_response ONLY \
         if the device you are playing matches the search target; otherwise answer with \
         no_response, which is what a real device does and is the common case. There is no \
         error response in SSDP — anything you send is an assertion that a device exists at \
         the LOCATION you name.",
        json!({
            "type": "send_ssdp_response",
            "st": "urn:schemas-upnp-org:device:MediaServer:1",
            "usn": "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33::urn:schemas-upnp-org:device:MediaServer:1",
            "location": "http://192.168.1.10:8080/description.xml"
        }),
    )
    .with_parameters(vec![
        p(
            "st",
            "string",
            "Search Target. Either a concrete type ('urn:schemas-upnp-org:device:...', \
             'uuid:...'), or the wildcard 'ssdp:all' (every device and service), or \
             'upnp:rootdevice' (root devices only). For a wildcard you must name the \
             concrete type in your response's 'st'",
        ),
        p(
            "mx",
            "number",
            "Maximum wait, in seconds, the control point will tolerate before an answer \
             (1-5). The server already applies a random delay up to this bound, capped by \
             its max_response_delay_ms parameter; you do not need to do anything with it",
        ),
        p(
            "man",
            "string",
            "The MAN header verbatim. A conforming M-SEARCH sends \"ssdp:discover\" \
             including the quotes; anything else means the sender is not doing UPnP \
             discovery and is usually worth ignoring",
        ),
        p(
            "host",
            "string",
            "The HOST header the search was addressed to — '239.255.255.250:1900' for a \
             multicast search, or this server's own address for a unicast one",
        ),
        p("source_address", "string", "ip:port the search came from"),
        p(
            "user_agent",
            "string",
            "USER-AGENT header, naming the control point's OS and product, or null",
        ),
        p(
            "headers",
            "object",
            "Every header in the message as a name-to-value map, including ones not broken \
             out above",
        ),
    ])
    .with_actions(vec![send_ssdp_response_action(), no_response_action()])
});

pub static SSDP_NOTIFY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_notify",
        "Another device announced itself on the SSDP multicast group. Nothing is expected in \
         reply — a NOTIFY is not a request — so no_response is almost always right. You may \
         answer with send_ssdp_notify to announce this server in turn, which multicasts to \
         everyone on the link.",
        json!({ "type": "no_response", "reason": "a NOTIFY needs no answer" }),
    )
    .with_parameters(vec![
        p(
            "nt",
            "string",
            "Notification Type: the device or service type being announced",
        ),
        p(
            "nts",
            "string",
            "'ssdp:alive', 'ssdp:byebye' or 'ssdp:update'",
        ),
        p("usn", "string", "Unique Service Name of the announcer"),
        p(
            "location",
            "string",
            "URL of the announcer's description document, or null (a byebye carries none)",
        ),
        p("server", "string", "The announcer's SERVER header, or null"),
        p(
            "cache_control_max_age",
            "number",
            "Seconds the announcement is valid for, from CACHE-CONTROL, or null",
        ),
        p("host", "string", "The HOST header of the announcement"),
        p(
            "source_address",
            "string",
            "ip:port the announcement came from",
        ),
        p(
            "headers",
            "object",
            "Every header in the message as a name-to-value map",
        ),
    ])
    .with_actions(vec![send_ssdp_notify_action(), no_response_action()])
});

// ---------------------------------------------------------------------------
// Protocol / Server impls
// ---------------------------------------------------------------------------

impl Protocol for SsdpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // SSDP is purely reactive here. An async action would be dispatched on the
        // registry's stateless instance, which owns no socket, so it could only ever return
        // NoAction — an advertised verb that silently does nothing. See CLAUDE.md's
        // "Announcing on our own initiative".
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_ssdp_response_action(),
            send_ssdp_notify_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "SSDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![SSDP_MSEARCH_EVENT.clone(), SSDP_NOTIFY_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SSDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Narrow on purpose. "discovery" would hijack keyword resolution from mdns, llmnr
        // and netbios-ns, which are all discovery protocols too.
        vec![
            "ssdp",
            "upnp",
            "upnp discovery",
            "m-search",
            "ssdp:discover",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Every datagram is its own peer entry and nothing closes it, so the 10-second
            // idle sweep is what keeps the connection list from growing without bound. This
            // flag is what enables it (see the root CLAUDE.md).
            .connectionless()
            // Deliberately silent: SSDP has no error message - a 200 OK and a NOTIFY both assert
            // that a device exists at a URL, and a control point caches that for max-age. A device
            // that does not match a search is required to say nothing, so silence is normal.
            .deliberately_silent()
            .state(DevelopmentState::Experimental)
            // 1900 is above 1023, so PrivilegedPort would be dead code — the
            // svn/PrivilegedPort(3690) mistake.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1900)
            .implementation(
                "Hand-rolled HTTPU codec (src/server/ssdp/message.rs) over a tokio \
                 UdpSocket. Parses M-SEARCH and NOTIFY, renders the UDA 1.1 §1.3.3 response \
                 header set and §1.2 announcements, applies the MX response jitter, and \
                 attempts a multicast group join for 239.255.255.250 / [FF02::C] that is \
                 logged but non-fatal when it fails. Does NOT implement the UPnP device \
                 description document, SOAP control, GENA eventing, or any HTTP server for \
                 the LOCATION URL it advertises: the model supplies a LOCATION, and \
                 something else must serve it.",
            )
            .llm_control(
                "The model decides whether this server matches each search target at all, \
                 and invents every device: its type, UUID, USN, description URL, SERVER \
                 string and cache lifetime. Declining is an explicit action (no_response) \
                 rather than an absence.",
            )
            .e2e_testing(
                "Mocked end-to-end through the real binary over a raw UDP socket bound to \
                 127.0.0.1, sending unicast M-SEARCH and NOTIFY. Codec asserted against \
                 literal UDA 1.1 message text. NOT validated against any third-party UPnP \
                 control point: no Rust SSDP client found could be pointed at a unicast \
                 loopback address and an ephemeral port, and the real-world control points \
                 (Windows/macOS/Sonos) only ever multicast to 239.255.255.250:1900, which \
                 needs the privileged well-known port and a real link.",
            )
            .notes(
                "DELIBERATELY SILENT ON FAILURE. SSDP has no error message: both messages a \
                 device can send are positive assertions that a device exists at a URL, and \
                 a control point caches them for max-age and then fetches that URL. So an \
                 LLM error, an unusable answer, or an explicit no_response all put NOTHING \
                 on the wire, and the distinction is carried in the log as \
                 decision=fail_closed_llm_error / model_silent / model_reject. Do not \
                 'fix' the silence with a WireFailure string. The multicast join is \
                 best-effort and logged rather than fatal; a unicast M-SEARCH sent straight \
                 to the port is answered whether or not it succeeded. Measured on macOS: \
                 the join succeeds even from a 127.0.0.1 bind, but SENDING to the group \
                 from one fails with EADDRNOTAVAIL, which is what notify_target is for.",
            )
            .max_inbound_bytes(crate::server::ssdp::message::MAX_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "SSDP / UPnP discovery server (HTTPU over UDP): answers M-SEARCH and multicasts \
         NOTIFY announcements"
    }

    fn example_prompt(&self) -> &'static str {
        "run an ssdp server on port 1900 pretending to be a MediaServer at \
         http://192.168.1.10:8080/description.xml; answer searches for MediaServer and \
         ssdp:all, and stay silent for anything else"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "max_response_delay_ms".to_string(),
                type_hint: "number".to_string(),
                description: "Ceiling, in milliseconds, on the random delay applied before \
                              answering an M-SEARCH. A real device waits a random interval \
                              between 0 and the request's MX seconds so a whole network's \
                              answers do not arrive at once, and this cap keeps that \
                              realistic without making every exchange take up to 5 seconds. \
                              The actual delay is uniform over 0..min(MX*1000, this). \
                              Default 1000; set 0 to answer immediately."
                    .to_string(),
                required: false,
                example: json!(1000),
                default: None,
            },
            ParameterDefinition {
                name: "server_header".to_string(),
                type_hint: "string".to_string(),
                description: "Default SERVER header for responses and announcements, in the \
                              UDA 1.1 form 'OS/version UPnP/1.1 product/version'. An \
                              action's own 'server' parameter overrides it. Default \
                              'NetGet/1.0 UPnP/1.1 NetGet-SSDP/1.0'."
                    .to_string(),
                required: false,
                example: json!("Linux/6.1 UPnP/1.1 MiniDLNA/1.3.0"),
                default: None,
            },
            ParameterDefinition {
                name: "join_multicast".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to join the SSDP multicast group (239.255.255.250 for \
                              IPv4, FF02::C for IPv6) so multicast M-SEARCHes are received. \
                              Default true. The join is best-effort: if it fails the server \
                              logs a warning and keeps running, and still answers unicast \
                              M-SEARCH sent straight to its port."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "multicast_interface".to_string(),
                type_hint: "string".to_string(),
                description: "Local IPv4 address of the interface to join the group on, e.g. \
                              '192.168.1.10'. Default '0.0.0.0', letting the kernel choose. \
                              Only used for an IPv4 bind; an IPv6 bind joins on interface \
                              index 0."
                    .to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
            ParameterDefinition {
                name: "notify_target".to_string(),
                type_hint: "string".to_string(),
                description: "ip:port that send_ssdp_notify announcements are actually sent \
                              to. Defaults to the protocol's multicast group — \
                              '239.255.255.250:1900' for an IPv4 bind, '[ff02::c]:1900' for \
                              IPv6. Override it to point announcements at one listener \
                              instead: a socket bound to loopback usually has no route to \
                              the multicast group, so on 127.0.0.1 the default send fails \
                              and this is how announcements are made observable. The HOST \
                              header of the announcement always names the group, whatever \
                              this is set to, because that is what the header means."
                    .to_string(),
                required: false,
                example: json!("239.255.255.250:1900"),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 1900,
                "base_stack": "ssdp",
                "startup_params": {
                    "server_header": "Linux/6.1 UPnP/1.1 MiniDLNA/1.3.0",
                    "max_response_delay_ms": 1000
                },
                "instruction": "You are a UPnP MediaServer with uuid \
                                9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33, described at \
                                http://192.168.1.10:8080/description.xml. Answer searches \
                                for ssdp:all, upnp:rootdevice and \
                                urn:schemas-upnp-org:device:MediaServer:1. Stay silent for \
                                every other search target."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 1900,
                "base_stack": "ssdp",
                "event_handlers": [{
                    "event_pattern": "ssdp_msearch",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "st = event.get('st', '')\nuuid = 'uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33'\ntarget = 'urn:schemas-upnp-org:device:MediaServer:1'\nif st in ('ssdp:all', 'upnp:rootdevice', target):\n    respond([{'type': 'send_ssdp_response', 'st': target, 'usn': uuid + '::' + target, 'location': 'http://192.168.1.10:8080/description.xml'}])\nelse:\n    respond([{'type': 'no_response', 'reason': 'not a media server search'}])"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 1900,
                "base_stack": "ssdp",
                "event_handlers": [{
                    "event_pattern": "ssdp_msearch",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_ssdp_response",
                            "st": "upnp:rootdevice",
                            "usn": "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33::upnp:rootdevice",
                            "location": "http://192.168.1.10:8080/description.xml"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for SsdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::SsdpServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_ssdp_response" => {
                let st = self.resolve_st(&action)?;
                let usn = required_str(
                    &action,
                    "usn",
                    "it is the unique identity a control point de-duplicates advertisements \
                     on, conventionally 'uuid:<device-uuid>::<st>'",
                )?;
                let location = parse_location(&action, "location")?;
                let server = optional_str(&action, "server")?
                    .unwrap_or_else(|| self.server_default().to_string());
                let max_age = parse_max_age(&action)?;
                let extra_headers = parse_extra_headers(&action)?;

                let rendered = message::render_search_response(&SearchResponse {
                    st,
                    usn,
                    location,
                    server,
                    max_age,
                    date: message::http_date(chrono::Utc::now()),
                    extra_headers,
                });
                Ok(ActionResult::Output(rendered.into_bytes()))
            }

            "send_ssdp_notify" => {
                let nt = required_str(
                    &action,
                    "nt",
                    "it is the device or service type being announced",
                )?;
                let nts = parse_nts(&action)?;
                let usn = required_str(
                    &action,
                    "usn",
                    "it is the unique identity of the advertisement, conventionally \
                     'uuid:<device-uuid>::<nt>'",
                )?;

                // A byebye says the device is gone. Carrying LOCATION and CACHE-CONTROL on
                // it contradicts the message — it would tell the control point where to
                // reach a device that just announced it is leaving, and for how long to
                // keep believing in it. UDA 1.1 §1.2.3 lists four headers and these are not
                // among them.
                let is_byebye = nts == "ssdp:byebye";
                let (location, server, max_age) = if is_byebye {
                    (None, None, None)
                } else {
                    (
                        Some(parse_location(&action, "location")?),
                        Some(
                            optional_str(&action, "server")?
                                .unwrap_or_else(|| self.server_default().to_string()),
                        ),
                        Some(parse_max_age(&action)?),
                    )
                };

                let rendered = message::render_notify(&NotifyMessage {
                    host: self.notify_host(),
                    nt,
                    nts: nts.clone(),
                    usn,
                    location,
                    server,
                    max_age,
                });

                // Not `Output`: an Output goes back to the peer that spoke to us, and a
                // NOTIFY is addressed to the whole multicast group. `mod.rs` routes on this
                // name.
                Ok(ActionResult::Custom {
                    name: "ssdp_notify".to_string(),
                    data: json!({ "message": rendered, "nts": nts }),
                })
            }

            "no_response" => {
                // Deliberately not `ActionResult::NoAction`. NoAction is what a bookkeeping
                // action such as `show_message` returns, so it cannot be told apart from a
                // model that produced no protocol action at all — and telling those two
                // apart is the entire point of this action existing.
                let reason = action
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("no reason given");
                Ok(ActionResult::Custom {
                    name: "ssdp_no_response".to_string(),
                    data: json!({ "reason": reason }),
                })
            }

            _ => Err(anyhow::anyhow!("Unknown SSDP action: {}", action_type)),
        }
    }
}
