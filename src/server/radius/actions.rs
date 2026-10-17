//! RADIUS protocol actions.
//!
//! # Fail closed
//!
//! RADIUS grants network access. The OAuth2 post-mortem in the root `CLAUDE.md` is the
//! reason this file is shaped the way it is: a credential-granting protocol that falls
//! through to a permissive default turns an LLM outage into an authorization bypass, and
//! makes a model's explicit denial indistinguishable from its silence.
//!
//! Three structural rules follow, and each is enforced somewhere a reader can point at:
//!
//! 1. **There is no default response.** `execute_action` can only ever produce the packet a
//!    named action asked for. Nothing here synthesises an Access-Accept.
//! 2. **Acceptance and denial are different actions.** `send_access_accept` and
//!    `send_access_reject` share no code path, so "the model said no" cannot decay into
//!    "the model said nothing" or vice versa.
//! 3. **Silence is denial, and it is logged as its own thing.** When the model returns no
//!    usable action — or the LLM call fails outright — `mod.rs` synthesises an Access-Reject
//!    and records `decision=fail_closed_no_action` / `decision=fail_closed_llm_error`, never
//!    `decision=model_reject`. See `RadiusServer::decide`.
//!
//! A fourth rule lives in `spawn`: without a `shared_secret` the server refuses to start,
//! rather than running with a guessable default.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

use super::packet::{self, Attribute, RadiusPacket};

/// RADIUS protocol handler.
///
/// The registry holds a context-free instance built with [`RadiusProtocol::new`]. The server
/// builds one instance *per request* with [`RadiusProtocol::for_request`], carrying that
/// request's identifier, Request Authenticator and the server's shared secret — everything
/// needed to sign a reply. A context-free instance cannot sign anything and says so.
pub struct RadiusProtocol {
    request: Option<RequestContext>,
}

/// Per-request signing context.
#[derive(Clone)]
pub struct RequestContext {
    /// Identifier of the request being answered; the reply must echo it.
    pub identifier: u8,
    /// The request's 16-byte Authenticator, an input to the Response Authenticator.
    pub authenticator: [u8; 16],
    /// Shared secret between this server and the NAS.
    pub secret: Vec<u8>,
    /// Proxy-State attributes to copy into the reply, in order (RFC 2865 §5.33).
    pub proxy_state: Vec<Vec<u8>>,
}

impl Default for RadiusProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl RadiusProtocol {
    pub fn new() -> Self {
        Self { request: None }
    }

    pub fn for_request(ctx: RequestContext) -> Self {
        Self { request: Some(ctx) }
    }

    fn ctx(&self) -> Result<&RequestContext> {
        self.request.as_ref().context(
            "RADIUS action executed without a request context: the reply's Response \
             Authenticator cannot be computed. This instance came from the registry, not \
             from a received packet.",
        )
    }

    /// Proxy-State attributes carried by the request being answered (RFC 2865 §5.33).
    pub fn proxy_state(&self) -> &[Vec<u8>] {
        match &self.request {
            Some(ctx) => &ctx.proxy_state,
            None => &[],
        }
    }

    /// Encode and sign a reply of `code` with exactly the attributes given.
    ///
    /// Public so the server can build its own fail-closed Access-Reject without going
    /// through an LLM action.
    pub fn encode_reply(&self, code: u8, attributes: &[Attribute]) -> Result<Vec<u8>> {
        let ctx = self.ctx()?;
        let encode = if matches!(
            code,
            packet::CODE_ACCESS_ACCEPT | packet::CODE_ACCESS_REJECT | packet::CODE_ACCESS_CHALLENGE
        ) {
            packet::encode_signed_response
        } else {
            packet::encode_response
        };
        encode(
            code,
            ctx.identifier,
            attributes,
            &ctx.authenticator,
            &ctx.secret,
        )
        .map_err(|e| anyhow::anyhow!("Failed to encode RADIUS {}: {}", packet::code_name(code), e))
    }

    /// Build a signed reply of `code`, appending the request's Proxy-State attributes.
    fn reply(&self, code: u8, mut attributes: Vec<Attribute>) -> Result<ActionResult> {
        for state in self.proxy_state() {
            attributes.push(Attribute::new(packet::ATTR_PROXY_STATE, state.clone()));
        }
        Ok(ActionResult::Output(self.encode_reply(code, &attributes)?))
    }
}

// ---------------------------------------------------------------------------
// Value coercion helpers — every documented field is really decoded here.
// ---------------------------------------------------------------------------

/// Well-known Service-Type values (RFC 2865 §5.6). Accepting the name as well as the number
/// is not cosmetic: models produce `"Framed-User"` far more reliably than `2`.
fn service_type_value(v: &serde_json::Value) -> Result<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).context("service_type out of range");
    }
    let name = v
        .as_str()
        .context("service_type must be a number or a well-known name")?;
    let n = match name
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
        .as_str()
    {
        "login" | "loginuser" => 1,
        "framed" | "frameduser" => 2,
        "callbacklogin" | "callbackloginuser" => 3,
        "callbackframed" | "callbackframeduser" => 4,
        "outbound" | "outbounduser" => 5,
        "administrative" | "administrativeuser" => 6,
        "nasprompt" | "naspromptuser" => 7,
        "authenticateonly" => 8,
        "callbacknasprompt" => 9,
        "callcheck" => 10,
        "callbackadministrative" => 11,
        other => {
            return Err(anyhow::anyhow!(
                "Unknown service_type '{}'. Use a number, or one of: Login-User, \
                 Framed-User, Callback-Login-User, Callback-Framed-User, Outbound-User, \
                 Administrative-User, NAS-Prompt-User, Authenticate-Only, \
                 Callback-NAS-Prompt, Call-Check, Callback-Administrative",
                other
            ))
        }
    };
    Ok(n)
}

/// Well-known Framed-Protocol values (RFC 2865 §5.7).
fn framed_protocol_value(v: &serde_json::Value) -> Result<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).context("framed_protocol out of range");
    }
    let name = v
        .as_str()
        .context("framed_protocol must be a number or a well-known name")?;
    let n = match name.to_ascii_lowercase().as_str() {
        "ppp" => 1,
        "slip" => 2,
        "ara" => 3,
        "gandalf" => 4,
        "xylogics" => 5,
        "x75" | "x.75" => 6,
        other => {
            return Err(anyhow::anyhow!(
                "Unknown framed_protocol '{}'. Use a number, or one of: PPP, SLIP, ARA, \
                 Gandalf, Xylogics, X.75",
                other
            ))
        }
    };
    Ok(n)
}

/// Decode a field documented as `utf8` or `hex`.
///
/// The `send_tcp_data` bug (`d70bb5b5`) is the reference case for why this exists as an
/// explicit field rather than a sniff: `"48656c6c6f"` is simultaneously valid text and valid
/// hex, and only the sender knows which it meant.
fn decode_encoded_field(
    action: &serde_json::Value,
    value_key: &str,
    encoding_key: &str,
) -> Result<Option<Vec<u8>>> {
    let raw = match action.get(value_key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let encoding = action
        .get(encoding_key)
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");
    match encoding {
        "utf8" => Ok(Some(raw.as_bytes().to_vec())),
        "hex" => Ok(Some(hex::decode(raw).with_context(|| {
            format!("'{}' is declared hex but is not valid hex", value_key)
        })?)),
        other => Err(anyhow::anyhow!(
            "Unknown {} '{}': use \"utf8\" or \"hex\"",
            encoding_key,
            other
        )),
    }
}

/// Reply-Message is limited to 253 octets per attribute; longer text is split across
/// several attributes, which is exactly what RFC 2865 §5.18 prescribes.
fn push_reply_message(attributes: &mut Vec<Attribute>, text: &str) {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return;
    }
    for chunk in bytes.chunks(253) {
        attributes.push(Attribute::new(packet::ATTR_REPLY_MESSAGE, chunk.to_vec()));
    }
}

fn push_optional_reply_message(attributes: &mut Vec<Attribute>, action: &serde_json::Value) {
    match action.get("reply_message") {
        Some(serde_json::Value::String(s)) => push_reply_message(attributes, s),
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    push_reply_message(attributes, s);
                }
            }
        }
        _ => {}
    }
}

fn parse_ipv4(action: &serde_json::Value, key: &str) -> Result<Option<Ipv4Addr>> {
    match action.get(key).and_then(|v| v.as_str()) {
        Some(s) => Ok(Some(s.parse::<Ipv4Addr>().with_context(|| {
            format!("'{}' is not a valid IPv4 address: {}", key, s)
        })?)),
        None => Ok(None),
    }
}

fn parse_u32(action: &serde_json::Value, key: &str) -> Result<Option<u32>> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("'{}' must be a non-negative integer", key))?;
            Ok(Some(
                u32::try_from(n).with_context(|| format!("'{}' exceeds 32 bits", key))?,
            ))
        }
    }
}

/// Encode a Vendor-Specific attribute (type 26) in the RFC 2865 §5.26 recommended format:
/// `Vendor-Id(4) | Vendor-Type(1) | Vendor-Length(1) | Value`.
fn encode_vendor_specific(entry: &serde_json::Value) -> Result<Attribute> {
    let vendor_id = entry
        .get("vendor_id")
        .and_then(|v| v.as_u64())
        .context("vendor attribute needs a numeric 'vendor_id'")?;
    let vendor_id = u32::try_from(vendor_id).context("vendor_id exceeds 32 bits")?;
    let vendor_type = entry
        .get("vendor_type")
        .and_then(|v| v.as_u64())
        .context("vendor attribute needs a numeric 'vendor_type' (0-255)")?;
    let vendor_type = u8::try_from(vendor_type).context("vendor_type must be 0-255")?;

    let value = decode_encoded_field(entry, "value", "value_encoding")?
        .context("vendor attribute needs a 'value'")?;
    if value.len() > 247 {
        return Err(anyhow::anyhow!(
            "vendor attribute value is {} bytes; the RFC 2865 §5.26 layout allows at most 247",
            value.len()
        ));
    }

    let mut out = Vec::with_capacity(6 + value.len());
    out.extend_from_slice(&vendor_id.to_be_bytes());
    out.push(vendor_type);
    out.push((value.len() + 2) as u8);
    out.extend_from_slice(&value);
    Ok(Attribute::new(26, out))
}

fn push_vendor_attributes(
    attributes: &mut Vec<Attribute>,
    action: &serde_json::Value,
) -> Result<()> {
    if let Some(items) = action.get("vendor_attributes").and_then(|v| v.as_array()) {
        for entry in items {
            attributes.push(encode_vendor_specific(entry)?);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

pub static RADIUS_ACCESS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_access_request",
        "A NAS asked whether to admit a user. Decide: accept, reject, or challenge. \
         There is no default — if you return nothing, the server sends Access-Reject.",
        json!({
            "type": "send_access_accept",
            "reply_message": "Welcome",
            "session_timeout": 3600
        }),
    )
    .with_parameters(vec![
        p(
            "identifier",
            "number",
            "RADIUS packet identifier (echoed automatically)",
        ),
        p(
            "user_name",
            "string",
            "User-Name attribute, or null if absent",
        ),
        p(
            "auth_method",
            "string",
            "How the user authenticated: 'pap' (User-Password present and decrypted), \
             'chap' (CHAP-Password present, NOT validated by this server), 'eap' \
             (EAP-Message present, NOT processed), or 'none'",
        ),
        p(
            "password",
            "string",
            "Cleartext password, present only when auth_method is 'pap'. Decrypted from \
             User-Password per RFC 2865 §5.2 with the shared secret",
        ),
        p("nas_ip_address", "string", "NAS-IP-Address, or null"),
        p("nas_identifier", "string", "NAS-Identifier, or null"),
        p("nas_port", "number", "NAS-Port, or null"),
        p("nas_port_type", "number", "NAS-Port-Type, or null"),
        p(
            "calling_station_id",
            "string",
            "Calling-Station-Id (client MAC/number), or null",
        ),
        p(
            "called_station_id",
            "string",
            "Called-Station-Id (SSID/NAS number), or null",
        ),
        p("service_type", "number", "Service-Type, or null"),
        p(
            "state",
            "string",
            "State attribute echoed back by the NAS after a previous Access-Challenge, \
             or null on a first request",
        ),
        p(
            "state_encoding",
            "string",
            "'utf8' or 'hex' — how to read the state field",
        ),
        p("source_addr", "string", "Address the request came from"),
        p(
            "attributes",
            "array",
            "Every attribute in the request as {type, name, value}, including ones not \
             broken out above",
        ),
    ])
    .with_actions(vec![
        send_access_accept_action(),
        send_access_reject_action(),
        send_access_challenge_action(),
    ])
});

pub static RADIUS_ACCOUNTING_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_accounting_request",
        "A NAS reported session accounting (RFC 2866). Acknowledge it, or stay silent to \
         make the NAS retry.",
        json!({ "type": "send_accounting_response" }),
    )
    .with_parameters(vec![
        p(
            "identifier",
            "number",
            "RADIUS packet identifier (echoed automatically)",
        ),
        p(
            "acct_status_type",
            "number",
            "Acct-Status-Type: 1=Start, 2=Stop, 3=Interim-Update, 7=Accounting-On, \
             8=Accounting-Off",
        ),
        p("user_name", "string", "User-Name, or null"),
        p("acct_session_id", "string", "Acct-Session-Id, or null"),
        p(
            "acct_session_time",
            "number",
            "Seconds the session has run, or null",
        ),
        p(
            "acct_input_octets",
            "number",
            "Octets received from the user, or null",
        ),
        p(
            "acct_output_octets",
            "number",
            "Octets sent to the user, or null",
        ),
        p("nas_ip_address", "string", "NAS-IP-Address, or null"),
        p("source_addr", "string", "Address the request came from"),
        p(
            "attributes",
            "array",
            "Every attribute as {type, name, value}",
        ),
    ])
    .with_actions(vec![send_accounting_response_action()])
});

pub static RADIUS_STATUS_SERVER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_status_server",
        "A NAS probed whether this server is alive (Status-Server, RFC 5997). Answer with \
         Access-Accept to report healthy, or Access-Reject to report unhealthy.",
        json!({ "type": "send_access_accept", "reply_message": "alive" }),
    )
    .with_parameters(vec![
        p(
            "identifier",
            "number",
            "RADIUS packet identifier (echoed automatically)",
        ),
        p("source_addr", "string", "Address the probe came from"),
        p(
            "attributes",
            "array",
            "Every attribute as {type, name, value}",
        ),
    ])
    .with_actions(vec![
        send_access_accept_action(),
        send_access_reject_action(),
    ])
});

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

fn send_access_accept_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_access_accept".to_string(),
        description: "GRANT access. Sends Access-Request → Access-Accept with the reply \
                      attributes given here. Use this only when the credentials and policy \
                      genuinely check out."
            .to_string(),
        parameters: vec![
            p(
                "reply_message",
                "string|array",
                "Text shown to the user (Reply-Message). May be an array for several lines",
            ),
            p(
                "framed_ip_address",
                "string",
                "Framed-IP-Address to assign, e.g. '10.0.0.42'",
            ),
            p(
                "framed_ip_netmask",
                "string",
                "Framed-IP-Netmask, e.g. '255.255.255.0'",
            ),
            p(
                "framed_protocol",
                "number|string",
                "Framed-Protocol: a number, or 'PPP'/'SLIP'",
            ),
            p("framed_mtu", "number", "Framed-MTU in octets"),
            p(
                "service_type",
                "number|string",
                "Service-Type: a number, or e.g. 'Framed-User'",
            ),
            p("session_timeout", "number", "Session-Timeout in seconds"),
            p("idle_timeout", "number", "Idle-Timeout in seconds"),
            p(
                "filter_id",
                "string",
                "Filter-Id naming an access filter on the NAS",
            ),
            p(
                "class",
                "string",
                "Class attribute the NAS echoes into accounting records",
            ),
            p(
                "class_encoding",
                "string",
                "'utf8' (default) or 'hex' — how to read class",
            ),
            p(
                "vendor_attributes",
                "array",
                "Vendor-Specific attributes: [{vendor_id, vendor_type, value, value_encoding}]",
            ),
        ],
        example: json!({
            "type": "send_access_accept",
            "reply_message": "Welcome to the network",
            "framed_ip_address": "10.0.0.42",
            "session_timeout": 3600,
            "service_type": "Framed-User"
        }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new().with_info("-> RADIUS Access-Accept"),
        ),
    }
}

fn send_access_reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_access_reject".to_string(),
        description: "DENY access. Sends Access-Reject. This is the correct answer whenever \
                      the credentials are wrong, the user is unknown, or policy forbids the \
                      request — and it is a decision the server records as yours, distinct \
                      from the Access-Reject it sends when you answer nothing at all."
            .to_string(),
        parameters: vec![p(
            "reply_message",
            "string|array",
            "Reason shown to the user (Reply-Message)",
        )],
        example: json!({
            "type": "send_access_reject",
            "reply_message": "Invalid credentials"
        }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new().with_info("-> RADIUS Access-Reject"),
        ),
    }
}

fn send_access_challenge_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_access_challenge".to_string(),
        description: "Ask for more information before deciding. Sends Access-Challenge with \
                      a State attribute the NAS will echo in its next Access-Request, so you \
                      can recognise the continuation. This is NOT a grant."
            .to_string(),
        parameters: vec![
            required(
                "state",
                "string",
                "Opaque State value the NAS must echo back",
            ),
            p(
                "state_encoding",
                "string",
                "'utf8' (default) or 'hex' — how to read state",
            ),
            p("reply_message", "string|array", "Prompt shown to the user"),
            p(
                "session_timeout",
                "number",
                "How long the user has to answer, in seconds",
            ),
        ],
        example: json!({
            "type": "send_access_challenge",
            "state": "otp-round-1",
            "reply_message": "Enter your one-time code"
        }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_info("-> RADIUS Access-Challenge"),
        ),
    }
}

fn send_accounting_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_accounting_response".to_string(),
        description: "Acknowledge an Accounting-Request. Answering nothing leaves the NAS to \
                      retransmit, which is the safe default if you do not want to record the \
                      session."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "send_accounting_response" }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_info("-> RADIUS Accounting-Response"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Protocol / Server impls
// ---------------------------------------------------------------------------

impl Protocol for RadiusProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_access_accept_action(),
            send_access_reject_action(),
            send_access_challenge_action(),
            send_accounting_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "RADIUS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            RADIUS_ACCESS_REQUEST_EVENT.clone(),
            RADIUS_ACCOUNTING_REQUEST_EVENT.clone(),
            RADIUS_STATUS_SERVER_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RADIUS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately narrow. Generic words like "auth" or "aaa" would hijack keyword
        // resolution for every other authentication protocol in the registry.
        vec!["radius", "radius server", "aaa server", "rfc 2865"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: every undecided Access-Request gets a correctly signed
            // Access-Reject (decision=fail_closed_*), which denies rather than asserts. Nothing here
            // can synthesise an Access-Accept.
            .answers_on_failure()
            // Beta, September 2026. The bar this file's own CLAUDE.md sets is a real
            // third-party client, not #[ignore]d, that FAILS rather than skips when the
            // client is missing. tests/server/radius/real_client_test.rs is now all three:
            // it drives FreeRADIUS `radclient`, and `require_radclient()` returns Err when
            // the binary is absent. It was Experimental purely because that gate used to
            // print SKIPPED and return Ok(()).
            .state(DevelopmentState::Beta)
            // 1812/1813 are above 1023, so PrivilegedPort would be dead code here.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1812)
            .implementation(
                "Hand-rolled RFC 2865/2866 codec (src/server/radius/packet.rs) over a tokio \
                 UdpSocket. Implements the Response Authenticator MD5, the Accounting-Request \
                 Authenticator (verified, not just computed), User-Password unhiding per \
                 §5.2, TLV attributes, Proxy-State echo and the RFC 3579 §3.2 \
                 Message-Authenticator (first in every Access reply; verified on a request \
                 that carries one). Does NOT implement CHAP, MS-CHAP or EAP: \
                 CHAP-Password and EAP-Message are handed to the model as opaque hex and no \
                 challenge is validated.",
            )
            .llm_control(
                "The model makes the authorization decision — Access-Accept, Access-Reject \
                 or Access-Challenge — and chooses the reply attributes (Framed-IP-Address, \
                 Session-Timeout, Filter-Id, Class, vendor-specific).",
            )
            .e2e_testing(
                "Validated against FreeRADIUS radclient, an independent implementation that \
                 NetGet did not write and does not link. It verifies our Response \
                 Authenticator itself and refuses the reply with 'invalid Response \
                 Authenticator' if the MD5 is wrong, so it checks the one thing that \
                 matters. Two tests in tests/server/radius/real_client_test.rs, neither \
                 #[ignore]d: radclient accepts a model-authorised Access-Accept and decodes \
                 the model's Reply-Message, Framed-IP-Address and Session-Timeout from its \
                 own dictionary; and radclient reads the FAIL-CLOSED Access-Reject produced \
                 when the model answers nothing, which must also be correctly signed (a \
                 denial the client discards as corrupt is a timeout, not a denial). Both \
                 FAIL, not skip, when radclient is absent — a skip-when-missing gate is a \
                 silent pass rather than evidence, and that gate was the only thing keeping \
                 this protocol at Experimental. FreeRADIUS is therefore required wherever \
                 the `radius` feature's suite runs (`brew install freeradius-server` / \
                 `apt-get install -y freeradius-utils`); it is not in CI's CI_FEATURES, so \
                 the CI gate neither compiles nor runs these tests. The codec is \
                 additionally pinned to RFC 2865 §7.1/§7.2 literal example bytes, checked \
                 with a separate MD5 implementation. CHAP, MS-CHAP and EAP are \
                 unimplemented and untested.",
            )
            .notes(
                "FAILS CLOSED: no LLM answer, an unusable answer, or an LLM error all \
                 produce Access-Reject, logged as decision=fail_closed_* and never as \
                 decision=model_reject. shared_secret is a required startup parameter; the \
                 server refuses to start without one. Accounting-Request packets whose \
                 Authenticator does not verify are dropped.",
            )
            .max_inbound_bytes(crate::server::radius::packet::MAX_PACKET_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "RADIUS authentication, authorization and accounting server (RFC 2865/2866)"
    }

    fn example_prompt(&self) -> &'static str {
        "run a radius server on port 1812 with shared secret testing123; accept alice with \
         password wonderland and give her 10.0.0.42, reject everyone else"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "shared_secret".to_string(),
            type_hint: "string".to_string(),
            description: "Shared secret between this server and the NAS. Required: it keys \
                          the Response Authenticator and the User-Password decryption, and \
                          the server refuses to start without it rather than using a \
                          guessable default."
                .to_string(),
            required: true,
            example: json!("testing123"),
            default: None,
        }]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 1812,
                "base_stack": "radius",
                "startup_params": { "shared_secret": "testing123" },
                "instruction": "Accept user alice with password wonderland, assigning \
                                10.0.0.42 and a 1 hour session. Reject every other user."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 1812,
                "base_stack": "radius",
                "startup_params": { "shared_secret": "testing123" },
                "event_handlers": [{
                    "event_pattern": "radius_access_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_access_accept'}] if event['user_name'] == 'alice' and event.get('password') == 'wonderland' else [{'type': 'send_access_reject', 'reply_message': 'denied'}])"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 1812,
                "base_stack": "radius",
                "startup_params": { "shared_secret": "testing123" },
                "event_handlers": [{
                    "event_pattern": "radius_access_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_access_reject",
                            "reply_message": "This server denies everyone"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for RadiusProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::RadiusServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_access_accept" => {
                let mut attributes = Vec::new();
                push_optional_reply_message(&mut attributes, &action);

                if let Some(ip) = parse_ipv4(&action, "framed_ip_address")? {
                    attributes.push(Attribute::ipv4(packet::ATTR_FRAMED_IP_ADDRESS, ip));
                }
                if let Some(mask) = parse_ipv4(&action, "framed_ip_netmask")? {
                    attributes.push(Attribute::ipv4(packet::ATTR_FRAMED_IP_NETMASK, mask));
                }
                if let Some(v) = action.get("framed_protocol") {
                    attributes.push(Attribute::integer(
                        packet::ATTR_FRAMED_PROTOCOL,
                        framed_protocol_value(v)?,
                    ));
                }
                if let Some(mtu) = parse_u32(&action, "framed_mtu")? {
                    attributes.push(Attribute::integer(packet::ATTR_FRAMED_MTU, mtu));
                }
                if let Some(v) = action.get("service_type") {
                    attributes.push(Attribute::integer(
                        packet::ATTR_SERVICE_TYPE,
                        service_type_value(v)?,
                    ));
                }
                if let Some(t) = parse_u32(&action, "session_timeout")? {
                    attributes.push(Attribute::integer(packet::ATTR_SESSION_TIMEOUT, t));
                }
                if let Some(t) = parse_u32(&action, "idle_timeout")? {
                    attributes.push(Attribute::integer(packet::ATTR_IDLE_TIMEOUT, t));
                }
                if let Some(f) = action.get("filter_id").and_then(|v| v.as_str()) {
                    attributes.push(Attribute::text(packet::ATTR_FILTER_ID, f));
                }
                if let Some(class) = decode_encoded_field(&action, "class", "class_encoding")? {
                    attributes.push(Attribute::new(packet::ATTR_CLASS, class));
                }
                push_vendor_attributes(&mut attributes, &action)?;

                self.reply(packet::CODE_ACCESS_ACCEPT, attributes)
            }
            "send_access_reject" => {
                let mut attributes = Vec::new();
                push_optional_reply_message(&mut attributes, &action);
                self.reply(packet::CODE_ACCESS_REJECT, attributes)
            }
            "send_access_challenge" => {
                let state = decode_encoded_field(&action, "state", "state_encoding")?.context(
                    "send_access_challenge requires 'state': without it the NAS cannot tie \
                     its next Access-Request to this challenge",
                )?;
                if state.is_empty() {
                    return Err(anyhow::anyhow!(
                        "send_access_challenge 'state' must not be empty"
                    ));
                }
                let mut attributes = vec![Attribute::new(packet::ATTR_STATE, state)];
                push_optional_reply_message(&mut attributes, &action);
                if let Some(t) = parse_u32(&action, "session_timeout")? {
                    attributes.push(Attribute::integer(packet::ATTR_SESSION_TIMEOUT, t));
                }
                self.reply(packet::CODE_ACCESS_CHALLENGE, attributes)
            }
            "send_accounting_response" => self.reply(packet::CODE_ACCOUNTING_RESPONSE, Vec::new()),
            _ => Err(anyhow::anyhow!("Unknown RADIUS action: {}", action_type)),
        }
    }
}

// ---------------------------------------------------------------------------
// Event payload construction
// ---------------------------------------------------------------------------

/// Every attribute, by number and name, with a typed value. Attributes the dictionary does
/// not name are still reported — a model that sees `Attribute-26` can at least say so.
pub fn attributes_json(request: &RadiusPacket) -> serde_json::Value {
    let items: Vec<_> = request
        .attributes
        .iter()
        .map(|attr| {
            let (name, _) = packet::attribute_info(attr.attr_type);
            json!({
                "type": attr.attr_type,
                "name": if name == "Unknown" {
                    format!("Attribute-{}", attr.attr_type)
                } else {
                    name.to_string()
                },
                "value": packet::attribute_value_json(attr.attr_type, &attr.value),
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

/// Read a named text attribute, if present.
pub fn text_attr(request: &RadiusPacket, attr_type: u8) -> Option<String> {
    request
        .first(attr_type)
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// Read a named 32-bit integer attribute, if present and well formed.
pub fn int_attr(request: &RadiusPacket, attr_type: u8) -> Option<u32> {
    request.first(attr_type).and_then(|v| {
        if v.len() == 4 {
            Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        } else {
            None
        }
    })
}

/// Read a named IPv4 attribute, if present and well formed.
pub fn ip_attr(request: &RadiusPacket, attr_type: u8) -> Option<String> {
    request.first(attr_type).and_then(|v| {
        if v.len() == 4 {
            Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string())
        } else {
            None
        }
    })
}
