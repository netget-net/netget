//! RADIUS client actions, events and metadata.
//!
//! NetGet is the NAS: it sends Access-Request (PAP or CHAP), Accounting-Request and
//! Status-Server to a RADIUS server, and the model decides who to authenticate and what to
//! account. The shared secret is a startup parameter the transport uses for every
//! authenticator; it is in no action, no event and no log line.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::radius::packet::{
    attribute_info, AttrKind, Attribute, ATTR_ACCT_SESSION_ID, ATTR_ACCT_STATUS_TYPE,
    ATTR_CHAP_PASSWORD, ATTR_EAP_MESSAGE, ATTR_MESSAGE_AUTHENTICATOR, ATTR_PROXY_STATE, ATTR_STATE,
    ATTR_USER_NAME, ATTR_USER_PASSWORD, MAX_USER_PASSWORD_LEN,
};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every request travels as.
pub const REQUEST_RESULT: &str = "radius_request";

/// Milliseconds to wait for a reply before retransmitting.
pub const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Retransmissions of an unanswered request before it is reported as a timeout.
pub const DEFAULT_RETRIES: u64 = 2;

/// NAS-Identifier sent on every request unless the action names another.
pub const DEFAULT_NAS_IDENTIFIER: &str = "netget";

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn attributes_param() -> Parameter {
    param(
        "attributes",
        "object",
        "Every other attribute of the reply, by dictionary name (Reply-Message, Session-Timeout, \
         Framed-IP-Address, Class, …); integers as numbers, addresses as dotted quads, opaque \
         values as hex",
        true,
    )
}

pub static RADIUS_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_connected",
        "Ready to send RADIUS requests (UDP has no handshake; nothing was sent)",
        json!({
            "type": "radius_access_request",
            "user_name": "alice",
            "password": "wonderland"
        }),
    )
    .with_parameters(vec![
        param(
            "auth_server",
            "string",
            "Where Access-Request and Status-Server go",
            true,
        ),
        param(
            "accounting_server",
            "string",
            "Where Accounting-Request goes",
            true,
        ),
    ])
});

fn access_reply_params() -> Vec<Parameter> {
    vec![
        param(
            "user_name",
            "string",
            "The User-Name the request carried",
            true,
        ),
        param(
            "method",
            "string",
            "pap, chap or none — how the password was sent",
            true,
        ),
        param(
            "reply_message",
            "string",
            "The server's Reply-Message, if it sent one",
            false,
        ),
        attributes_param(),
    ]
}

pub static RADIUS_ACCESS_ACCEPT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_access_accept",
        "The server accepted the user (Access-Accept, authenticators verified)",
        json!({
            "type": "radius_accounting_request",
            "status_type": "Start",
            "session_id": "s-1",
            "user_name": "alice"
        }),
    )
    .with_parameters(access_reply_params())
});

pub static RADIUS_ACCESS_REJECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_access_reject",
        "The server refused the user (Access-Reject, authenticators verified)",
        json!({"type": "disconnect"}),
    )
    .with_parameters(access_reply_params())
});

pub static RADIUS_ACCESS_CHALLENGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_access_challenge",
        "The server wants another round (Access-Challenge). Answer with radius_access_request \
         for the same user: the client carries the challenge's State back itself",
        json!({
            "type": "radius_access_request",
            "user_name": "alice",
            "password": "123456"
        }),
    )
    .with_parameters(access_reply_params())
});

pub static RADIUS_ACCOUNTING_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_accounting_response",
        "The server acknowledged an Accounting-Request (Accounting-Response, verified)",
        json!({
            "type": "radius_accounting_request",
            "status_type": "Stop",
            "session_id": "s-1"
        }),
    )
    .with_parameters(vec![
        param(
            "status_type",
            "string",
            "The Acct-Status-Type acknowledged",
            true,
        ),
        param(
            "session_id",
            "string",
            "The Acct-Session-Id acknowledged",
            true,
        ),
        attributes_param(),
    ])
});

pub static RADIUS_STATUS_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_status_response",
        "The server answered a Status-Server: it is up and holds the shared secret",
        json!({"type": "radius_access_request", "user_name": "alice", "password": "x"}),
    )
    .with_parameters(vec![
        param(
            "port",
            "string",
            "auth or accounting — which server answered",
            true,
        ),
        param(
            "code",
            "string",
            "Access-Accept or Accounting-Response",
            true,
        ),
        attributes_param(),
    ])
});

pub static RADIUS_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "radius_error",
        "A request got no trustworthy answer",
        json!({"type": "radius_status_server"}),
    )
    .with_parameters(vec![
        param(
            "kind",
            "string",
            "timeout (no reply after every retransmission), bad_authenticator or \
             bad_message_authenticator (a reply that does not prove it knows the secret; it was \
             discarded and the request is still waiting), missing_message_authenticator, \
             unexpected_code, or malformed",
            true,
        ),
        param("message", "string", "What went wrong", true),
        param(
            "request",
            "string",
            "Access-Request, Accounting-Request or Status-Server",
            true,
        ),
        param(
            "user_name",
            "string",
            "The request's User-Name, if it had one",
            false,
        ),
    ])
});

/// RADIUS client protocol.
pub struct RadiusClientProtocol;

impl RadiusClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RadiusClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn all_actions() -> Vec<ActionDefinition> {
    let extra = param(
        "attributes",
        "object",
        "Extra attributes by dictionary name: {\"NAS-Port\": 7, \"Called-Station-Id\": \
         \"ap-1\", \"Framed-IP-Address\": \"10.0.0.5\"}. User-Password, CHAP-Password, \
         Message-Authenticator, State, Proxy-State and EAP-Message are set by the client \
         itself and refused here",
        false,
    );
    vec![
        ActionDefinition {
            name: "radius_access_request".to_string(),
            description: "Ask the server to authenticate a user (Access-Request)".to_string(),
            parameters: vec![
                param(
                    "user_name",
                    "string",
                    "The user to authenticate (User-Name)",
                    true,
                ),
                param("password", "string", "The user's password, as text", false),
                param(
                    "method",
                    "string",
                    "pap (default: the password hidden per RFC 2865 §5.2) or chap (only a \
                     CHAP digest of it is sent)",
                    false,
                ),
                param(
                    "nas_identifier",
                    "string",
                    "NAS-Identifier (default \"netget\")",
                    false,
                ),
                extra.clone(),
            ],
            example: json!({
                "type": "radius_access_request",
                "user_name": "alice",
                "password": "wonderland"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> RADIUS Access-Request user={user_name} method={method}"),
            ),
        },
        ActionDefinition {
            name: "radius_accounting_request".to_string(),
            description: "Report a session event to the accounting server (Accounting-Request)"
                .to_string(),
            parameters: vec![
                param(
                    "status_type",
                    "string",
                    "Start, Stop, Interim-Update, Accounting-On or Accounting-Off",
                    true,
                ),
                param("session_id", "string", "Acct-Session-Id", true),
                param(
                    "user_name",
                    "string",
                    "The session's user (User-Name)",
                    false,
                ),
                param(
                    "nas_identifier",
                    "string",
                    "NAS-Identifier (default \"netget\")",
                    false,
                ),
                extra,
            ],
            example: json!({
                "type": "radius_accounting_request",
                "status_type": "Start",
                "session_id": "s-1",
                "user_name": "alice"
            }),
            log_template: Some(LogTemplate::new().with_info(
                "-> RADIUS Accounting-Request {status_type} session={session_id} user={user_name}",
            )),
        },
        ActionDefinition {
            name: "radius_status_server".to_string(),
            description: "Ask whether the server is up and holds the shared secret \
                          (Status-Server, RFC 5997)"
                .to_string(),
            parameters: vec![param(
                "port",
                "string",
                "auth (default) or accounting",
                false,
            )],
            example: json!({"type": "radius_status_server"}),
            log_template: Some(LogTemplate::new().with_info("-> RADIUS Status-Server port={port}")),
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Stop: forget every pending request and close the socket".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: Some(LogTemplate::new().with_info("-> RADIUS disconnect")),
        },
    ]
}

/// How a validated Access-Request sends its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Pap(String),
    Chap(String),
    None,
}

impl Method {
    pub fn name(&self) -> &'static str {
        match self {
            Method::Pap(_) => "pap",
            Method::Chap(_) => "chap",
            Method::None => "none",
        }
    }
}

/// One validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadiusRequest {
    Access {
        user_name: String,
        method: Method,
        attributes: Vec<Attribute>,
    },
    Accounting {
        status_type: String,
        session_id: String,
        user_name: Option<String>,
        attributes: Vec<Attribute>,
    },
    Status {
        accounting_port: bool,
    },
}

/// Acct-Status-Type values (RFC 2866 §5.1).
fn status_type_value(name: &str) -> Option<u32> {
    match name
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
        .as_str()
    {
        "start" => Some(1),
        "stop" => Some(2),
        "interimupdate" | "alive" => Some(3),
        "accountingon" => Some(7),
        "accountingoff" => Some(8),
        _ => None,
    }
}

/// The dictionary number for an attribute name, from the server's own dictionary.
fn attribute_type(name: &str) -> Option<u8> {
    (1..=255u8).find(|t| attribute_info(*t).0.eq_ignore_ascii_case(name))
}

/// Attributes the client sets itself. Letting the model write them would let it forge the
/// integrity check, smuggle a password in clear, or answer a challenge it was not given.
const RESERVED: &[u8] = &[
    ATTR_USER_PASSWORD,
    ATTR_CHAP_PASSWORD,
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_STATE,
    ATTR_PROXY_STATE,
    ATTR_EAP_MESSAGE,
];

fn extra_attributes(action: &Value) -> Result<Vec<Attribute>> {
    let Some(map) = action.get("attributes") else {
        return Ok(Vec::new());
    };
    let map = match map {
        Value::Null => return Ok(Vec::new()),
        Value::Object(m) => m,
        other => return Err(anyhow!("'attributes' must be an object, got {other}")),
    };
    let mut out = Vec::new();
    for (name, value) in map {
        let t =
            attribute_type(name).with_context(|| format!("unknown RADIUS attribute {name:?}"))?;
        if RESERVED.contains(&t)
            || t == ATTR_USER_NAME
            || t == ATTR_ACCT_SESSION_ID
            || t == ATTR_ACCT_STATUS_TYPE
        {
            return Err(anyhow!(
                "{name} is set by the client itself (or by its own action field), not through \
                 'attributes'"
            ));
        }
        let attr = match attribute_info(t).1 {
            AttrKind::Text => Attribute::text(
                t,
                value
                    .as_str()
                    .with_context(|| format!("{name} is text, got {value}"))?,
            ),
            AttrKind::Integer => {
                let n = value
                    .as_u64()
                    .with_context(|| format!("{name} is an integer, got {value}"))?;
                Attribute::integer(
                    t,
                    u32::try_from(n).map_err(|_| anyhow!("{name} {n} does not fit 32 bits"))?,
                )
            }
            AttrKind::IpAddr => Attribute::ipv4(
                t,
                value
                    .as_str()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .with_context(|| format!("{name} is an IPv4 address, got {value}"))?,
            ),
            AttrKind::Octets => {
                return Err(anyhow!(
                    "{name} is an opaque octet string, which this client does not take from \
                     an action"
                ))
            }
        };
        if attr.value.len() > 253 {
            return Err(anyhow!(
                "{name} is {} bytes; an attribute holds 253",
                attr.value.len()
            ));
        }
        out.push(attr);
    }
    Ok(out)
}

fn nas_identifier(action: &Value) -> Result<Attribute> {
    let id = match action.get("nas_identifier") {
        None | Some(Value::Null) => DEFAULT_NAS_IDENTIFIER,
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 253 => s.as_str(),
        Some(other) => {
            return Err(anyhow!(
                "'nas_identifier' must be 1-253 bytes of text, got {other}"
            ))
        }
    };
    Ok(Attribute::text(
        crate::server::radius::packet::ATTR_NAS_IDENTIFIER,
        id,
    ))
}

fn text_field(action: &Value, name: &str) -> Result<String> {
    let s = action
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field '{name}'"))?;
    if s.is_empty() || s.len() > 253 {
        return Err(anyhow!("'{name}' must be 1-253 bytes"));
    }
    Ok(s.to_string())
}

/// Parse one model action into a request. `Ok(None)` is `disconnect`.
pub fn request_from_action(action: &Value) -> Result<Option<RadiusRequest>> {
    let action_type = action
        .get("type")
        .and_then(Value::as_str)
        .context("missing 'type'")?;
    match action_type {
        "radius_access_request" => {
            let user_name = text_field(action, "user_name")?;
            let password = match action.get("password") {
                None | Some(Value::Null) => None,
                Some(Value::String(p)) => Some(p.clone()),
                Some(other) => return Err(anyhow!("'password' must be text, got {other}")),
            };
            if password
                .as_ref()
                .is_some_and(|p| p.len() > MAX_USER_PASSWORD_LEN)
            {
                return Err(anyhow!(
                    "a RADIUS password is at most {MAX_USER_PASSWORD_LEN} bytes (RFC 2865 §5.2)"
                ));
            }
            let method = match (action.get("method").and_then(Value::as_str), password) {
                (_, None) => Method::None,
                (None | Some("pap"), Some(p)) => Method::Pap(p),
                (Some("chap"), Some(p)) => Method::Chap(p),
                (Some(other), _) => return Err(anyhow!("'method' is pap or chap, got {other:?}")),
            };
            let mut attributes = vec![Attribute::text(ATTR_USER_NAME, &user_name)];
            attributes.push(nas_identifier(action)?);
            attributes.extend(extra_attributes(action)?);
            Ok(Some(RadiusRequest::Access {
                user_name,
                method,
                attributes,
            }))
        }
        "radius_accounting_request" => {
            let status_type = text_field(action, "status_type")?;
            let value = status_type_value(&status_type).with_context(|| {
                format!(
                    "status_type {status_type:?} is not Start, Stop, Interim-Update, \
                     Accounting-On or Accounting-Off"
                )
            })?;
            let session_id = text_field(action, "session_id")?;
            let user_name = match action.get("user_name") {
                None | Some(Value::Null) => None,
                Some(_) => Some(text_field(action, "user_name")?),
            };
            let mut attributes = vec![
                Attribute::integer(ATTR_ACCT_STATUS_TYPE, value),
                Attribute::text(ATTR_ACCT_SESSION_ID, &session_id),
            ];
            if let Some(u) = &user_name {
                attributes.push(Attribute::text(ATTR_USER_NAME, u));
            }
            attributes.push(nas_identifier(action)?);
            attributes.extend(extra_attributes(action)?);
            Ok(Some(RadiusRequest::Accounting {
                status_type,
                session_id,
                user_name,
                attributes,
            }))
        }
        "radius_status_server" => {
            let accounting_port = match action.get("port").and_then(Value::as_str) {
                None | Some("auth") => false,
                Some("accounting") => true,
                Some(other) => return Err(anyhow!("'port' is auth or accounting, got {other:?}")),
            };
            Ok(Some(RadiusRequest::Status { accounting_port }))
        }
        "disconnect" => Ok(None),
        other => Err(anyhow!("Unknown RADIUS client action: {other}")),
    }
}

impl Protocol for RadiusClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "secret".to_string(),
                type_hint: "string".to_string(),
                description: "The shared secret this NAS and the server both hold. Used for \
                              every authenticator and never shown in events or logs"
                    .to_string(),
                required: true,
                example: json!("testing123"),
                default: None,
            },
            ParameterDefinition {
                name: "accounting_port".to_string(),
                type_hint: "integer".to_string(),
                description: "UDP port of the accounting server on the same host (default: \
                              the authentication port plus one, as 1812/1813)"
                    .to_string(),
                required: false,
                example: json!(1813),
                default: None,
            },
            ParameterDefinition {
                name: "timeout_ms".to_string(),
                type_hint: "integer".to_string(),
                description: "Milliseconds to wait for a reply before retransmitting \
                              (100-60000, default 3000)"
                    .to_string(),
                required: false,
                example: json!(3000),
                default: Some(json!(DEFAULT_TIMEOUT_MS)),
            },
            ParameterDefinition {
                name: "retries".to_string(),
                type_hint: "integer".to_string(),
                description: "Retransmissions before a request is reported as a timeout \
                              (0-5, default 2)"
                    .to_string(),
                required: false,
                example: json!(2),
                default: Some(json!(DEFAULT_RETRIES)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "RADIUS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            RADIUS_CONNECTED_EVENT.clone(),
            RADIUS_ACCESS_ACCEPT_EVENT.clone(),
            RADIUS_ACCESS_REJECT_EVENT.clone(),
            RADIUS_ACCESS_CHALLENGE_EVENT.clone(),
            RADIUS_ACCOUNTING_RESPONSE_EVENT.clone(),
            RADIUS_STATUS_RESPONSE_EVENT.clone(),
            RADIUS_ERROR_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RADIUS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["radius", "radius client", "nas", "aaa client"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "RADIUS NAS (RFC 2865/2866/5997) over UDP, building packets with the server's \
                 codec (src/server/radius/packet.rs) plus src/client/radius/wire.rs: PAP \
                 User-Password hiding, CHAP-Password, the Accounting-Request authenticator, and \
                 a Message-Authenticator (RFC 3579) on every Access-Request and Status-Server. \
                 Every reply is checked before the model sees it: its code against the \
                 request, its Response Authenticator, and its Message-Authenticator, which is \
                 required on access and status replies. A transport task owns the socket, the \
                 identifiers and retransmission; the model is asked from a separate turn task.",
            )
            .llm_control(
                "Who to authenticate and how (PAP or CHAP), what to account (Start, Stop, \
                 Interim-Update, Accounting-On/Off with extra attributes by dictionary name), \
                 and Status-Server probes. The shared secret is a startup parameter the model \
                 never sees again.",
            )
            .e2e_testing(
                "tests/client/radius/real_server_test.rs, 8 LLM calls, against FreeRADIUS \
                 radiusd -X run unprivileged from a minimal raddb that requires a \
                 Message-Authenticator. PAP and CHAP are accepted with the users file's \
                 Reply-Message, a wrong password and an always-reject user are refused, an \
                 Accounting Start carrying the model's attributes lands in FreeRADIUS's detail \
                 file, and Status-Server is answered; FreeRADIUS checks every authenticator \
                 NetGet computes and NetGet verifies every reply's. The test also asserts the \
                 shared secret reaches no event and nothing NetGet printed. A second test \
                 injects an Access-Request (logged by FreeRADIUS as Login OK) and an \
                 Accounting Stop through the command channel. Not #[ignore]d; a missing \
                 radiusd fails the test. transport_test.rs refuses forged and unsigned replies \
                 against hand-written servers.",
            )
            .notes(
                "No EAP, MS-CHAP, CoA/Disconnect-Request (RFC 5176), RadSec or IPv6 attributes. \
                 A challenge's State is carried back automatically on the next Access-Request \
                 for the same user; that path is not exercised against a real server.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "RADIUS client (NAS) for authentication, accounting and status checks"
    }

    fn example_prompt(&self) -> &'static str {
        "Authenticate user alice with password wonderland against the RADIUS server at \
         localhost:1812 with secret testing123"
    }

    fn group_name(&self) -> &'static str {
        "Authentication"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1812",
                "base_stack": "radius",
                "instruction": "Authenticate alice and start an accounting session for her",
                "startup_params": {"secret": "testing123"}
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1812",
                "base_stack": "radius",
                "startup_params": {"secret": "testing123"},
                "event_handlers": [{
                    "event_pattern": "radius_access_accept",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<radius_client_handler>"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1812",
                "base_stack": "radius",
                "startup_params": {"secret": "testing123"},
                "event_handlers": [
                    {
                        "event_pattern": "radius_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "radius_status_server"}]
                        }
                    },
                    {
                        "event_pattern": "radius_status_response",
                        "handler": {"type": "static", "actions": [{"type": "disconnect"}]}
                    }
                ]
            }),
        )
    }
}

impl Client for RadiusClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref().context(
                "the RADIUS client needs the shared secret as startup parameter 'secret'",
            )?;
            let secret = params
                .get_optional_string("secret")?
                .filter(|s| !s.is_empty())
                .context("the RADIUS client needs a non-empty startup parameter 'secret'")?;
            let accounting_port = match params.get_optional_u64("accounting_port")? {
                None => None,
                Some(p) => Some(
                    u16::try_from(p)
                        .ok()
                        .filter(|p| *p != 0)
                        .with_context(|| format!("accounting_port {p} is not a UDP port"))?,
                ),
            };
            let timeout_ms = params
                .get_optional_u64("timeout_ms")?
                .unwrap_or(DEFAULT_TIMEOUT_MS);
            if !(100..=60_000).contains(&timeout_ms) {
                return Err(anyhow!("timeout_ms {timeout_ms} is outside 100-60000"));
            }
            let retries = params
                .get_optional_u64("retries")?
                .unwrap_or(DEFAULT_RETRIES);
            if retries > 5 {
                return Err(anyhow!("retries {retries} is over 5"));
            }
            crate::client::radius::RadiusClient::connect_with_llm_actions(
                ctx.remote_addr,
                crate::client::radius::Settings {
                    secret: secret.into_bytes(),
                    accounting_port,
                    timeout: std::time::Duration::from_millis(timeout_ms),
                    // Range-checked above.
                    retries: u32::try_from(retries).unwrap_or(2),
                },
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match request_from_action(&action)? {
            None => Ok(ClientActionResult::Disconnect),
            Some(_) => Ok(ClientActionResult::Custom {
                name: REQUEST_RESULT.to_string(),
                data: action,
            }),
        }
    }
}
