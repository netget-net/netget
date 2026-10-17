//! CoAP client actions, events and metadata.
//!
//! NetGet sends CoAP requests (RFC 7252) over UDP and the model decides what to ask: GET, POST,
//! PUT and DELETE on a path with a query, a Content-Format and a text or JSON payload, and
//! Observe (RFC 7641) registration and cancellation. Message ids, tokens, retransmission,
//! acknowledgements and Block2 reassembly (RFC 7959) are the transport's, so the model works in
//! paths and payloads, never bytes.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::coap::codec::{content_format_id, MAX_REPRESENTATION_LEN};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every request travels as.
pub const REQUEST_RESULT: &str = "coap_request";

/// RFC 7252 §4.8 `ACK_TIMEOUT`: the first retransmission of a Confirmable request waits a
/// random time between this and `ACK_TIMEOUT * ACK_RANDOM_FACTOR` (1.5).
pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 2000;

/// RFC 7252 §4.8 `MAX_RETRANSMIT`: a Confirmable request is sent at most this many more times.
pub const DEFAULT_MAX_RETRANSMIT: u64 = 4;

/// Block1 block size in bytes: a request body over this goes out in blocks (RFC 7959). 1024 is
/// SZX 6, the largest a block can be; a server may ask for smaller ones and is obeyed.
pub const DEFAULT_BLOCK_SIZE: u64 = 1024;

/// Longest a Uri-Path segment or Uri-Query item may be (RFC 7252 §5.10: 0-255 octets).
pub const MAX_URI_OPTION_LEN: usize = 255;

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn response_params() -> Vec<Parameter> {
    vec![
        param(
            "method",
            "string",
            "GET, POST, PUT or DELETE — the request answered",
            true,
        ),
        param(
            "path",
            "string",
            "The request's path, e.g. /sensors/temp",
            true,
        ),
        param(
            "code",
            "string",
            "The response code in c.dd form, e.g. 2.05",
            true,
        ),
        param(
            "status",
            "string",
            "The code's name, e.g. Content, Changed, Created, Not Found",
            true,
        ),
        param(
            "content_format",
            "string",
            "The payload's media type (text/plain, application/json, …), if the server named \
             one",
            false,
        ),
        param(
            "payload",
            "string",
            "The payload as text. Absent when empty or not UTF-8 (payload_size still says how \
             long it was)",
            false,
        ),
        param(
            "payload_json",
            "any",
            "The payload parsed, when the content format is application/json and it parses",
            false,
        ),
        param("payload_size", "number", "Payload length in bytes", true),
        param(
            "options",
            "object",
            "Other response options: max_age, etag (hex), location_path, observe, size2",
            true,
        ),
    ]
}

pub static COAP_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "coap_connected",
        "Ready to send CoAP requests to the server (UDP has no handshake; nothing was sent)",
        json!({"type": "coap_get", "path": "/.well-known/core"}),
    )
    .with_parameters(vec![param(
        "remote_addr",
        "string",
        "The CoAP server requests go to",
        true,
    )])
});

pub static COAP_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = response_params();
    params.push(param(
        "observing",
        "boolean",
        "Present on responses to coap_observe / coap_observe_cancel: true while the \
         observation is registered, false once it is cancelled",
        false,
    ));
    params.push(param(
        "blocks",
        "number",
        "How many Block2 blocks the payload was reassembled from (1 when it fit in one)",
        true,
    ));
    EventType::new(
        "coap_response",
        "The server answered a request (after reassembling any Block2 transfer)",
        json!({"type": "coap_put", "path": "/example_data", "payload": "hello"}),
    )
    .with_parameters(params)
});

pub static COAP_NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = response_params();
    params.push(param(
        "sequence",
        "number",
        "The notification's Observe sequence number",
        true,
    ));
    EventType::new(
        "coap_notification",
        "An observed resource changed and the server sent its new state (RFC 7641)",
        json!({"type": "coap_observe_cancel", "path": "/time"}),
    )
    .with_parameters(params)
});

pub static COAP_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "coap_error",
        "A request got no usable answer",
        json!({"type": "coap_get", "path": "/"}),
    )
    .with_parameters(vec![
        param(
            "kind",
            "string",
            "timeout (no answer after every retransmission), reset (the server answered RST), \
             body_too_large (a Block2 transfer passed the reassembly limit), bad_block (a \
             Block2 block out of order), or not_observing (cancel for a path with no \
             observation)",
            true,
        ),
        param("message", "string", "What went wrong", true),
        param("method", "string", "The request's method", true),
        param("path", "string", "The request's path", true),
    ])
});

/// CoAP client protocol.
pub struct CoapClientProtocol;

impl CoapClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CoapClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn common_params(with_payload: bool) -> Vec<Parameter> {
    let mut params = vec![
        param("path", "string", "Resource path, e.g. /sensors/temp", true),
        param(
            "query",
            "string",
            "Query string without '?', items separated by '&', e.g. unit=c&n=3",
            false,
        ),
        param(
            "confirmable",
            "boolean",
            "Send as Confirmable (retransmitted until acknowledged; default true) or \
             Non-confirmable",
            false,
        ),
    ];
    if with_payload {
        params.push(param(
            "payload",
            "any",
            "The body: a string is sent as text, an object or array as JSON. Up to 64 KiB; \
             over one block (block_size, default 1024 bytes) it is sent in Block1 blocks",
            true,
        ));
        params.push(param(
            "content_format",
            "string",
            "text/plain, application/json, application/link-format, … (default: \
             application/json for an object or array, text/plain for a string)",
            false,
        ));
    } else {
        params.push(param(
            "accept",
            "string",
            "The media type wanted back, e.g. application/json",
            false,
        ));
    }
    params
}

fn all_actions() -> Vec<ActionDefinition> {
    let def = |name: &str, description: &str, params: Vec<Parameter>, example: Value| {
        let info = match name {
            "coap_get" => "-> CoAP GET {path} {query}",
            "coap_post" => "-> CoAP POST {path} {query} {preview(payload,60)}",
            "coap_put" => "-> CoAP PUT {path} {query} {preview(payload,60)}",
            "coap_delete" => "-> CoAP DELETE {path} {query}",
            "coap_observe" => "-> CoAP observe {path}",
            "coap_observe_cancel" => "-> CoAP cancel observation of {path}",
            _ => "-> CoAP stop",
        };
        ActionDefinition {
            name: name.to_string(),
            description: description.to_string(),
            parameters: params,
            example,
            log_template: Some(LogTemplate::new().with_info(info)),
        }
    };
    vec![
        def(
            "coap_get",
            "Read a resource",
            common_params(false),
            json!({"type": "coap_get", "path": "/sensors/temp"}),
        ),
        def(
            "coap_post",
            "Send data to a resource (often creates one)",
            common_params(true),
            json!({"type": "coap_post", "path": "/logs", "payload": "door opened"}),
        ),
        def(
            "coap_put",
            "Replace a resource's state",
            common_params(true),
            json!({"type": "coap_put", "path": "/example_data", "payload": "hello"}),
        ),
        def(
            "coap_delete",
            "Delete a resource",
            common_params(false),
            json!({"type": "coap_delete", "path": "/example_data"}),
        ),
        def(
            "coap_observe",
            "Register to be notified whenever the resource changes (RFC 7641). The first \
             answer arrives as coap_response with observing true; every later change as \
             coap_notification",
            common_params(false),
            json!({"type": "coap_observe", "path": "/time"}),
        ),
        def(
            "coap_observe_cancel",
            "Cancel an observation made with coap_observe",
            vec![param("path", "string", "The observed path", true)],
            json!({"type": "coap_observe_cancel", "path": "/time"}),
        ),
        def(
            "disconnect",
            "Stop: forget every exchange and observation and close the socket",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

/// A validated request, as the transport sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapRequest {
    /// `GET`, `POST`, `PUT` or `DELETE`.
    pub method: &'static str,
    /// Uri-Path segments.
    pub path: Vec<String>,
    /// Uri-Query items.
    pub query: Vec<String>,
    pub confirmable: bool,
    pub content_format: Option<u16>,
    pub accept: Option<u16>,
    pub payload: Vec<u8>,
    pub observe: ObserveAction,
}

impl CoapRequest {
    /// The path as the model wrote it, leading-slashed.
    pub fn path_string(&self) -> String {
        format!("/{}", self.path.join("/"))
    }
}

/// What a request does to an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveAction {
    None,
    Register,
    Cancel,
}

fn split_path(path: &str) -> Result<Vec<String>> {
    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(long) = segments.iter().find(|s| s.len() > MAX_URI_OPTION_LEN) {
        return Err(anyhow!(
            "path segment of {} bytes; a Uri-Path option carries at most {MAX_URI_OPTION_LEN}",
            long.len()
        ));
    }
    Ok(segments)
}

fn media_type(action: &Value, field: &str) -> Result<Option<u16>> {
    match action.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => content_format_id(name).map(Some).with_context(|| {
            format!("unknown {field} {name:?}; use e.g. text/plain or application/json")
        }),
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .map(Some)
            .with_context(|| format!("{field} must be a media type name or a number 0-65535")),
    }
}

/// Parse one model action into a request. `Ok(None)` is `disconnect`.
pub fn request_from_action(action: &Value) -> Result<Option<CoapRequest>> {
    let action_type = action
        .get("type")
        .and_then(Value::as_str)
        .context("missing 'type'")?;
    let (method, observe, with_payload) = match action_type {
        "coap_get" => ("GET", ObserveAction::None, false),
        "coap_post" => ("POST", ObserveAction::None, true),
        "coap_put" => ("PUT", ObserveAction::None, true),
        "coap_delete" => ("DELETE", ObserveAction::None, false),
        "coap_observe" => ("GET", ObserveAction::Register, false),
        "coap_observe_cancel" => ("GET", ObserveAction::Cancel, false),
        "disconnect" => return Ok(None),
        other => return Err(anyhow!("Unknown CoAP client action: {other}")),
    };
    let path = split_path(
        action
            .get("path")
            .and_then(Value::as_str)
            .context("missing string field 'path'")?,
    )?;
    let query: Vec<String> = match action.get("query") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(q)) => q
            .trim_start_matches('?')
            .split('&')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        Some(v) => return Err(anyhow!("'query' must be a string, got {v}")),
    };
    if let Some(long) = query.iter().find(|s| s.len() > MAX_URI_OPTION_LEN) {
        return Err(anyhow!(
            "query item of {} bytes; a Uri-Query option carries at most {MAX_URI_OPTION_LEN}",
            long.len()
        ));
    }
    let confirmable = match action.get("confirmable") {
        None | Some(Value::Null) => true,
        Some(v) => v.as_bool().context("'confirmable' must be true or false")?,
    };
    let (payload, content_format) = if with_payload {
        let explicit = media_type(action, "content_format")?;
        match action.get("payload") {
            Some(Value::String(text)) => (text.as_bytes().to_vec(), explicit.or(Some(0))),
            Some(v @ (Value::Object(_) | Value::Array(_))) => {
                (serde_json::to_vec(v)?, explicit.or(Some(50)))
            }
            Some(Value::Null) | None => {
                return Err(anyhow!("{action_type} needs a 'payload' (text or JSON)"))
            }
            Some(other) => (other.to_string().into_bytes(), explicit.or(Some(50))),
        }
    } else {
        (Vec::new(), None)
    };
    if payload.len() > MAX_REPRESENTATION_LEN {
        return Err(anyhow!(
            "payload is {} bytes; this client uploads at most {MAX_REPRESENTATION_LEN} (a body \
             over one block is sent in Block1 blocks, RFC 7959)",
            payload.len()
        ));
    }
    Ok(Some(CoapRequest {
        method,
        path,
        query,
        confirmable,
        content_format,
        accept: if with_payload {
            None
        } else {
            media_type(action, "accept")?
        },
        payload,
        observe,
    }))
}

impl Protocol for CoapClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "ack_timeout_ms".to_string(),
                type_hint: "integer".to_string(),
                description: "RFC 7252 ACK_TIMEOUT: milliseconds before the first \
                              retransmission of a Confirmable request (randomised up to 1.5x, \
                              doubling each time). Default 2000"
                    .to_string(),
                required: false,
                example: json!(2000),
                default: Some(json!(DEFAULT_ACK_TIMEOUT_MS)),
            },
            ParameterDefinition {
                name: "max_retransmit".to_string(),
                type_hint: "integer".to_string(),
                description: "RFC 7252 MAX_RETRANSMIT: how many times a Confirmable request is \
                              re-sent before it is reported as a timeout. Default 4, at most 8"
                    .to_string(),
                required: false,
                example: json!(4),
                default: Some(json!(DEFAULT_MAX_RETRANSMIT)),
            },
            ParameterDefinition {
                name: "block_size".to_string(),
                type_hint: "integer".to_string(),
                description: "Block1 block size in bytes: a request body larger than this is \
                              uploaded in blocks of this size (RFC 7959). A power of two from \
                              16 to 1024. A server that asks for smaller blocks gets them"
                    .to_string(),
                required: false,
                example: json!(1024),
                default: Some(json!(DEFAULT_BLOCK_SIZE)),
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
        "CoAP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            COAP_CONNECTED_EVENT.clone(),
            COAP_RESPONSE_EVENT.clone(),
            COAP_NOTIFICATION_EVENT.clone(),
            COAP_ERROR_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>CoAP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "coap",
            "coap client",
            "constrained application protocol",
            "iot client",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "CoAP (RFC 7252) client over a connected UDP socket, encoding and decoding with \
                 the server's own codec (src/server/coap/codec.rs). A transport task owns the \
                 socket: message ids and tokens, Confirmable retransmission with RFC 7252 \
                 back-off and a bounded attempt count, empty ACKs for separate responses and \
                 notifications, RST for tokens it does not know, Block2 reassembly (RFC 7959) \
                 up to 64 KiB, and Observe registration and cancellation (RFC 7641). The model \
                 is asked from a separate turn task.",
            )
            .llm_control(
                "Which requests to send: GET/POST/PUT/DELETE with path, query, content format \
                 and a text or JSON payload (Block1 over block_size), Confirmable or not, and \
                 Observe register/cancel. \
                 Every answer arrives as coap_response, coap_notification or coap_error.",
            )
            .e2e_testing(
                "tests/client/coap/real_server_test.rs, 7+ LLM calls, against libcoap's \
                 coap-server (C), written and read back with libcoap's coap-client. coap-client \
                 stores 3000 bytes; the model GETs them and is shown one coap_response \
                 reassembled from three Block2 blocks, PUTs a sentence built from that body \
                 (checked byte for byte), which coap-client reads back, then observes /time: \
                 registration, notifications, cancellation on the same token. A second test \
                 injects a PUT through the command channel that coap-client reads back, and a \
                 third PUTs 3000 bytes the transport uploads as Block1 blocks, read back whole \
                 by coap-client; blockwise_upload_test.rs does the same against aiocoap's \
                 server and against a hand-written server that lowers the block size. Not \
                 #[ignore]d; a missing coap-server or coap-client fails the test. \
                 transport_test.rs drives retransmission, the Block2 cap and order, the \
                 oversize drop, deduplication, RST and the exchange cap against hand-written \
                 servers.",
            )
            .notes(
                "No DTLS (coaps), no CoAP over TCP/WebSocket, no multicast. A request body is \
                 at most 64 KiB, uploaded in Block1 blocks over block_size. A notification \
                 over one block is reported truncated rather than fetched. Payloads reach the \
                 model as text or parsed JSON; a non-UTF-8 payload is reported by size only, \
                 never re-encoded.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "CoAP client for reading, writing and observing resources on constrained devices"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the CoAP server at localhost:5683, list its resources and observe /time"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5683",
                "base_stack": "coap",
                "instruction": "List the server's resources and read each one"
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5683",
                "base_stack": "coap",
                "event_handlers": [{
                    "event_pattern": "coap_notification",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<coap_client_handler>"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5683",
                "base_stack": "coap",
                "event_handlers": [
                    {
                        "event_pattern": "coap_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "coap_get", "path": "/.well-known/core"}]
                        }
                    },
                    {
                        "event_pattern": "coap_response",
                        "handler": {"type": "static", "actions": [{"type": "disconnect"}]}
                    }
                ]
            }),
        )
    }
}

impl Client for CoapClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let (ack_timeout_ms, max_retransmit, block_size) = match ctx.startup_params.as_ref() {
                Some(p) => (
                    p.get_optional_u64("ack_timeout_ms")?
                        .unwrap_or(DEFAULT_ACK_TIMEOUT_MS),
                    p.get_optional_u64("max_retransmit")?
                        .unwrap_or(DEFAULT_MAX_RETRANSMIT),
                    p.get_optional_u64("block_size")?
                        .unwrap_or(DEFAULT_BLOCK_SIZE),
                ),
                None => (
                    DEFAULT_ACK_TIMEOUT_MS,
                    DEFAULT_MAX_RETRANSMIT,
                    DEFAULT_BLOCK_SIZE,
                ),
            };
            let block_szx = (0..=crate::server::coap::codec::MAX_SZX)
                .find(|szx| crate::server::coap::codec::szx_size(*szx) as u64 == block_size)
                .ok_or_else(|| {
                    anyhow!("block_size {block_size} is not a power of two from 16 to 1024")
                })?;
            if !(10..=60_000).contains(&ack_timeout_ms) {
                return Err(anyhow!(
                    "ack_timeout_ms {ack_timeout_ms} is outside 10-60000"
                ));
            }
            if max_retransmit > 8 {
                return Err(anyhow!("max_retransmit {max_retransmit} is over 8"));
            }
            crate::client::coap::CoapClient::connect_with_llm_actions(
                ctx.remote_addr,
                crate::client::coap::Reliability {
                    ack_timeout: std::time::Duration::from_millis(ack_timeout_ms),
                    // Range-checked above.
                    max_retransmit: u32::try_from(max_retransmit).unwrap_or(4),
                    block_szx,
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
