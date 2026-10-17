//! ZooKeeper server protocol actions

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Jute `Stat`, the 68-byte struct that trails most ZooKeeper replies.
///
/// The handler supplies the interesting parts (`zxid`, `version`, sizes); the rest is filled
/// with values that are self-consistent for a server that keeps no znode tree. Encoding it here
/// rather than asking the model for hex is the point: a model cannot reliably emit 68 bytes of
/// big-endian integers, and one wrong byte desynchronizes the client for the whole connection.
fn encode_stat(zxid: i64, version: i32, data_length: i32, num_children: i32) -> Vec<u8> {
    let now_ms = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let mut stat = Vec::with_capacity(68);
    stat.extend_from_slice(&zxid.to_be_bytes()); // czxid
    stat.extend_from_slice(&zxid.to_be_bytes()); // mzxid
    stat.extend_from_slice(&now_ms.to_be_bytes()); // ctime
    stat.extend_from_slice(&now_ms.to_be_bytes()); // mtime
    stat.extend_from_slice(&version.to_be_bytes()); // version
    stat.extend_from_slice(&0i32.to_be_bytes()); // cversion
    stat.extend_from_slice(&0i32.to_be_bytes()); // aversion
    stat.extend_from_slice(&0i64.to_be_bytes()); // ephemeralOwner (0 = persistent)
    stat.extend_from_slice(&data_length.to_be_bytes()); // dataLength
    stat.extend_from_slice(&num_children.to_be_bytes()); // numChildren
    stat.extend_from_slice(&zxid.to_be_bytes()); // pzxid
    stat
}

/// Jute buffer/string: i32 length followed by the bytes.
fn encode_buffer(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Shared reply-header parameters. Every response action carries the same three.
fn header_parameters(zxid_description: &str) -> Vec<Parameter> {
    vec![
        Parameter {
            name: "xid".to_string(),
            type_hint: "integer".to_string(),
            description: "Transaction ID. Must be the `xid` of the request being answered — a \
                          ZooKeeper client matches replies to requests by this value and will \
                          hang or desynchronize if it does not match. Omit it and the request's \
                          own xid is used."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "zxid".to_string(),
            type_hint: "integer".to_string(),
            description: zxid_description.to_string(),
            required: true,
        },
        Parameter {
            name: "error_code".to_string(),
            type_hint: "integer".to_string(),
            description: "Error code (0 = OK, -101 = NONODE, -110 = NODEEXISTS, -102 = NOAUTH). \
                          A non-zero code sends a header-only reply and the body fields are \
                          ignored."
                .to_string(),
            required: false,
        },
    ]
}

/// Answer `getData` (opcode 4) with the znode's contents.
fn zookeeper_data_action() -> ActionDefinition {
    let mut parameters =
        header_parameters("ZooKeeper transaction ID (server-assigned change counter)");
    parameters.push(Parameter {
        name: "data".to_string(),
        type_hint: "string".to_string(),
        description: "The znode's contents, as text. Serialized for you together with the \
                      znode's Stat — do not encode anything by hand."
            .to_string(),
        required: true,
    });
    parameters.push(Parameter {
        name: "version".to_string(),
        type_hint: "integer".to_string(),
        description: "Data version of the znode. Defaults to 0.".to_string(),
        required: false,
    });

    ActionDefinition {
        name: "zookeeper_data".to_string(),
        description: "Answer a getData request with the contents of a znode. Use this for \
                      operation \"getData\"."
            .to_string(),
        parameters,
        example: json!({
            "type": "zookeeper_data",
            "xid": 3,
            "zxid": 100,
            "data": "postgres://localhost:5432"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ZooKeeper data ({data_len}B)")
                .with_debug("ZooKeeper zookeeper_data: xid={xid} zxid={zxid} data='{data}'"),
        ),
    }
}

/// Answer `getChildren` (opcode 8) / `getChildren2` (opcode 12).
fn zookeeper_children_action() -> ActionDefinition {
    let mut parameters =
        header_parameters("ZooKeeper transaction ID (server-assigned change counter)");
    parameters.push(Parameter {
        name: "children".to_string(),
        type_hint: "array".to_string(),
        description: "Child node names, without any path prefix — e.g. [\"web\", \"api\"] for \
                      the children of /services."
            .to_string(),
        required: true,
    });
    parameters.push(Parameter {
        name: "include_stat".to_string(),
        type_hint: "boolean".to_string(),
        description: "Set true only when answering getChildren2 (op_code 12), whose reply \
                      carries a Stat after the child list. Plain getChildren (op_code 8) does \
                      not. Defaults to false."
            .to_string(),
        required: false,
    });

    ActionDefinition {
        name: "zookeeper_children".to_string(),
        description: "Answer a getChildren request with the list of child node names. Use this \
                      for operation \"getChildren\" and \"getChildren2\"."
            .to_string(),
        parameters,
        example: json!({
            "type": "zookeeper_children",
            "xid": 3,
            "zxid": 200,
            "children": ["web", "api", "db"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ZooKeeper children")
                .with_debug("ZooKeeper zookeeper_children: xid={xid} zxid={zxid}"),
        ),
    }
}

/// Answer `exists` (opcode 3) / `setData` (opcode 5), whose reply is a bare `Stat`.
fn zookeeper_stat_action() -> ActionDefinition {
    let mut parameters =
        header_parameters("ZooKeeper transaction ID (server-assigned change counter)");
    parameters.push(Parameter {
        name: "version".to_string(),
        type_hint: "integer".to_string(),
        description: "Data version of the znode. Defaults to 0.".to_string(),
        required: false,
    });
    parameters.push(Parameter {
        name: "data_length".to_string(),
        type_hint: "integer".to_string(),
        description: "Size in bytes of the znode's data. Defaults to 0.".to_string(),
        required: false,
    });
    parameters.push(Parameter {
        name: "num_children".to_string(),
        type_hint: "integer".to_string(),
        description: "Number of children the znode has. Defaults to 0.".to_string(),
        required: false,
    });

    ActionDefinition {
        name: "zookeeper_stat".to_string(),
        description: "Answer with a znode's Stat and nothing else. Use this for operation \
                      \"exists\" and \"setData\". To report that the node does not exist, use \
                      zookeeper_response with error_code -101 instead."
            .to_string(),
        parameters,
        example: json!({
            "type": "zookeeper_stat",
            "xid": 3,
            "zxid": 100,
            "data_length": 25
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ZooKeeper stat")
                .with_debug("ZooKeeper zookeeper_stat: xid={xid} zxid={zxid} version={version}"),
        ),
    }
}

/// Answer `create` (opcode 1), whose reply is the created path.
fn zookeeper_created_action() -> ActionDefinition {
    let mut parameters =
        header_parameters("ZooKeeper transaction ID (server-assigned change counter)");
    parameters.push(Parameter {
        name: "path".to_string(),
        type_hint: "string".to_string(),
        description: "The path that was created. For a sequential node this is the request's \
                      path with the 10-digit sequence number appended."
            .to_string(),
        required: true,
    });

    ActionDefinition {
        name: "zookeeper_created".to_string(),
        description: "Answer a create request with the path of the new znode. Use this for \
                      operation \"create\". To reject a create, use zookeeper_response with \
                      error_code -110 (NODEEXISTS)."
            .to_string(),
        parameters,
        example: json!({
            "type": "zookeeper_created",
            "xid": 3,
            "zxid": 300,
            "path": "/services/web"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ZooKeeper created {path}")
                .with_debug("ZooKeeper zookeeper_created: xid={xid} zxid={zxid} path={path}"),
        ),
    }
}

/// The header-only response action, and the escape hatch for opcodes with no structured
/// encoder. Declared here rather than inline so the event type and `get_sync_actions()` hand
/// the model the same definition.
fn zookeeper_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "zookeeper_response".to_string(),
        description: "Send a bare ZooKeeper reply header — use this to report an error \
                      (`error_code`), or to answer an operation whose reply carries no body \
                      (delete, sync). Prefer zookeeper_data / zookeeper_children / \
                      zookeeper_stat / zookeeper_created where they apply: they encode the \
                      reply body for you. `data_hex` is a last-resort escape hatch for opcodes \
                      with no structured action and requires hand-written Jute — see \
                      src/server/zookeeper/CLAUDE.md."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "xid".to_string(),
                type_hint: "integer".to_string(),
                description: "Transaction ID. Must be the `xid` of the request being answered — \
                              a ZooKeeper client matches replies to requests by this value and \
                              will hang or desynchronize if it does not match. Omit it and the \
                              request's own xid is used."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "zxid".to_string(),
                type_hint: "integer".to_string(),
                description: "ZooKeeper transaction ID (server-assigned change counter)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "error_code".to_string(),
                type_hint: "integer".to_string(),
                description: "Error code (0 = OK, -101 = NONODE, -110 = NODEEXISTS, -102 = NOAUTH)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "data_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Jute-serialized reply body, hex encoded. Omit or leave empty for \
                              operations whose reply carries no body."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "zookeeper_response",
            "xid": 1,
            "zxid": 100,
            "error_code": 0,
            "data_hex": "0000000000000064"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ZooKeeper response (err={error_code})")
                .with_debug(
                    "ZooKeeper zookeeper_response: xid={xid} zxid={zxid} error_code={error_code}",
                ),
        ),
    }
}

/// Every reply action, in the order a model should reach for them. The event type and
/// `get_sync_actions()` both use this, so an action can never be offered by one and rejected
/// by the other.
fn zookeeper_actions() -> Vec<ActionDefinition> {
    vec![
        zookeeper_data_action(),
        zookeeper_children_action(),
        zookeeper_stat_action(),
        zookeeper_created_action(),
        zookeeper_response_action(),
    ]
}

// Event type constants
pub static ZOOKEEPER_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zookeeper_request",
        "A ZooKeeper client sent a request on an established session. Answer with the action \
         that matches `operation`: getData -> zookeeper_data, getChildren/getChildren2 -> \
         zookeeper_children, exists/setData -> zookeeper_stat, create -> zookeeper_created, \
         anything else or any error -> zookeeper_response. The session handshake and pings are \
         handled by the server and never appear here.",
        json!({
            "type": "zookeeper_data",
            "xid": 3,
            "zxid": 100,
            "data": "postgres://localhost:5432"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "xid".to_string(),
            type_hint: "integer".to_string(),
            description: "Request transaction ID, an integer: echo back the `xid` the event \
                          carried. The examples show a literal because that is what an LLM \
                          answer must contain - nothing substitutes into a model's reply. A \
                          static handler is the other case and may write the placeholder \
                          {{event.xid}}, which the handler executor interpolates before \
                          dispatch."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Operation type (create, delete, getData, setData, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "op_code".to_string(),
            type_hint: "integer".to_string(),
            description: "Numeric ZooKeeper opcode, for operations with no name mapping"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description:
                "ZNode path (e.g., /myapp/config). Empty when the request carries no path."
                    .to_string(),
            required: false,
        },
    ])
    .with_actions(zookeeper_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("ZooKeeper {operation} {path}")
            .with_debug("ZooKeeper request xid={xid} op={operation} path={path}")
            .with_trace("ZooKeeper request: {json_pretty(.)}"),
    )
});

/// ZooKeeper protocol implementation
pub struct ZookeeperProtocol;

/// Read a model-supplied ZooKeeper wire integer, refusing anything a Java `int` cannot hold.
///
/// Every one of these was `as_i64()… as i32`, which wraps in silence, and for `error_code` the
/// wrap is a fail-open: **`error_code: 4294967296` narrows to `0`**, `is_error` goes false, and
/// a reply the model meant as NONODE or NOAUTH is encoded as the success it was refusing —
/// body appended and all. The `required: true` guard on `zookeeper_response` checks that the
/// field is *an integer*, which such a value is; it never checked that the integer survived
/// the narrowing.
///
/// `xid` is the same shape on a correlation identifier: a client matches replies by xid, so a
/// wrapped one answers whichever request happened to carry the truncated value.
///
/// Refusing beats clamping — `i32::MAX` is not what the model asked for either — and the
/// message is what the repair loop reads. ZooKeeper's own wire types are Java `int`, so that
/// is the honest bound rather than a list of named codes.
fn i32_field(action: &serde_json::Value, key: &str, default: i32) -> Result<i32> {
    let value = match action.get(key) {
        None => return Ok(default),
        Some(v) if v.is_null() => return Ok(default),
        Some(v) => v,
    };
    let raw = value
        .as_i64()
        .ok_or_else(|| anyhow!("zookeeper '{key}' must be an integer, got {value}"))?;
    i32::try_from(raw).map_err(|_| {
        anyhow!(
            "zookeeper '{key}' {raw} does not fit the 32-bit integer ZooKeeper puts on the \
             wire (-2147483648 to 2147483647). Truncating it would change what the reply \
             says: an error_code that narrows to 0 is a grant."
        )
    })
}

impl ZookeeperProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ZookeeperProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        zookeeper_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "ZooKeeper"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![(*ZOOKEEPER_REQUEST_EVENT).clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ZooKeeper"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["zookeeper", "zk"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against a real, independent client — zookeeper-async —
            // covering a real ZooKeeper client completing session and node operations. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(2181)
            .implementation(
                "Hand-rolled ZooKeeper wire protocol. The ConnectRequest/ConnectResponse \
                 session handshake, pings and closeSession are answered by the server; every \
                 other opcode is handed to the handler as a zookeeper_request event.",
            )
            .llm_control(
                "The handler chooses the reply: zookeeper_data (getData), zookeeper_children \
                 (getChildren), zookeeper_stat (exists/setData), zookeeper_created (create), \
                 or zookeeper_response for errors and bodiless replies. Jute encoding is done \
                 in Rust, not by the model.",
            )
            .e2e_testing(
                "E2E driven by the real zookeeper-async client: it completes a session, reads \
                 data and children, and receives NONODE errors. One test also checks the \
                 ConnectResponse bytes directly over a raw socket.",
            )
            .notes(
                "Session handshake works and real clients complete a session. Limitations: \
                 only the request header and the leading path string are decoded, so \
                 create/setData payloads, watch flags, ACLs and version numbers never reach \
                 the handler; watches are not implemented (no server-initiated frames); no \
                 session is ever expired because no session table is kept; the zookeeper_response \
                 data_hex escape hatch still asks for hand-written Jute for opcodes with no \
                 structured action. No storage: the handler answers every request.",
            )
            .max_inbound_bytes(crate::server::zookeeper::MAX_REQUEST_BYTES as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "ZooKeeper distributed coordination server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a ZooKeeper server on port 2181"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every request with a success reply, echoing the
        // request xid, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "zookeeper_request":
    actions = [{"type": "zookeeper_response",
                "xid": event.get("xid", 0),
                "zxid": 0, "error_code": 0}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all ZooKeeper responses intelligently
            json!({
                "type": "open_server",
                "port": 2181,
                "base_stack": "zookeeper",
                "instruction": "ZooKeeper distributed coordination server handling znode operations"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 2181,
                "base_stack": "zookeeper",
                "event_handlers": [{
                    "event_pattern": "zookeeper_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 2181,
                "base_stack": "zookeeper",
                "event_handlers": [{
                    "event_pattern": "zookeeper_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "zookeeper_data",
                            // Echo the request's xid; a literal would break correlation.
                            "xid": 3,
                            "zxid": 1,
                            "data": "hello"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for ZookeeperProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::zookeeper::ZookeeperServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. ZooKeeper: the client sends a ConnectRequest first and the server's reply is framed against it.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the ZooKeeper server: the client sends a ConnectRequest first and the server's reply is framed against it"
                ));
            }

            ZookeeperServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
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

        // `xid` is deliberately passed through as an Option rather than defaulted to 0 here:
        // the connection loop knows the xid of the request being answered and substitutes it
        // when the handler omitted one. Defaulting to 0 at this layer would put a reply on the
        // wire that no client can correlate.
        let xid = match action.get("xid") {
            None => None,
            Some(v) if v.is_null() => None,
            Some(_) => Some(i32_field(&action, "xid", 0)?),
        };
        let zxid = action.get("zxid").and_then(|v| v.as_i64()).unwrap_or(0);
        // Shared by every action below. The dedicated success responses (create, get_data,
        // …) do not declare `error_code` and are affirmative by construction, so 0 is right
        // for them; `zookeeper_response` DOES declare it required and is checked in its own
        // arm, because there 0 is a grant rather than a shape.
        let error_code = i32_field(&action, "error_code", 0)?;
        let version = i32_field(&action, "version", 0)?;

        // A non-zero error code means the reply is header-only: real ZooKeeper sends no body
        // with an error, and appending one desynchronizes the client.
        let is_error = error_code != 0;

        let body = match action_type {
            // Not offered to the model (a ZooKeeper server answers requests, it does not hang
            // up on its own), but the dashboard's "disconnect this peer" injects it through
            // the peer command task, which half-closes the write side on this result.
            "close_connection" => return Ok(ActionResult::CloseConnection),
            "zookeeper_data" => {
                if is_error {
                    Vec::new()
                } else {
                    let data = action
                        .get("data")
                        .and_then(|v| v.as_str())
                        .context("zookeeper_data requires a 'data' field")?;
                    let mut body = encode_buffer(data.as_bytes());
                    body.extend_from_slice(&encode_stat(zxid, version, data.len() as i32, 0));
                    body
                }
            }
            "zookeeper_children" => {
                if is_error {
                    Vec::new()
                } else {
                    let children = action
                        .get("children")
                        .and_then(|v| v.as_array())
                        .context("zookeeper_children requires a 'children' array")?;
                    let names: Vec<&str> = children
                        .iter()
                        .map(|c| {
                            c.as_str().ok_or_else(|| {
                                anyhow!("zookeeper_children: every entry of 'children' must be a string")
                            })
                        })
                        .collect::<Result<_>>()?;

                    let mut body = Vec::new();
                    body.extend_from_slice(&(names.len() as i32).to_be_bytes());
                    for name in &names {
                        body.extend_from_slice(&encode_buffer(name.as_bytes()));
                    }
                    // getChildren2 (op_code 12) trails a Stat; plain getChildren does not.
                    if action
                        .get("include_stat")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        body.extend_from_slice(&encode_stat(zxid, version, 0, names.len() as i32));
                    }
                    body
                }
            }
            "zookeeper_stat" => {
                if is_error {
                    Vec::new()
                } else {
                    let data_length = i32_field(&action, "data_length", 0)?;
                    let num_children = i32_field(&action, "num_children", 0)?;
                    encode_stat(zxid, version, data_length, num_children)
                }
            }
            "zookeeper_created" => {
                if is_error {
                    Vec::new()
                } else {
                    let path = action
                        .get("path")
                        .and_then(|v| v.as_str())
                        .context("zookeeper_created requires a 'path' field")?;
                    encode_buffer(path.as_bytes())
                }
            }
            "zookeeper_response" => {
                // `error_code` is declared `required: true` on this action, and it is the one
                // action whose whole purpose is to say whether the operation succeeded.
                // Defaulting it to 0 meant an answer that omitted it — or supplied a
                // non-integer — was encoded as a successful reply, so a model that meant
                // NONODE or NOAUTH silently granted the operation instead.
                if !action
                    .get("error_code")
                    .map(|v| v.is_i64() || v.is_u64())
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "zookeeper_response requires `error_code` (an integer; 0 = OK, \
                         -101 = NONODE, -110 = NODEEXISTS, -102 = NOAUTH) - it decides success \
                         or failure and must be stated, not assumed"
                    ));
                }
                // Reject invalid hex loudly instead of silently sending a body-less reply:
                // a truncated body desynchronizes the client for the rest of the connection.
                match action.get("data_hex").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() && !is_error => hex::decode(s).map_err(|e| {
                        anyhow!("zookeeper_response: 'data_hex' is not valid hex: {}", e)
                    })?,
                    _ => Vec::new(),
                }
            }
            _ => return Err(anyhow!("Unknown action type: {}", action_type)),
        };

        Ok(ActionResult::Custom {
            name: "zookeeper_response".to_string(),
            data: json!({
                "xid": xid,
                "zxid": zxid,
                "error_code": error_code,
                "body_hex": hex::encode(&body),
            }),
        })
    }
}
