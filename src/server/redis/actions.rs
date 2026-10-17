//! Redis protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Redis protocol action handler
pub struct RedisProtocol {
    #[allow(dead_code)]
    connection_id: ConnectionId,
    #[allow(dead_code)]
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    /// The RESP version this connection speaks: 2 until a `HELLO 3`. Shared by the read loop,
    /// the peer-injection task and the pub/sub hub, which encodes each delivered message for
    /// its subscriber's version.
    protover: Arc<AtomicU8>,
    /// The running server's pub/sub hub and cluster topology. `None` on the registry's
    /// stateless instance, which reaches them through `execute_action_with_state` instead.
    shared: Option<Arc<super::RedisShared>>,
}

impl RedisProtocol {
    pub fn new(
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Self {
        Self {
            connection_id,
            app_state,
            status_tx,
            protover: Arc::new(AtomicU8::new(2)),
            shared: None,
        }
    }

    /// The instance one connection encodes through, bound to its server's shared state.
    pub fn for_connection(
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        shared: Arc<super::RedisShared>,
    ) -> Self {
        Self {
            shared: Some(shared),
            ..Self::new(connection_id, app_state, status_tx)
        }
    }

    /// The RESP version replies are encoded for (2 or 3).
    pub fn protocol_version(&self) -> u8 {
        self.protover.load(Ordering::Relaxed)
    }

    pub fn set_protocol_version(&self, version: u8) {
        self.protover.store(version, Ordering::Relaxed);
    }

    /// The shared version cell, handed to the pub/sub hub with a subscription.
    pub fn protover_cell(&self) -> Arc<AtomicU8> {
        self.protover.clone()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for RedisProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Unsupported by this server and refused if set to true. Redis: a RESP server answers commands and never speaks first; an unsolicited reply would desynchronise every client's command pipeline."
                        .to_string(),
                    required: false,
                    example: json!(false),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "first_byte_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a connected peer may send no command at all before \
                                  the server closes it. Default 300, matching the window a \
                                  `manual` rule gives a human to answer one event - the peer \
                                  is often NetGet's own Redis client, which opens a socket and \
                                  sends nothing until someone uses [ send message ]. Lower it \
                                  (30 was the old value) for a listener exposed to strangers."
                        .to_string(),
                    required: false,
                    example: json!(300),
                    default: Some(serde_json::json!(super::FIRST_COMMAND_READ_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "idle_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds an established connection may go without a further \
                                  command before the server closes it. Default 300. Real Redis \
                                  ships `timeout 0` and every pooling client holds connections \
                                  unused between bursts, so raise it rather than lower it if \
                                  your clients pool."
                        .to_string(),
                    required: false,
                    example: json!(300),
                    default: Some(serde_json::json!(super::IDLE_BETWEEN_COMMANDS_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "cluster_nodes".to_string(),
                    type_hint: "array".to_string(),
                    description: "Run in cluster mode as one master of the Redis Cluster this \
                                  array describes. Each node is {\"host\", \"port\", \
                                  \"slots\": [\"0-5460\", ...], \"id\" (optional, 40 hex), \
                                  \"myself\": true for this server}; this server's own host and \
                                  port default to where it is listening. The server then answers \
                                  CLUSTER SLOTS/SHARDS/NODES/INFO/KEYSLOT/MYID itself and \
                                  redirects a key in a slot another node owns with -MOVED, so a \
                                  cluster client can navigate several NetGet servers given the \
                                  same array. Omit it for a standalone server."
                        .to_string(),
                    required: false,
                    example: json!([
                        {"host": "127.0.0.1", "port": 7000, "slots": ["0-8191"], "myself": true},
                        {"host": "127.0.0.1", "port": 7001, "slots": ["8192-16383"]}
                    ]),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Both reach the running server through `execute_action_with_state`. (A
        // `list_redis_connections` action used to be declared here; its executor returned a
        // hardcoded empty list, so it only ever misled the model.)
        vec![
            redis_publish_message_action(),
            redis_cluster_set_slot_action(),
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            redis_simple_string_action(),
            redis_bulk_string_action(),
            redis_array_action(),
            redis_integer_action(),
            redis_error_action(),
            redis_null_action(),
            close_this_connection_action(),
            redis_accept_subscription_action(),
            redis_deliver_message_action(),
            redis_publish_message_action(),
            redis_cluster_set_slot_action(),
        ]
        .into_iter()
        .chain(resp3_actions())
        .collect()
    }
    fn protocol_name(&self) -> &'static str {
        "Redis"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_redis_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Redis"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["redis"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against two independent clients that share no code with each
            // other or with redis-protocol — redis-rs (Rust) and redis-cli (C). Not Stable:
            // Stable additionally wants spec compliance and scripting support reviewed, which
            // has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(6379)
            .implementation("redis-protocol v6.0 (RESP2 request parsing), manual RESP2/RESP3 encoding per connection after HELLO")
            .llm_control(
                "Every data command (GET, SET, INCR, ...); pub/sub policy (whether a SUBSCRIBE is \
                 allowed, whether a PUBLISH is delivered and what it returns) and messages of its \
                 own; cluster slot ownership",
            )
            .e2e_testing(
                "Two independent clients. redis-rs (tests/server/redis/e2e_test.rs, \
                 llm_failure_test.rs): one test per RESP2 reply type, each deserialised into \
                 the Rust type the test asked for. redis-cli — the C client, valkey-cli here \
                 (real_client_test.rs, hard-fails when the binary is absent): seven commands on \
                 one connection, asserted as one ordered list of what --no-raw printed, so each \
                 reply type is read off the wire rather than coerced (simple string, bulk \
                 string quoted, (integer) n, a two-element multi-bulk, (nil) distinguished from \
                 an empty bulk string, and (error) …) and a reply landing against the wrong \
                 command fails as a mismatched line. \
                 RESP3 (resp3_test.rs): HELLO 3 answered in Rust, every RESP3 type read by \
                 redis-cli -3 and by redis-py 5's own RESP3 parser (with credentials sent in \
                 HELLO and a push ahead of a reply), and the RESP2 downgrades by both. \
                 Pub/sub (pubsub_test.rs): redis-cli subscribers on RESP2 and RESP3 and on a \
                 pattern receive what redis-cli publishes and what the model publishes, and \
                 redis-rs's RESP2 PubSub and RESP3 push sender read message and pmessage; the \
                 model's refusal and withholding hold. Cluster (cluster_test.rs): three servers \
                 sharing a cluster_nodes topology are navigated by redis-cli -c, pass \
                 redis-cli --cluster check, and serve redis-rs's ClusterClient, which follows \
                 MOVED after the model moves a slot; ASK/ASKING for a migrating slot. Hash slots \
                 and glob matching equal a real redis-server's CLUSTER KEYSLOT and KEYS \
                 (keys_oracle_test.rs). Every pub/sub bound and the slow-consumer disconnect \
                 are pinned from raw sockets (pubsub_bounds_test.rs). \
                 NOT proven: inline commands, pipelining \
                 (neither client sends two commands in one write), AUTH/SELECT/MULTI, \
                 cluster-wide PUBLISH (there is no bus), and TLS.",
            )
            .notes("RESP2, and RESP3 after HELLO 3 (no attributes, no streamed types, no client-side caching); HELLO with AUTH is judged by the handler. Pub/sub: SUBSCRIBE/PSUBSCRIBE/SSUBSCRIBE (model-approved), UNSUBSCRIBE family, PUBLISH/SPUBLISH (model decides delivery), PUBSUB introspection, RESP2 subscribed mode, redis_publish_message for the model's own messages; bounded per connection, per server and per message, and a subscriber 8 MiB behind is disconnected. Cluster mode (cluster_nodes): CLUSTER SLOTS/SHARDS/NODES/INFO/KEYSLOT/MYID, MOVED/ASK/CROSSSLOT/CLUSTERDOWN routing by CRC16 hash slot, redis_cluster_set_slot; no bus, no replicas. No SELECT/MULTI semantics, no inline commands")
            .max_inbound_bytes(crate::server::redis::MAX_PENDING_FRAME_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Redis in-memory data store"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Redis server on port 6379"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic RESP replies keyed off the command verb. The 'command'
        // event field is the full command line, so split off the first word.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "redis_command":
    parts = event.get("command", "").split()
    verb = parts[0].upper() if parts else ""
    if verb == "PING":
        actions = [{"type": "redis_simple_string", "value": "PONG"}]
    elif verb == "SET":
        actions = [{"type": "redis_simple_string", "value": "OK"}]
    elif verb == "GET":
        actions = [{"type": "redis_bulk_string", "value": "cached-value"}]
    elif verb == "INCR":
        actions = [{"type": "redis_integer", "value": 1}]
    else:
        actions = [{"type": "redis_error", "message": "ERR unknown command"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: model acts as a coherent key-value store across commands.
            json!({
                "type": "open_server",
                "port": 6379,
                "base_stack": "redis",
                "instruction": "Act as a Redis server backing a session cache. Remember values set with SET and return them on GET, treat INCR/DECR as maintaining running counters, and answer TTL/EXISTS consistently with what has been stored so far in this connection."
            }),
            // Script mode: fixed replies per command verb, no LLM call.
            json!({
                "type": "open_server",
                "port": 6379,
                "base_stack": "redis",
                "event_handlers": [{
                    "event_pattern": "redis_command",
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
                "port": 6379,
                "base_stack": "redis",
                "event_handlers": [{
                    "event_pattern": "redis_command",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "redis_simple_string",
                            "value": "OK"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for RedisProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::redis::RedisServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. Redis: a RESP server answers commands and never speaks first; an unsolicited reply would desynchronise every client's command pipeline.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the Redis server: a RESP server answers commands and never speaks first; an unsolicited reply would desynchronise every client's command pipeline"
                ));
            }

            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;
            let cluster_nodes = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_array("cluster_nodes"))
                .transpose()?
                .flatten()
                .map(|nodes| serde_json::Value::Array(nodes.clone()));

            RedisServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
                ctx.server_id,
                super::RedisServerOptions {
                    first_byte_timeout_secs,
                    idle_timeout_secs,
                    cluster_nodes,
                },
            )
            .await
        })
    }

    /// `redis_publish_message` and `redis_cluster_set_slot` act on the running server, which
    /// the registry's stateless instance can only reach through the handle `spawn` registered.
    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<ActionResult>> + Send + 'a>,
    > {
        Box::pin(async move {
            let needs_server = matches!(
                action.get("type").and_then(|v| v.as_str()),
                Some("redis_publish_message" | "redis_cluster_set_slot")
            );
            if needs_server && self.shared.is_none() {
                let shared = match server_id {
                    Some(id) => state.server_handle::<super::RedisShared>(id).await,
                    None => None,
                };
                let Some(shared) = shared else {
                    anyhow::bail!(
                        "this action needs a running Redis server; name it with server_id \
                         (it is dispatched through execute_action_with_state)"
                    );
                };
                return execute_on_shared(&shared, &action, &self.status_tx);
            }
            self.execute_action(action)
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "redis_simple_string" => self.execute_redis_simple_string(action),
            "redis_bulk_string" => self.execute_redis_bulk_string(action),
            "redis_array" => self.execute_redis_array(action),
            "redis_integer" => self.execute_redis_integer(action),
            "redis_error" => self.execute_redis_error(action),
            "redis_null" => self.execute_redis_null(action),
            "redis_map"
            | "redis_set"
            | "redis_double"
            | "redis_boolean"
            | "redis_big_number"
            | "redis_verbatim_string"
            | "redis_push" => self.execute_resp3(action_type, &action),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            // Decisions the read loop carries out: it holds the channel and the message the
            // event was about, and the connection's outbox the confirmations go to.
            "redis_accept_subscription" => Ok(ActionResult::Custom {
                name: ACCEPT_SUBSCRIPTION.to_string(),
                data: json!({}),
            }),
            "redis_deliver_message" => Ok(ActionResult::Custom {
                name: DELIVER_MESSAGE.to_string(),
                data: json!({}),
            }),
            "redis_publish_message" | "redis_cluster_set_slot" => match &self.shared {
                Some(shared) => execute_on_shared(shared, &action, &self.status_tx),
                None => Err(anyhow::anyhow!(
                    "{action_type} needs the running server; it is dispatched through \
                     execute_action_with_state with a server_id"
                )),
            },
            // Not offered to the model (`close_this_connection` is its verb), but the
            // dashboard's "disconnect this peer" injects `close_connection` through the peer
            // command task, which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Redis action: {}", action_type)),
        }
    }
}

impl RedisProtocol {
    /// Every reply verb returns `ActionResult::Output` with the RESP2 bytes already
    /// encoded, so the same executor serves both the connection's read loop and the
    /// dashboard's "message this peer" injection (`server::peer_support` writes
    /// `Output` bytes; a `Custom` result would be reported as executed without
    /// touching the wire — the gap this refactor closed).
    fn execute_redis_simple_string(&self, action: serde_json::Value) -> Result<ActionResult> {
        let value = action
            .get("value")
            .and_then(|v| v.as_str())
            .context("Missing 'value' field")?;

        debug!("Redis simple string response: {}", value);
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Redis → Simple string: {}", value));

        Ok(ActionResult::Output(encode_simple_string(value)))
    }

    fn execute_redis_bulk_string(&self, action: serde_json::Value) -> Result<ActionResult> {
        let value = action.get("value");

        let result = if let Some(v) = value {
            if v.is_null() {
                None
            } else if let Some(s) = v.as_str() {
                Some(s.as_bytes().to_vec())
            } else {
                Some(v.to_string().as_bytes().to_vec())
            }
        } else {
            None
        };

        debug!("Redis bulk string response: {:?}", result);
        let _ = self.status_tx.send(format!(
            "[DEBUG] Redis → Bulk string: {} bytes",
            result.as_ref().map(|v| v.len()).unwrap_or(0)
        ));

        Ok(ActionResult::Output(match result {
            Some(bytes) => encode_bulk_string(&bytes),
            None => super::resp3::null(self.protocol_version()),
        }))
    }

    fn execute_redis_array(&self, action: serde_json::Value) -> Result<ActionResult> {
        let values = action
            .get("values")
            .and_then(|v| v.as_array())
            .context("Missing 'values' array")?;

        debug!("Redis array response: {} elements", values.len());
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Redis → Array: {} elements", values.len()));

        Ok(ActionResult::Output(super::resp3::array(
            values,
            self.protocol_version(),
        )?))
    }

    fn execute_redis_integer(&self, action: serde_json::Value) -> Result<ActionResult> {
        let value = action
            .get("value")
            .and_then(|v| v.as_i64())
            .context("Missing 'value' field")?;

        debug!("Redis integer response: {}", value);
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Redis → Integer: {}", value));

        Ok(ActionResult::Output(encode_integer(value)))
    }

    fn execute_redis_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' field")?;

        // An error the handler *chose* to send, not one netget synthesised because it could
        // not answer. On the wire both are just `-…`, so the log carries the distinction, as
        // `src/server/radius/` does: `decision=model_reject` here,
        // `decision=fail_closed_*` in `mod.rs`.
        debug!(
            "Redis connection {} decision=model_reject: {}",
            self.connection_id,
            crate::utils::truncate_for_log(message, 512)
        );
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Redis ✗ Error: {}", message));

        Ok(ActionResult::Output(encode_error(message)))
    }

    fn execute_redis_null(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("Redis null response");
        let _ = self.status_tx.send("[DEBUG] Redis → Null".to_string());

        Ok(ActionResult::Output(super::resp3::null(
            self.protocol_version(),
        )))
    }

    /// The RESP3 reply types, encoded for this connection's version (downgraded on RESP2).
    fn execute_resp3(&self, kind: &str, action: &serde_json::Value) -> Result<ActionResult> {
        use super::resp3;
        let proto = self.protocol_version();
        let items = || -> Result<&Vec<serde_json::Value>> {
            action
                .get("values")
                .and_then(|v| v.as_array())
                .context("Missing 'values' array")
        };
        let bytes = match kind {
            "redis_map" => resp3::map(
                &resp3::entries(action.get("entries").context("Missing 'entries'")?)?,
                proto,
            )?,
            "redis_set" => resp3::set(items()?, proto)?,
            "redis_double" => {
                resp3::double(action.get("value").context("Missing 'value'")?, proto)?
            }
            "redis_boolean" => resp3::boolean(
                action
                    .get("value")
                    .and_then(|v| v.as_bool())
                    .context("Missing boolean 'value'")?,
                proto,
            ),
            "redis_big_number" => resp3::big_number(
                action
                    .get("value")
                    .and_then(|v| v.as_str())
                    .context("Missing 'value' (a string of digits)")?,
                proto,
            )?,
            "redis_verbatim_string" => resp3::verbatim(
                action
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("txt"),
                action
                    .get("text")
                    .and_then(|v| v.as_str())
                    .context("Missing 'text'")?,
                proto,
            )?,
            _ => resp3::push(items()?, proto)?,
        };
        debug!(
            "Redis {} reply (RESP{}): {} bytes",
            kind,
            proto,
            bytes.len()
        );
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Redis → {kind} (RESP{proto})"));
        Ok(ActionResult::Output(bytes))
    }
}

// ============================================================================
// RESP2 encoding — single source of truth
// ============================================================================
//
// Called by the executors above (so the LLM path, script/static handlers and
// dashboard peer injection all produce identical bytes) and by `mod.rs` for the
// replies the loop synthesises itself (frame-cap error, LLM-failure error,
// no-response error).

/// Strip CR and LF from a RESP *simple* payload, mapping each to a space.
///
/// A RESP simple string (`+…`) and simple error (`-…`) are CRLF-terminated with **no length
/// prefix**, so a newline anywhere in the payload ends the frame early and everything after it
/// is parsed as the *next* reply. The connection is then desynchronised for good: every
/// subsequent command reads the wrong answer, and the client has no way to notice.
///
/// The value comes from model output (`redis_simple_string`'s `value`, `redis_error`'s
/// `message`), so it is exactly as trustworthy as any other generated text. `mod.rs` documents
/// this hazard on the LLM-failure path and avoids it by sending a fixed category; the
/// model-facing verbs had no such guard.
///
/// Mapping to a space rather than rejecting the reply is what Redis itself does —
/// `addReplyErrorFormat` runs `sdsmapchars(s, "\r\n", "  ", 2)` before framing. This goes one
/// step further than Redis and maps *every* control character, ESC included: a simple string
/// or error is printed verbatim by `redis-cli`, where an escape sequence forges a screen.
fn sanitize_simple_payload(s: &str, action: &str) -> String {
    let cleaned = crate::utils::sanitize::line_field(s);
    if cleaned == s {
        return cleaned;
    }
    warn!(
        "Redis: {} payload contained a control character, which for CR/LF would have ended the \
         RESP frame early and desynchronised the connection; mapping each to a space (as Redis \
         does)",
        action
    );
    cleaned
}

/// Encode a simple string response ("+OK\r\n")
pub fn encode_simple_string(s: &str) -> Vec<u8> {
    format!("+{}\r\n", sanitize_simple_payload(s, "simple string")).into_bytes()
}

/// Encode a bulk string response ("$5\r\nhello\r\n")
pub fn encode_bulk_string(bytes: &[u8]) -> Vec<u8> {
    let mut result = format!("${}\r\n", bytes.len()).into_bytes();
    result.extend_from_slice(bytes);
    result.extend_from_slice(b"\r\n");
    result
}

/// Encode a null bulk string ("$-1\r\n")
pub fn encode_null() -> Vec<u8> {
    b"$-1\r\n".to_vec()
}

/// Encode an integer response (":42\r\n")
pub fn encode_integer(i: i64) -> Vec<u8> {
    format!(":{}\r\n", i).into_bytes()
}

/// Encode an error response ("-ERR message\r\n")
pub fn encode_error(msg: &str) -> Vec<u8> {
    format!("-{}\r\n", sanitize_simple_payload(msg, "error")).into_bytes()
}

/// Encode an array response.
///
/// The element mapping is part of the `redis_array` action contract documented to the LLM:
/// strings become bulk strings, integers become RESP integers, booleans become the bulk
/// strings `"1"`/`"0"`, null becomes a nil bulk string, and nested arrays/objects are
/// serialized to JSON and sent as a bulk string (RESP2 has no JSON type).
pub fn encode_array(values: &[serde_json::Value]) -> Vec<u8> {
    let mut result = format!("*{}\r\n", values.len()).into_bytes();

    for value in values {
        match value {
            serde_json::Value::String(s) => {
                result.extend_from_slice(&encode_bulk_string(s.as_bytes()));
            }
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    result.extend_from_slice(&encode_integer(i));
                } else {
                    // Encode as bulk string
                    let s = n.to_string();
                    result.extend_from_slice(&encode_bulk_string(s.as_bytes()));
                }
            }
            serde_json::Value::Bool(b) => {
                let s = if *b { "1" } else { "0" };
                result.extend_from_slice(&encode_bulk_string(s.as_bytes()));
            }
            serde_json::Value::Null => {
                result.extend_from_slice(&encode_null());
            }
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                // Nested arrays/objects - encode as bulk string JSON
                let s = value.to_string();
                result.extend_from_slice(&encode_bulk_string(s.as_bytes()));
            }
        }
    }

    result
}

/// Action definition: Send Redis simple string response
pub fn redis_simple_string_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_simple_string".to_string(),
        description: "Send a simple string response (e.g., '+OK\\r\\n')".to_string(),
        parameters: vec![Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "The string value to send (without RESP encoding)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "redis_simple_string",
            "value": "OK"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis +{value}")
                .with_debug("Redis redis_simple_string: value={value}"),
        ),
    }
}

/// Action definition: Send Redis bulk string response
pub fn redis_bulk_string_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_bulk_string".to_string(),
        description: "Send a bulk string response (e.g., '$5\\r\\nhello\\r\\n'). Use null for nil bulk string".to_string(),
        parameters: vec![Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "The string value to send, or null for nil bulk string".to_string(),
            required: false,
        }],
        example: json!({
            "type": "redis_bulk_string",
            "value": "hello world"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis ${value_len}B")
                .with_debug("Redis redis_bulk_string: {value_len} bytes"),
        ),
    }
}

/// Action definition: Send Redis array response
pub fn redis_array_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_array".to_string(),
        description: "Send an array response, for commands that return a list (KEYS, MGET, LRANGE, SCAN...)".to_string(),
        parameters: vec![Parameter {
            name: "values".to_string(),
            type_hint: "array".to_string(),
            description: "Array of values. A string becomes a bulk string, an integer becomes a RESP integer, true/false become the bulk strings \"1\"/\"0\", null becomes a nil element, and a nested array or object is sent as its JSON text in a bulk string".to_string(),
            required: true,
        }],
        example: json!({
            "type": "redis_array",
            "values": ["value1", "value2", "value3"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis *{values_len} elements")
                .with_debug("Redis redis_array: {values_len} elements"),
        ),
    }
}

/// Action definition: Send Redis integer response
pub fn redis_integer_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_integer".to_string(),
        description: "Send an integer response (e.g., ':42\\r\\n')".to_string(),
        parameters: vec![Parameter {
            name: "value".to_string(),
            type_hint: "integer".to_string(),
            description: "The integer value to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "redis_integer",
            "value": 42
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis :{value}")
                .with_debug("Redis redis_integer: value={value}"),
        ),
    }
}

/// Action definition: Send Redis error response
pub fn redis_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_error".to_string(),
        description: "Send an error response (e.g., '-ERR message\\r\\n')".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The error message to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "redis_error",
            "message": "ERR unknown command 'foobar'"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis -{message}")
                .with_debug("Redis redis_error: {message}"),
        ),
    }
}

/// Action definition: Send Redis null response
pub fn redis_null_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_null".to_string(),
        description: "Send a null response ('$-1\\r\\n')".to_string(),
        parameters: vec![],
        example: json!({
            "type": "redis_null"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis (nil)")
                .with_debug("Redis redis_null"),
        ),
    }
}

/// Action definition: Close current Redis connection
pub fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current Redis connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Redis connection closed")
                .with_debug("Redis close_this_connection"),
        ),
    }
}

/// `ActionResult::Custom` name of `redis_accept_subscription`.
pub const ACCEPT_SUBSCRIPTION: &str = "redis_accept_subscription";
/// `ActionResult::Custom` name of `redis_deliver_message`.
pub const DELIVER_MESSAGE: &str = "redis_deliver_message";

/// Carry out `redis_publish_message` or `redis_cluster_set_slot` against a running server.
fn execute_on_shared(
    shared: &super::RedisShared,
    action: &serde_json::Value,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<ActionResult> {
    match action.get("type").and_then(|v| v.as_str()) {
        Some("redis_publish_message") => {
            let channel = action
                .get("channel")
                .and_then(|v| v.as_str())
                .context("Missing 'channel'")?;
            let message = action
                .get("message")
                .and_then(|v| v.as_str())
                .context("Missing 'message'")?;
            let shard = action
                .get("shard")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let kind = if shard {
                super::pubsub::Kind::Shard
            } else {
                super::pubsub::Kind::Channel
            };
            super::pubsub::check_name(kind, channel.as_bytes()).map_err(anyhow::Error::msg)?;
            super::pubsub::check_message(message.as_bytes()).map_err(anyhow::Error::msg)?;
            let receivers = shared
                .hub
                .publish(channel.as_bytes(), message.as_bytes(), shard);
            debug!(
                "Redis decision=model_publish channel='{}' receivers={}",
                crate::utils::truncate_for_log(channel, 128),
                receivers
            );
            let _ = status_tx.send(format!(
                "[INFO] Redis published to '{}': {} receiver(s)",
                crate::utils::truncate_for_log(channel, 128),
                receivers
            ));
            Ok(ActionResult::NoAction)
        }
        Some("redis_cluster_set_slot") => {
            let cluster = shared.cluster.as_ref().context(
                "this server is not in cluster mode (start it with the cluster_nodes parameter)",
            )?;
            let slots =
                super::cluster::parse_slots(action.get("slots").context("Missing 'slots'")?)?;
            let state = action
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("node");
            let node = action.get("node").and_then(|v| v.as_str());
            let summary = cluster
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .set_slot(slots, state, node)?;
            let _ = status_tx.send(format!("[INFO] Redis cluster: {summary}"));
            debug!("Redis cluster slot change: {}", summary);
            Ok(ActionResult::NoAction)
        }
        other => Err(anyhow::anyhow!("not a server-state action: {other:?}")),
    }
}

/// Action definition: allow a SUBSCRIBE / PSUBSCRIBE / SSUBSCRIBE.
pub fn redis_accept_subscription_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_accept_subscription".to_string(),
        description: "Allow the subscription a redis_subscribe event asks for. The server then \
                      registers it and sends the client one confirmation per channel; to refuse \
                      instead, answer with redis_error (e.g. NOPERM ...)."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "redis_accept_subscription"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis subscription accepted")
                .with_debug("Redis redis_accept_subscription"),
        ),
    }
}

/// Action definition: deliver the PUBLISH a redis_publish event is about.
pub fn redis_deliver_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_deliver_message".to_string(),
        description: "Deliver the message a redis_publish event is about to every subscriber of \
                      its channel (and of every matching pattern), and answer the publisher with \
                      the number of deliveries. To answer without delivering, send redis_integer \
                      instead; to refuse, redis_error."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "redis_deliver_message"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis message delivered")
                .with_debug("Redis redis_deliver_message"),
        ),
    }
}

/// Action definition: publish a message of the model's own.
pub fn redis_publish_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_publish_message".to_string(),
        description: "Publish a message of your own to every client of this server subscribed \
                      to the channel (or to a matching pattern), as if a client had sent PUBLISH. \
                      Writes nothing to the client whose command you are answering, so still \
                      answer it."
            .to_string(),
        parameters: vec![
            param("channel", "string", "The channel to publish on", true),
            param("message", "string", "The message text", true),
            param(
                "shard",
                "boolean",
                "true to publish on the shard channel (SPUBLISH) rather than the ordinary one",
                false,
            ),
        ],
        example: json!({"type": "redis_publish_message", "channel": "news", "message": "hello"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis PUBLISH {channel}")
                .with_debug("Redis redis_publish_message: channel={channel}"),
        ),
    }
}

/// Action definition: change which node serves cluster slots.
pub fn redis_cluster_set_slot_action() -> ActionDefinition {
    ActionDefinition {
        name: "redis_cluster_set_slot".to_string(),
        description: "Change this server's view of the cluster, as CLUSTER SETSLOT does (cluster \
                      mode only). state node: the slots now belong to node, so this server \
                      redirects them there with -MOVED; migrating: this server's slots are moving \
                      to node and it answers -ASK; importing: the slots are arriving from node and \
                      are served after ASKING; stable: clear migrating/importing."
            .to_string(),
        parameters: vec![
            param(
                "slots",
                "string",
                "A slot (\"42\") or an inclusive range (\"0-100\")",
                true,
            ),
            param(
                "state",
                "string",
                "node (default), migrating, importing or stable",
                false,
            ),
            param(
                "node",
                "string",
                "The other node, as host:port or its 40-character id (not needed for stable)",
                false,
            ),
        ],
        example: json!({"type": "redis_cluster_set_slot", "slots": "0-100", "state": "stable"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Redis cluster slots {slots} {state}")
                .with_debug("Redis redis_cluster_set_slot: slots={slots} state={state}"),
        ),
    }
}

// ============================================================================
// Redis Action Constants
// ============================================================================

pub static REDIS_SIMPLE_STRING_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| redis_simple_string_action());
pub static REDIS_BULK_STRING_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| redis_bulk_string_action());
pub static REDIS_ARRAY_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| redis_array_action());
pub static REDIS_INTEGER_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| redis_integer_action());
pub static REDIS_ERROR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| redis_error_action());
pub static REDIS_NULL_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| redis_null_action());
pub static REDIS_CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| close_this_connection_action());

// ============================================================================
// Redis Event Type Constants
// ============================================================================

/// Redis command event - triggered when client sends a command
pub static REDIS_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_command",
        "Redis command received from client",
        json!({"type": "placeholder", "event_id": "redis_command"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The Redis command string sent by the client".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol".to_string(),
            type_hint: "number".to_string(),
            description: "The RESP version this connection speaks: 2, or 3 after the client sent HELLO 3. RESP3-only replies (map, set, double, boolean, big number, verbatim) are downgraded on RESP2; a push needs RESP3".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        REDIS_SIMPLE_STRING_ACTION.clone(),
        REDIS_BULK_STRING_ACTION.clone(),
        REDIS_ARRAY_ACTION.clone(),
        REDIS_INTEGER_ACTION.clone(),
        REDIS_ERROR_ACTION.clone(),
        REDIS_NULL_ACTION.clone(),
        REDIS_CLOSE_CONNECTION_ACTION.clone(),
        redis_publish_message_action(),
        redis_cluster_set_slot_action(),
    ]
    .into_iter()
    .chain(resp3_actions())
    .collect())
    .with_log_template(
        LogTemplate::new()
            .with_info("Redis: {command}")
            .with_debug("Redis command: {command}")
            .with_trace("Redis: {json_pretty(.)}"),
    )
});

/// A client asked to subscribe. Raised for SUBSCRIBE, PSUBSCRIBE and SSUBSCRIBE once the
/// request is known to fit every bound, so the model decides policy and nothing else.
pub static REDIS_SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_subscribe",
        "A client asked to subscribe to channels or patterns",
        json!({"type": "redis_accept_subscription"}),
    )
    .with_parameters(vec![
        param(
            "command",
            "string",
            "SUBSCRIBE (channels), PSUBSCRIBE (glob patterns) or SSUBSCRIBE (shard channels)",
            true,
        ),
        param(
            "channels",
            "array",
            "The channels or patterns requested, in order",
            true,
        ),
        param(
            "subscriptions",
            "number",
            "How many subscriptions this connection already holds",
            true,
        ),
        param(
            "protocol",
            "number",
            "The connection's RESP version: messages arrive as pushes on 3, arrays on 2",
            true,
        ),
    ])
    .with_actions(vec![
        redis_accept_subscription_action(),
        REDIS_ERROR_ACTION.clone(),
        redis_publish_message_action(),
        REDIS_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Redis: {command} {channels}")
            .with_debug("Redis subscribe: {command} {channels}"),
    )
});

/// A client published. Raised for PUBLISH and SPUBLISH once the message fits its bound.
pub static REDIS_PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_publish",
        "A client published a message to a channel",
        json!({"type": "redis_deliver_message"}),
    )
    .with_parameters(vec![
        param(
            "command",
            "string",
            "PUBLISH, or SPUBLISH for a shard channel",
            true,
        ),
        param("channel", "string", "The channel the message is for", true),
        param("message", "string", "The message text", true),
        param(
            "receivers",
            "number",
            "How many deliveries redis_deliver_message would make right now",
            true,
        ),
        param(
            "protocol",
            "number",
            "The publisher's RESP version (2 or 3)",
            true,
        ),
    ])
    .with_actions(vec![
        redis_deliver_message_action(),
        REDIS_INTEGER_ACTION.clone(),
        REDIS_ERROR_ACTION.clone(),
        redis_publish_message_action(),
        REDIS_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Redis: {command} {channel}")
            .with_debug("Redis publish: {command} {channel} ({receivers} receivers)"),
    )
});

/// Get Redis event types
pub fn get_redis_event_types() -> Vec<EventType> {
    vec![
        REDIS_COMMAND_EVENT.clone(),
        REDIS_SUBSCRIBE_EVENT.clone(),
        REDIS_PUBLISH_EVENT.clone(),
    ]
}

fn resp3_action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: serde_json::Value,
    info: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new()
                .with_info(info)
                .with_debug(format!("Redis {name}")),
        ),
    }
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

/// The RESP3 reply verbs. Each is encoded for the connection's protocol: native on a
/// connection that sent `HELLO 3`, downgraded the way Redis downgrades on RESP2.
pub fn resp3_actions() -> Vec<ActionDefinition> {
    vec![
        resp3_action(
            "redis_map",
            "Send a map (HGETALL, CONFIG GET, XINFO…): a RESP3 map, or on RESP2 the flat key/value array Redis sends there",
            vec![param("entries", "object", "The map as a JSON object, or [[key, value], …] when order matters. Values follow redis_array's rules (on RESP3 a nested object is a map, an array an array, a fraction a double, true/false booleans, null a null)", true)],
            json!({"type": "redis_map", "entries": {"name": "Ada", "visits": 3}}),
            "-> Redis map",
        ),
        resp3_action(
            "redis_set",
            "Send a set (SMEMBERS, SINTER…): a RESP3 set, or an array on RESP2",
            vec![param("values", "array", "The members, encoded as redis_array encodes its elements", true)],
            json!({"type": "redis_set", "values": ["red", "green"]}),
            "-> Redis set {values_len} members",
        ),
        resp3_action(
            "redis_double",
            "Send a floating-point number (ZSCORE, INCRBYFLOAT…): a RESP3 double, or a bulk string on RESP2",
            vec![param("value", "number", "The number, or the string inf, -inf or nan", true)],
            json!({"type": "redis_double", "value": 2.5}),
            "-> Redis double {value}",
        ),
        resp3_action(
            "redis_boolean",
            "Send true or false: a RESP3 boolean, or the integer 1/0 on RESP2",
            vec![param("value", "boolean", "The boolean to send: true or false (1 or 0 on RESP2)", true)],
            json!({"type": "redis_boolean", "value": true}),
            "-> Redis boolean {value}",
        ),
        resp3_action(
            "redis_big_number",
            "Send an integer too large for 64 bits: a RESP3 big number, or a bulk string on RESP2",
            vec![param("value", "string", "The decimal digits, optionally with a leading minus sign", true)],
            json!({"type": "redis_big_number", "value": "3492890328409238509324850943850943825024385"}),
            "-> Redis big number",
        ),
        resp3_action(
            "redis_verbatim_string",
            "Send text a client should show as is (INFO, LATENCY DOCTOR): a RESP3 verbatim string, or a bulk string on RESP2",
            vec![
                param("text", "string", "The text, newlines allowed", true),
                param("format", "string", "Three letters naming the text's format: txt (default) or mkd", false),
            ],
            json!({"type": "redis_verbatim_string", "text": "# Server\nredis_version:7.4.0", "format": "txt"}),
            "-> Redis verbatim string",
        ),
        resp3_action(
            "redis_push",
            "Send an out-of-band push (pub/sub message, client-side-caching invalidation). RESP3 only: refused on a RESP2 connection",
            vec![param("values", "array", "The push's elements, the first naming its kind, e.g. [\"message\", \"news\", \"hello\"]", true)],
            json!({"type": "redis_push", "values": ["message", "news", "hello"]}),
            "-> Redis push {values_len} elements",
        ),
    ]
}
