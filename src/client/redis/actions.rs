//! Redis client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Redis client connected event
pub static REDIS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_connected",
        "Redis client successfully connected to server",
        json!({
            "type": "execute_redis_command",
            "command": "GET mykey"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Redis server address".to_string(),
            required: true,
        },
        Parameter {
            name: "cluster_nodes".to_string(),
            type_hint: "array".to_string(),
            description: "Cluster mode only: every master (host:port) in the slot map read at \
                          connect"
                .to_string(),
            required: false,
        },
    ])
});

/// Redis client response received event
pub static REDIS_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_response_received",
        "Response received from Redis server",
        json!({
            "type": "execute_redis_command",
            "command": "SET result OK"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "One complete reply rendered as redis-cli prints it: OK, (integer) 3, \
                          \"value\", (nil), (error) ERR ...; arrays and maps as JSON"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "reply_type".to_string(),
            type_hint: "string".to_string(),
            description: "simple_string, error, integer, bulk_string, null, array, map, set, \
                          push, boolean, double, big_number or verbatim_string"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "value".to_string(),
            type_hint: "any".to_string(),
            description: "The reply as JSON: a string, an integer, null, an array, an object \
                          for a map, or {\"error\": \"...\"} for an error"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "node".to_string(),
            type_hint: "string".to_string(),
            description: "Cluster mode only: the node (host:port) that gave this answer"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "slot".to_string(),
            type_hint: "number".to_string(),
            description: "Cluster mode only: the hash slot the command's keys hash to".to_string(),
            required: false,
        },
        Parameter {
            name: "redirects".to_string(),
            type_hint: "array".to_string(),
            description: "Cluster mode only: each MOVED/ASK redirection the client followed \
                          for this command"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "redirects_exhausted".to_string(),
            type_hint: "boolean".to_string(),
            description: "Cluster mode only: true when the command was still being redirected \
                          after the redirection limit, so the reply is the last redirection error"
                .to_string(),
            required: false,
        },
    ])
});

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

/// A message delivered on a channel this client subscribed to.
pub static REDIS_CLIENT_MESSAGE_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
            "redis_message_received",
            "A pub/sub message arrived on a channel or pattern this client subscribed to",
            json!({
                "type": "redis_publish",
                "channel": "replies",
                "message": "got it"
            }),
        )
        .with_parameters(vec![
        param(
            "kind",
            "string",
            "message (a SUBSCRIBE channel), pmessage (matched a PSUBSCRIBE pattern) or smessage \
             (a shard channel)",
            true,
        ),
        param("channel", "string", "The channel the message was published on", true),
        param(
            "pattern",
            "string",
            "For a pmessage, the pattern that matched; absent otherwise",
            false,
        ),
        param("message", "string", "The message text", true),
        param(
            "subscriptions",
            "object",
            "What this connection is subscribed to: channels, patterns, shard_channels",
            true,
        ),
        param(
            "protocol",
            "number",
            "The connection's RESP version: 3 if the message came as a push",
            true,
        ),
    ])
    });

/// A subscribe or unsubscribe the server confirmed.
pub static REDIS_CLIENT_SUBSCRIPTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redis_subscription_changed",
        "The server confirmed a subscribe or unsubscribe",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        param(
            "kind",
            "string",
            "subscribe, psubscribe, ssubscribe, unsubscribe, punsubscribe or sunsubscribe",
            true,
        ),
        param(
            "channel",
            "string",
            "The channel or pattern confirmed; null when an unsubscribe found nothing to drop",
            false,
        ),
        param(
            "count",
            "number",
            "Subscriptions the server says this connection now holds (shard channels are \
             counted apart from channels and patterns)",
            true,
        ),
        param(
            "subscriptions",
            "object",
            "What this connection is subscribed to: channels, patterns, shard_channels",
            true,
        ),
    ])
});

/// Redis client protocol action handler
pub struct RedisClientProtocol;

impl RedisClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn names_param(name: &str, what: &str) -> Parameter {
    param(name, "array", what, false)
}

/// `redis_subscribe`, `redis_unsubscribe` and `redis_publish`: pub/sub as structured actions,
/// so a channel name with a space needs no quoting and the client knows what it is doing.
fn pubsub_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "redis_subscribe".to_string(),
            description: "Subscribe to channels (SUBSCRIBE), glob patterns (PSUBSCRIBE) or shard \
                          channels (SSUBSCRIBE). Each confirmation arrives as \
                          redis_subscription_changed and each message as redis_message_received. \
                          Not available in cluster mode."
                .to_string(),
            parameters: vec![
                names_param("channels", "Channel names to subscribe to"),
                names_param("patterns", "Glob patterns to subscribe to, e.g. news.*"),
                names_param("shard_channels", "Shard channel names to subscribe to"),
            ],
            example: json!({"type": "redis_subscribe", "channels": ["news"], "patterns": ["alerts.*"]}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("Redis client SUBSCRIBE {channels} {patterns}")
                    .with_debug("Redis client redis_subscribe"),
            ),
        },
        ActionDefinition {
            name: "redis_unsubscribe".to_string(),
            description:
                "Unsubscribe. Name channels, patterns or shard_channels to drop those; an \
                          empty list drops every subscription of that kind; no field at all drops \
                          everything this connection holds."
                    .to_string(),
            parameters: vec![
                names_param("channels", "Channels to unsubscribe from ([] for all)"),
                names_param("patterns", "Patterns to unsubscribe from ([] for all)"),
                names_param(
                    "shard_channels",
                    "Shard channels to unsubscribe from ([] for all)",
                ),
            ],
            example: json!({"type": "redis_unsubscribe", "channels": ["news"]}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("Redis client UNSUBSCRIBE")
                    .with_debug("Redis client redis_unsubscribe"),
            ),
        },
        ActionDefinition {
            name: "redis_publish".to_string(),
            description: "Publish a message to a channel (PUBLISH, or SPUBLISH with shard). While \
                          this connection is subscribed on RESP2 it cannot publish itself, so the \
                          client publishes over a short second connection to the same server."
                .to_string(),
            parameters: vec![
                param("channel", "string", "The channel to publish on", true),
                param("message", "string", "The message text", true),
                param(
                    "shard",
                    "boolean",
                    "true to publish on a shard channel (SPUBLISH)",
                    false,
                ),
            ],
            example: json!({"type": "redis_publish", "channel": "news", "message": "hello"}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("Redis client PUBLISH {channel}")
                    .with_debug("Redis client redis_publish: {channel}"),
            ),
        },
    ]
}

// Implement Protocol trait (common functionality)
impl Protocol for RedisClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "cluster".to_string(),
                type_hint: "boolean".to_string(),
                description: "Treat remote_addr as one node of a Redis Cluster: read the slot map \
                              with CLUSTER SLOTS, send each command to the node that owns its \
                              keys' hash slot, and follow MOVED (refreshing the map) and ASK \
                              redirections, at most a fixed number per command. Commands run one \
                              at a time; pub/sub subscriptions are not available in this mode."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "resp3".to_string(),
                type_hint: "boolean".to_string(),
                description: "Send HELLO 3 on connect and speak RESP3, so pub/sub messages arrive \
                              as pushes and the connection can still run ordinary commands while \
                              subscribed. Connecting fails if the server refuses RESP3. Not \
                              available together with cluster."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        let mut actions = pubsub_actions();
        actions.extend(vec![
            ActionDefinition {
                name: "execute_redis_command".to_string(),
                description: "Execute a Redis command".to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description: "Redis command as typed at redis-cli (e.g. GET key, \
                                  SET greeting \"hello world\"). Quote an argument that contains \
                                  spaces with double or single quotes."
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_redis_command",
                    "command": "GET mykey"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the Redis server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]);
        actions
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = pubsub_actions();
        actions.extend(vec![
            ActionDefinition {
                name: "execute_redis_command".to_string(),
                description: "Execute a Redis command in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description: "Redis command".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_redis_command",
                    "command": "SET result OK"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description:
                    "Take no action and wait for more data from the server. Use when the reply so \
                 far is incomplete."
                        .to_string(),
                parameters: vec![],
                example: json!({ "type": "wait_for_more" }),
                log_template: None,
            },
        ]);
        actions
    }
    fn protocol_name(&self) -> &'static str {
        "Redis"
    }
    /// The **statics**, not fresh `EventType::new(..)` copies.
    ///
    /// This used to build a second, different `EventType` for each id: no parameters, and a
    /// `{"type": "placeholder"}` example. Those are what the registry and the model-facing
    /// docs surface, while the emitted events carry the statics above — two sources of truth
    /// for the same event id, and they had already drifted.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            REDIS_CLIENT_CONNECTED_EVENT.clone(),
            REDIS_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
            REDIS_CLIENT_MESSAGE_EVENT.clone(),
            REDIS_CLIENT_SUBSCRIPTION_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Redis"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["redis", "redis client", "connect to redis"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation(
                "Hand-written RESP on tokio (src/client/redis/resp.rs): commands split the way \
                 redis-cli splits them and sent as RESP arrays; one complete RESP2/RESP3 reply \
                 per event, bounded in depth, declared size and element count",
            )
            .llm_control("Full control over Redis commands")
            .e2e_testing(
                "Pub/sub (pubsub_real_server_test.rs, RESP2 and RESP3): a message redis-cli \
                 publishes to a real redis-server reaches the model as redis_message_received \
                 (pattern messages with their pattern), and the model's answer, a publish of \
                 its own, is printed by a redis-cli SUBSCRIBE; the model's unsubscribe empties \
                 the server's PUBSUB NUMSUB/NUMPAT. Cluster (cluster_real_server_test.rs): a \
                 real three-node Redis Cluster from redis-cli --cluster create; after a \
                 CLUSTER SETSLOT reshard the client follows MOVED to the new owner, and through \
                 a migrating slot it follows ASK with ASKING, each read back with redis-cli. \
                 tests/client/redis/real_server_test.rs, 9 LLM calls, against a real \
                 redis-server (Valkey locally, Redis on Ubuntu) read back with redis-cli. The \
                 model SETs a quoted value containing a space, GETs it, and RPUSHes a line built \
                 from the reply it was shown; a hash written by redis-cli reaches the model as \
                 one four-element array event. Every reply is matched on its parsed reply_type \
                 and value, so a reply split across events fails. Not #[ignore]d, and a missing \
                 redis-server or redis-cli fails the test rather than skipping it. \
                 resp_reader_test.rs pins the framing and each bound byte by byte.",
            )
            .notes(
                "Pub/sub: redis_subscribe/redis_unsubscribe/redis_publish, each delivered message \
                 a redis_message_received event (channel, pattern, message) on RESP2 and RESP3 \
                 (resp3 parameter); a subscribed RESP2 connection publishes over a short second \
                 connection. Cluster mode (cluster parameter): slot map from CLUSTER SLOTS, \
                 commands routed by hash slot, MOVED (with a map refresh) and ASK (with ASKING) \
                 followed, at most 5 redirections per command; commands run one at a time and \
                 pub/sub subscriptions are refused there. No AUTH or SELECT startup parameters: \
                 both are reachable only as explicit commands. Non-UTF-8 bulk strings reach the \
                 model through a lossy conversion. No connect timeout.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Redis client for key-value operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Redis at localhost:6379 and get the value of 'user:123'"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls Redis commands
            json!({
                "type": "open_client",
                "remote_addr": "localhost:6379",
                "base_stack": "redis",
                "instruction": "Get the value of 'user:123' and report its contents"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:6379",
                "base_stack": "redis",
                "event_handlers": [{
                    "event_pattern": "redis_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<redis_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed Redis command on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:6379",
                "base_stack": "redis",
                "event_handlers": [
                    {
                        "event_pattern": "redis_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "execute_redis_command",
                                "command": "GET status"
                            }]
                        }
                    },
                    {
                        "event_pattern": "redis_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for RedisClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::redis::RedisClient;
            let flag = |name: &str| -> anyhow::Result<bool> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_bool(name))
                    .transpose()?
                    .flatten()
                    .unwrap_or(false))
            };
            let options = crate::client::redis::RedisClientOptions {
                cluster: flag("cluster")?,
                resp3: flag("resp3")?,
            };
            RedisClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                options,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "execute_redis_command" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' field")?
                    .to_string();
                // Refused here, before anything reaches the wire: an unbalanced quote has no
                // honest reading, and guessing one would send a command the model did not write.
                crate::client::redis::resp::split_command(&command)?;

                Ok(ClientActionResult::Custom {
                    name: "redis_command".to_string(),
                    data: json!({
                        "command": command,
                    }),
                })
            }
            "redis_subscribe" => {
                let mut commands = Vec::new();
                for (field, verb) in [
                    ("channels", "SUBSCRIBE"),
                    ("patterns", "PSUBSCRIBE"),
                    ("shard_channels", "SSUBSCRIBE"),
                ] {
                    let names = string_list(&action, field)?;
                    if !names.is_empty() {
                        commands.push(command_with(verb, &names));
                    }
                }
                anyhow::ensure!(
                    !commands.is_empty(),
                    "redis_subscribe names no channels, patterns or shard_channels"
                );
                Ok(ClientActionResult::Custom {
                    name: "redis_commands".to_string(),
                    data: json!({ "commands": commands }),
                })
            }
            "redis_unsubscribe" => {
                let mut commands = Vec::new();
                for (field, verb) in [
                    ("channels", "UNSUBSCRIBE"),
                    ("patterns", "PUNSUBSCRIBE"),
                    ("shard_channels", "SUNSUBSCRIBE"),
                ] {
                    if action.get(field).is_some() {
                        commands.push(command_with(verb, &string_list(&action, field)?));
                    }
                }
                if commands.is_empty() {
                    return Ok(ClientActionResult::Custom {
                        name: "redis_unsubscribe_all".to_string(),
                        data: json!({}),
                    });
                }
                Ok(ClientActionResult::Custom {
                    name: "redis_commands".to_string(),
                    data: json!({ "commands": commands }),
                })
            }
            "redis_publish" => {
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
                let verb = if shard { "SPUBLISH" } else { "PUBLISH" };
                Ok(ClientActionResult::Custom {
                    name: "redis_publish".to_string(),
                    data: json!({ "args": [verb, channel, message] }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // CLAUDE.md lists wait_for_more as one of the three standard client
            // sync actions, and ftp/imap/doh/rip/tcp/dns all implement it. These two
            // did not, so returning it was an "unknown action" error the client then
            // swallowed -- two suites passed while sending an action the client
            // could never obey.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown Redis client action: {}",
                action_type
            )),
        }
    }
}

/// A JSON array of strings from an action field (absent is empty).
fn string_list(action: &serde_json::Value, field: &str) -> Result<Vec<String>> {
    match action.get(field) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .with_context(|| format!("'{field}' holds a non-string"))
            })
            .collect(),
        Some(_) => Err(anyhow::anyhow!("'{field}' is an array of strings")),
    }
}

fn command_with(verb: &str, names: &[String]) -> Vec<String> {
    std::iter::once(verb.to_string())
        .chain(names.iter().cloned())
        .collect()
}
