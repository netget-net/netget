//! Memcached client actions, events and metadata.
//!
//! NetGet dials a memcached server and speaks the text protocol. The model decides which
//! requests to send (`memcached_get`, `memcached_set`, …) and is shown every reply as a
//! structured event: one `memcached_value` or `memcached_miss` per requested key, one status
//! event per storage/delete/counter/touch reply, `memcached_stats` as a JSON object.
//!
//! Values travel as **text**. A value the model stores is its UTF-8 bytes; a value the server
//! returns that is not valid UTF-8 is refused with `memcached_error {kind: "non_text_value"}`
//! naming the key and its length, rather than re-encoded into something the model would then
//! write back as different bytes.

use crate::client::memcached::wire::{
    validate_key, validate_stats_group, Request, StoreVerb, MAX_GET_KEYS,
};
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::memcached::protocol::MAX_VALUE_LEN;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every wire request travels as.
pub const REQUEST_RESULT: &str = "memcached_request";

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn key_param(desc: &str) -> Parameter {
    param("key", "string", desc, true)
}

fn command_param() -> Parameter {
    param(
        "command",
        "string",
        "The request this answers: set, add, replace, append, prepend, cas, delete, incr, \
         decr or touch",
        true,
    )
}

pub static MEMCACHED_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_connected",
        "Connected to a memcached server over TCP",
        json!({"type": "memcached_get", "keys": ["greeting"]}),
    )
    .with_parameters(vec![param(
        "remote_addr",
        "string",
        "The server this client is connected to",
        true,
    )])
});

pub static MEMCACHED_VALUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_value",
        "A requested key was found: one event per hit of a get/gets",
        json!({"type": "memcached_set", "key": "seen", "value": "yes"}),
    )
    .with_parameters(vec![
        key_param("The key the request named"),
        param("value", "string", "The stored value, as text", true),
        param(
            "flags",
            "number",
            "The 32-bit flags stored with the item",
            true,
        ),
        param(
            "cas",
            "number",
            "The CAS unique (gets only); pass it to memcached_cas to update the item only if \
             nobody else has",
            false,
        ),
    ])
});

pub static MEMCACHED_MISS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_miss",
        "A requested key is not on the server: one event per miss of a get/gets",
        json!({"type": "memcached_add", "key": "greeting", "value": "hello"}),
    )
    .with_parameters(vec![key_param("The key that was not found")])
});

pub static MEMCACHED_STORED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_stored",
        "The server stored the value (STORED)",
        json!({"type": "memcached_get", "keys": ["greeting"]}),
    )
    .with_parameters(vec![command_param(), key_param("The key that was stored")])
});

pub static MEMCACHED_NOT_STORED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_not_stored",
        "The server did not store the value because the add/replace/append/prepend \
         condition did not hold (NOT_STORED)",
        json!({"type": "memcached_set", "key": "greeting", "value": "hello"}),
    )
    .with_parameters(vec![
        command_param(),
        key_param("The key the request named"),
    ])
});

pub static MEMCACHED_EXISTS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_exists",
        "A cas was refused because the item changed since its CAS unique was read (EXISTS)",
        json!({"type": "memcached_gets", "keys": ["counter"]}),
    )
    .with_parameters(vec![
        command_param(),
        key_param("The key the request named"),
    ])
});

pub static MEMCACHED_NOT_FOUND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_not_found",
        "The key the request named does not exist (NOT_FOUND)",
        json!({"type": "memcached_set", "key": "counter", "value": "0"}),
    )
    .with_parameters(vec![
        command_param(),
        key_param("The key the request named"),
    ])
});

pub static MEMCACHED_DELETED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_deleted",
        "The key was deleted (DELETED)",
        json!({"type": "memcached_get", "keys": ["greeting"]}),
    )
    .with_parameters(vec![key_param("The key that was deleted")])
});

pub static MEMCACHED_TOUCHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_touched",
        "The key's expiration time was updated (TOUCHED)",
        json!({"type": "memcached_get", "keys": ["session"]}),
    )
    .with_parameters(vec![key_param("The key that was touched")])
});

pub static MEMCACHED_COUNTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_counter",
        "The new value of a counter after incr/decr",
        json!({"type": "memcached_incr", "key": "hits", "delta": 1}),
    )
    .with_parameters(vec![
        param(
            "command",
            "string",
            "The request answered: incr or decr",
            true,
        ),
        key_param("The counter's key"),
        param(
            "value",
            "number",
            "The counter's value after the change",
            true,
        ),
    ])
});

pub static MEMCACHED_STATS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_stats",
        "The server's statistics, as one object of name to value",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![
        param(
            "stats",
            "object",
            "Every STAT line, name to value (values are strings, as the server wrote them)",
            true,
        ),
        param(
            "group",
            "string",
            "The stats group asked for, if any",
            false,
        ),
    ])
});

pub static MEMCACHED_VERSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_version",
        "The server's version string",
        json!({"type": "memcached_stats"}),
    )
    .with_parameters(vec![param(
        "version",
        "string",
        "The version, e.g. 1.6.45",
        true,
    )])
});

pub static MEMCACHED_OK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_ok",
        "The server acknowledged a flush_all (OK)",
        json!({"type": "memcached_get", "keys": ["greeting"]}),
    )
    .with_parameters(vec![param(
        "command",
        "string",
        "The request acknowledged: flush_all",
        true,
    )])
});

pub static MEMCACHED_ERROR_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "memcached_error",
        "A request failed: the server answered ERROR, CLIENT_ERROR or SERVER_ERROR, or a value \
         it returned is not text",
        json!({"type": "memcached_version"}),
    )
    .with_parameters(vec![
        param(
            "kind",
            "string",
            "error (unknown command), client_error (the request was malformed), server_error \
             (the server could not do it, e.g. out of memory), or non_text_value (a stored \
             value is not UTF-8 and this client carries text only)",
            true,
        ),
        param("message", "string", "What the server or the client said", true),
        param("command", "string", "The request this answers", false),
        param("key", "string", "The key involved, where there is one", false),
    ])
    });

/// Memcached client protocol.
pub struct MemcachedClientProtocol;

impl MemcachedClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MemcachedClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn store_action(verb: &str, description: &str, cas: bool) -> ActionDefinition {
    let mut parameters = vec![
        key_param("Key, at most 250 bytes, no spaces or control characters"),
        param(
            "value",
            "string",
            "The value, as text. Any characters, including spaces and newlines",
            true,
        ),
        param(
            "flags",
            "number",
            "32-bit opaque flags stored with the item (default 0)",
            false,
        ),
        param(
            "exptime",
            "number",
            "Expiration: 0 = never (default), seconds from now up to 30 days, or a Unix \
             timestamp",
            false,
        ),
    ];
    let mut example = json!({
        "type": format!("memcached_{verb}"),
        "key": "greeting",
        "value": "hello world",
    });
    if cas {
        parameters.push(param(
            "cas_unique",
            "number",
            "The CAS unique a memcached_gets returned for this key",
            true,
        ));
        example["cas_unique"] = json!(12);
    }
    let cas_part = if cas { " cas={cas_unique}" } else { "" };
    ActionDefinition {
        name: format!("memcached_{verb}"),
        description: description.to_string(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("-> memcached {verb} {{key}}{cas_part}"))
                .with_debug(format!(
                    "memcached {verb}: key={{key}} flags={{flags}} exptime={{exptime}}{cas_part} \
                     value={{preview(value,80)}}"
                )),
        ),
    }
}

fn simple_action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let info = match name {
        "memcached_get" => "-> memcached get {json(keys)}",
        "memcached_gets" => "-> memcached gets {json(keys)}",
        "memcached_delete" => "-> memcached delete {key}",
        "memcached_incr" => "-> memcached incr {key} by {delta}",
        "memcached_decr" => "-> memcached decr {key} by {delta}",
        "memcached_touch" => "-> memcached touch {key} exptime={exptime}",
        "memcached_stats" => "-> memcached stats {group}",
        "memcached_version" => "-> memcached version",
        "memcached_flush_all" => "-> memcached flush_all confirm={confirm} delay={delay}",
        _ => "-> memcached disconnect",
    };
    ActionDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

fn all_actions() -> Vec<ActionDefinition> {
    let keys_param = param(
        "keys",
        "array",
        "The keys to read (1 to 32). Each hit arrives as its own memcached_value event, each \
         miss as memcached_miss",
        true,
    );
    vec![
        simple_action(
            "memcached_get",
            "Read one or more keys",
            vec![keys_param.clone()],
            json!({"type": "memcached_get", "keys": ["greeting", "counter"]}),
        ),
        simple_action(
            "memcached_gets",
            "Read keys together with their CAS unique, for a later memcached_cas",
            vec![keys_param],
            json!({"type": "memcached_gets", "keys": ["counter"]}),
        ),
        store_action("set", "Store a value unconditionally", false),
        store_action("add", "Store a value only if the key does not exist", false),
        store_action(
            "replace",
            "Store a value only if the key already exists",
            false,
        ),
        store_action("append", "Append text to an existing value", false),
        store_action("prepend", "Prepend text to an existing value", false),
        store_action(
            "cas",
            "Store a value only if the item has not changed since memcached_gets read it",
            true,
        ),
        simple_action(
            "memcached_delete",
            "Delete a key and its value from the server",
            vec![key_param("The key to delete")],
            json!({"type": "memcached_delete", "key": "greeting"}),
        ),
        simple_action(
            "memcached_incr",
            "Increment a numeric value",
            vec![
                key_param("The counter's key"),
                param("delta", "number", "Amount to add (unsigned 64-bit)", true),
            ],
            json!({"type": "memcached_incr", "key": "hits", "delta": 1}),
        ),
        simple_action(
            "memcached_decr",
            "Decrement a numeric value (memcached stops at 0)",
            vec![
                key_param("The counter's key"),
                param(
                    "delta",
                    "number",
                    "Amount to subtract (unsigned 64-bit)",
                    true,
                ),
            ],
            json!({"type": "memcached_decr", "key": "hits", "delta": 1}),
        ),
        simple_action(
            "memcached_touch",
            "Change a key's expiration time without reading it",
            vec![
                key_param("The key whose expiration time changes"),
                param(
                    "exptime",
                    "number",
                    "New expiration, as for memcached_set",
                    true,
                ),
            ],
            json!({"type": "memcached_touch", "key": "session", "exptime": 300}),
        ),
        simple_action(
            "memcached_stats",
            "Read the server's statistics",
            vec![param(
                "group",
                "string",
                "Optional group: settings, items, slabs, sizes or conns",
                false,
            )],
            json!({"type": "memcached_stats"}),
        ),
        simple_action(
            "memcached_version",
            "Ask the server for its version",
            vec![],
            json!({"type": "memcached_version"}),
        ),
        simple_action(
            "memcached_flush_all",
            "Invalidate EVERY item on the server. Refused unless confirm is true",
            vec![
                param(
                    "confirm",
                    "boolean",
                    "Must be true: this deletes everything the server holds, for every client",
                    true,
                ),
                param(
                    "delay",
                    "number",
                    "Seconds to wait before flushing (default: immediately)",
                    false,
                ),
            ],
            json!({"type": "memcached_flush_all", "confirm": true}),
        ),
        simple_action(
            "disconnect",
            "Close the connection to the memcached server",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn str_field<'a>(action: &'a Value, name: &str) -> Result<&'a str> {
    action
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field '{name}'"))
}

fn checked_key(action: &Value) -> Result<String> {
    let key = str_field(action, "key")?;
    validate_key(key).map_err(|e| anyhow!(e))?;
    Ok(key.to_string())
}

fn u64_field(action: &Value, name: &str) -> Result<Option<u64>> {
    match action.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .with_context(|| format!("'{name}' must be a non-negative integer, got {v}")),
    }
}

fn exptime_field(action: &Value, required: bool) -> Result<i64> {
    match action.get("exptime") {
        None | Some(Value::Null) if !required => Ok(0),
        None | Some(Value::Null) => Err(anyhow!("missing number field 'exptime'")),
        Some(v) => v
            .as_i64()
            .with_context(|| format!("'exptime' must be an integer, got {v}")),
    }
}

/// Parse and validate one model action into a wire request. `Ok(None)` is `disconnect`.
///
/// Every refusal happens here, before anything reaches the wire, so the model gets a reason
/// rather than a CLIENT_ERROR it has to interpret.
pub fn request_from_action(action: &Value) -> Result<Option<Request>> {
    let action_type = str_field(action, "type")?;
    let request = match action_type {
        "memcached_get" | "memcached_gets" => {
            let keys: Vec<String> = match action.get("keys") {
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|k| {
                        k.as_str()
                            .map(str::to_string)
                            .with_context(|| format!("every key must be a string, got {k}"))
                    })
                    .collect::<Result<_>>()?,
                Some(Value::String(one)) => vec![one.clone()],
                _ => return Err(anyhow!("missing 'keys' (an array of strings)")),
            };
            if keys.is_empty() || keys.len() > MAX_GET_KEYS {
                return Err(anyhow!(
                    "a get names 1 to {MAX_GET_KEYS} keys; {} given",
                    keys.len()
                ));
            }
            for (i, k) in keys.iter().enumerate() {
                validate_key(k).map_err(|e| anyhow!(e))?;
                if keys[..i].contains(k) {
                    return Err(anyhow!("key {k:?} is named twice"));
                }
            }
            Request::Get {
                keys,
                with_cas: action_type == "memcached_gets",
            }
        }
        "memcached_set" | "memcached_add" | "memcached_replace" | "memcached_append"
        | "memcached_prepend" | "memcached_cas" => {
            let verb = match action_type {
                "memcached_set" => StoreVerb::Set,
                "memcached_add" => StoreVerb::Add,
                "memcached_replace" => StoreVerb::Replace,
                "memcached_append" => StoreVerb::Append,
                "memcached_prepend" => StoreVerb::Prepend,
                _ => StoreVerb::Cas,
            };
            let key = checked_key(action)?;
            let value = str_field(action, "value")?.to_string();
            if value.len() > MAX_VALUE_LEN {
                return Err(anyhow!(
                    "value is {} bytes; memcached's default item limit is {MAX_VALUE_LEN}",
                    value.len()
                ));
            }
            let flags = match u64_field(action, "flags")? {
                None => 0,
                Some(f) => u32::try_from(f)
                    .map_err(|_| anyhow!("flags {f} does not fit memcached's 32-bit field"))?,
            };
            let exptime = exptime_field(action, false)?;
            let cas_unique = if verb == StoreVerb::Cas {
                Some(
                    u64_field(action, "cas_unique")?
                        .context("memcached_cas needs 'cas_unique' from a memcached_gets")?,
                )
            } else {
                None
            };
            Request::Store {
                verb,
                key,
                flags,
                exptime,
                value,
                cas_unique,
            }
        }
        "memcached_delete" => Request::Delete {
            key: checked_key(action)?,
        },
        "memcached_incr" | "memcached_decr" => {
            let key = checked_key(action)?;
            let delta = u64_field(action, "delta")?.context("missing number field 'delta'")?;
            if action_type == "memcached_incr" {
                Request::Incr { key, delta }
            } else {
                Request::Decr { key, delta }
            }
        }
        "memcached_touch" => Request::Touch {
            key: checked_key(action)?,
            exptime: exptime_field(action, true)?,
        },
        "memcached_stats" => {
            let group = match action.get("group") {
                None | Some(Value::Null) => None,
                Some(Value::String(g)) if g.is_empty() => None,
                Some(Value::String(g)) => {
                    validate_stats_group(g).map_err(|e| anyhow!(e))?;
                    Some(g.clone())
                }
                Some(other) => return Err(anyhow!("'group' must be a string, got {other}")),
            };
            Request::Stats { group }
        }
        "memcached_version" => Request::Version,
        "memcached_flush_all" => {
            if action.get("confirm").and_then(Value::as_bool) != Some(true) {
                return Err(anyhow!(
                    "memcached_flush_all invalidates every item on the server for every \
                     client; it is only sent with \"confirm\": true"
                ));
            }
            Request::FlushAll {
                delay: u64_field(action, "delay")?,
            }
        }
        "disconnect" => return Ok(None),
        other => return Err(anyhow!("Unknown Memcached client action: {other}")),
    };
    Ok(Some(request))
}

impl Protocol for MemcachedClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "Memcached"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            MEMCACHED_CONNECTED_EVENT.clone(),
            MEMCACHED_VALUE_EVENT.clone(),
            MEMCACHED_MISS_EVENT.clone(),
            MEMCACHED_STORED_EVENT.clone(),
            MEMCACHED_NOT_STORED_EVENT.clone(),
            MEMCACHED_EXISTS_EVENT.clone(),
            MEMCACHED_NOT_FOUND_EVENT.clone(),
            MEMCACHED_DELETED_EVENT.clone(),
            MEMCACHED_TOUCHED_EVENT.clone(),
            MEMCACHED_COUNTER_EVENT.clone(),
            MEMCACHED_STATS_EVENT.clone(),
            MEMCACHED_VERSION_EVENT.clone(),
            MEMCACHED_OK_EVENT.clone(),
            MEMCACHED_ERROR_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Memcached"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "memcached",
            "memcached client",
            "memcache",
            "connect to memcached",
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
                "Hand-written memcached text-protocol client on tokio \
                 (src/client/memcached/wire.rs). One transport task owns the socket and the \
                 FIFO pairing each reply with its request; the model is asked from a separate \
                 turn task, so a parked turn never stalls the socket. Requests are never sent \
                 noreply. Reads are bounded: a 2 KiB reply line, the declared VALUE size \
                 checked against memcached's 1 MiB item limit before the block is read, only \
                 requested keys, 4096 STAT lines.",
            )
            .llm_control(
                "Which keys to read and write and what to store: get/gets (up to 32 keys), \
                 set/add/replace/append/prepend/cas with flags and exptime, delete, incr/decr, \
                 touch, stats, version, and flush_all only with confirm: true.",
            )
            .e2e_testing(
                "tests/client/memcached/real_server_test.rs, 8 LLM calls, against the real C \
                 memcached prepared and read back with libmemcached's memcp and memcat (a \
                 separate C client library). The model sets a value with flags 42 that memcat \
                 reads back with its flags; gets four keys and is shown two values (with CAS \
                 uniques), a non-UTF-8 value refused as non_text_value, and a miss, each as its \
                 own event matched on parsed fields; and stores a value built from the one \
                 memcp wrote, which memcat reads back. A second test drives the command channel \
                 against the same server: an injected set read back by memcat, flush_all \
                 without confirm refused before the wire, and a disconnect. Not #[ignore]d; a \
                 missing memcached, memcp or memcat fails the test rather than skipping it. \
                 wire_test.rs and in_flight_test.rs pin the framing and each bound.",
            )
            .notes(
                "Text protocol only (the binary protocol is deprecated upstream). Values are \
                 text: a non-UTF-8 value is reported as memcached_error kind non_text_value, \
                 never re-encoded. No SASL, no meta commands (mg/ms), no response timeout.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Memcached client for reading and writing cache items over the text protocol"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to memcached at localhost:11211, store 'hello' under key greeting and read it back"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:11211",
                "base_stack": "memcached",
                "instruction": "Store 'hello' under greeting, read it back and report it"
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:11211",
                "base_stack": "memcached",
                "event_handlers": [{
                    "event_pattern": "memcached_value",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<memcached_client_handler>"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:11211",
                "base_stack": "memcached",
                "event_handlers": [
                    {
                        "event_pattern": "memcached_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "memcached_get", "keys": ["status"]}]
                        }
                    },
                    {
                        "event_pattern": "memcached_value",
                        "handler": {"type": "static", "actions": [{"type": "disconnect"}]}
                    }
                ]
            }),
        )
    }
}

impl Client for MemcachedClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::memcached::MemcachedClient::connect_with_llm_actions(
                ctx.remote_addr,
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
