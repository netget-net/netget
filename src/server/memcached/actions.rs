//! Memcached protocol actions.
//!
//! **This server stores nothing.** There is no map, no table, no file. Every `get` is
//! answered by the model; every `set` is a question put to the model about whether it would
//! have stored the item. That is the project rule (protocols must not implement storage) and
//! it is also the only reason a Memcached server under NetGet is interesting: a hash map is
//! not worth emulating, but a model deciding what a key holds is.
//!
//! If real persistence is wanted, the sanctioned route is the generic SQLite facility
//! (`src/state/sqlite.rs`) that the model opts into at runtime — never a cache welded into
//! this protocol.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::protocol::{self, ValueItem};

pub struct MemcachedProtocol;

impl Default for MemcachedProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl MemcachedProtocol {
    pub fn new() -> Self {
        Self
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

/// Decode a value documented as `utf8` or `hex`.
///
/// Explicit rather than sniffed, for the reason the TCP fix (`d70bb5b5`) established:
/// `"48656c6c6f"` is simultaneously valid text and valid hex, and only the sender knows
/// which it meant. Cache values are frequently binary (serialised objects, compressed
/// blobs), so this is not a theoretical concern here.
fn decode_value(entry: &serde_json::Value, key: &str, encoding_key: &str) -> Result<Vec<u8>> {
    let raw = entry
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("missing '{}'", key))?;
    match entry
        .get(encoding_key)
        .and_then(|v| v.as_str())
        .unwrap_or("utf8")
    {
        "utf8" => Ok(raw.as_bytes().to_vec()),
        "hex" => Ok(hex::decode(raw)
            .with_context(|| format!("'{}' is declared hex but is not valid hex", key))?),
        other => Err(anyhow::anyhow!(
            "Unknown {} '{}': use \"utf8\" or \"hex\"",
            encoding_key,
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Events — one per command shape, and every one of them is raised by mod.rs.
// ---------------------------------------------------------------------------

pub static MEMCACHED_GET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_get",
        "A client asked for one or more keys. Answer each requested key your instruction gives \
         a value; a key it does not is absent and is left out. Returning an empty values list \
         is a cache miss. answer_with says which keys may appear.",
        json!({
            "type": "send_memcached_values",
            "values": [{"key": "example-key", "value": "example-value"}]
        }),
    )
    .with_parameters(vec![
        p(
            "command",
            "string",
            "'get' or 'gets'; 'gets' also wants a cas_unique per value",
        ),
        p("keys", "array", "Keys requested, in order"),
        p(
            "answer_with",
            "string",
            "The action, and the only keys the answer may carry",
        ),
    ])
    .with_actions(vec![
        send_values_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_STORE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_store",
        "A client wants to store an item. Decide whether the store succeeds. This server \
         keeps nothing, so 'succeeds' means whatever your instruction says it should mean.",
        json!({ "type": "send_memcached_status", "status": "STORED" }),
    )
    .with_parameters(vec![
        p(
            "command",
            "string",
            "'set', 'add', 'replace', 'append', 'prepend' or 'cas'",
        ),
        p("key", "string", "Key being stored"),
        p(
            "flags",
            "number",
            "Opaque 32-bit flags the client asked to be stored with the item",
        ),
        p(
            "exptime",
            "number",
            "Requested expiry: 0 = never, <0 = immediately expired",
        ),
        p(
            "bytes",
            "number",
            "Length of the data block, as counted off the wire",
        ),
        p("cas_unique", "number", "Present only for 'cas'"),
        p("value", "string", "The data block"),
        p(
            "value_encoding",
            "string",
            "'utf8' if the data block was valid UTF-8, else 'hex'",
        ),
    ])
    .with_actions(vec![
        send_status_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_delete",
        "A client asked to delete a key. Answer DELETED or NOT_FOUND.",
        json!({ "type": "send_memcached_status", "status": "DELETED" }),
    )
    .with_parameters(vec![p("key", "string", "Key to delete")])
    .with_actions(vec![
        send_status_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_ARITHMETIC_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_arithmetic",
        "A client asked to increment or decrement a counter. Answer with the new value, \
         NOT_FOUND, or a CLIENT_ERROR if the key does not hold a number.",
        json!({ "type": "send_memcached_number", "value": 43 }),
    )
    .with_parameters(vec![
        p("command", "string", "'incr' or 'decr'"),
        p("key", "string", "Counter key"),
        p("delta", "number", "Amount to add or subtract"),
    ])
    .with_actions(vec![
        send_number_action(),
        send_status_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_TOUCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_touch",
        "A client asked to update a key's expiry without fetching it. Answer TOUCHED or \
         NOT_FOUND.",
        json!({ "type": "send_memcached_status", "status": "TOUCHED" }),
    )
    .with_parameters(vec![
        p("key", "string", "Key to touch"),
        p("exptime", "number", "New expiry"),
    ])
    .with_actions(vec![
        send_status_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_STATS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_stats",
        "A client asked for server statistics. Report what your instruction says about this \
         server - its version, how many items it holds - under memcached's stat names, and \
         fill the rest plausibly.",
        json!({
            "type": "send_memcached_stats",
            "stats": {"version": "1.6.0", "curr_items": "0", "uptime": "0"}
        }),
    )
    .with_parameters(vec![
        p(
            "argument",
            "string",
            "Sub-command such as 'items', 'slabs', 'sizes', or null for the general stats",
        ),
        p(
            "answer_with",
            "string",
            "The action, and which stat names carry what the instruction says",
        ),
    ])
    .with_actions(vec![
        send_stats_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_VERSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_version",
        "A client asked which memcached version this is. Answer with whatever version you \
         want to claim to be.",
        json!({ "type": "send_memcached_version", "version": "1.6.45" }),
    )
    .with_parameters(vec![])
    .with_actions(vec![
        send_version_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_FLUSH_ALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_flush_all",
        "A client asked to invalidate everything. Answer OK, or refuse with an error.",
        json!({ "type": "send_memcached_status", "status": "OK" }),
    )
    .with_parameters(vec![p(
        "delay",
        "number",
        "Seconds until the flush takes effect; 0 means immediately",
    )])
    .with_actions(vec![
        send_status_action(),
        send_error_action(),
        close_connection_action(),
    ])
});

pub static MEMCACHED_UNKNOWN_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "memcached_unknown_command",
        "A command line this server does not recognise. Real memcached answers ERROR; you \
         may instead answer as though the verb existed.",
        json!({ "type": "send_memcached_error", "kind": "ERROR" }),
    )
    .with_parameters(vec![p("line", "string", "The command line as received")])
    .with_actions(vec![
        send_error_action(),
        send_status_action(),
        send_values_action(),
        close_connection_action(),
    ])
});

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

fn send_values_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_values".to_string(),
        description: "Answer a get/gets. Each entry becomes a VALUE block; an empty list is \
                      a cache miss (END with no values). Only keys the client asked for may \
                      appear - NetGet drops any other. The byte count in each VALUE header is \
                      computed from the payload — do not supply one. The example's keys and \
                      values are placeholders."
            .to_string(),
        parameters: vec![required(
            "values",
            "array",
            "[{key, value, value_encoding ('utf8' default or 'hex'), flags (default 0), \
             cas_unique (gets only)}]. Omit keys you want to report as missing.",
        )],
        example: json!({
            "type": "send_memcached_values",
            "values": [
                {"key": "example-key", "value": "example-value", "flags": 0},
                {"key": "example-blob", "value": "0001ff", "value_encoding": "hex"}
            ]
        }),
        log_template: None,
    }
}

fn send_status_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_status".to_string(),
        description: "Answer with one of the protocol's fixed status lines.".to_string(),
        parameters: vec![required(
            "status",
            "string",
            "One of STORED, NOT_STORED, EXISTS, NOT_FOUND, DELETED, TOUCHED, OK, ERROR",
        )],
        example: json!({ "type": "send_memcached_status", "status": "STORED" }),
        log_template: None,
    }
}

fn send_number_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_number".to_string(),
        description: "Answer an incr/decr with the counter's new value.".to_string(),
        parameters: vec![required(
            "value",
            "number",
            "New counter value (64-bit unsigned)",
        )],
        example: json!({ "type": "send_memcached_number", "value": 43 }),
        log_template: None,
    }
}

fn send_stats_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_stats".to_string(),
        description: "Answer a stats command. Each entry becomes a STAT line, terminated by \
                      END. Use memcached's own stat names (version, curr_items, total_items, \
                      bytes, uptime, pid); the example's values are placeholders for the ones \
                      your instruction gives."
            .to_string(),
        parameters: vec![required(
            "stats",
            "object",
            "Flat map of stat name to value; values are rendered as text",
        )],
        example: json!({
            "type": "send_memcached_stats",
            "stats": {"version": "1.6.0", "curr_items": "0", "uptime": "0"}
        }),
        log_template: None,
    }
}

fn send_version_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_version".to_string(),
        description: "Answer a version command.".to_string(),
        parameters: vec![required("version", "string", "Version string to claim")],
        example: json!({ "type": "send_memcached_version", "version": "1.6.45" }),
        log_template: None,
    }
}

fn send_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_memcached_error".to_string(),
        description: "Answer with a protocol error. 'ERROR' means the command is not \
                      understood; 'CLIENT_ERROR' means the client got the request wrong; \
                      'SERVER_ERROR' means this server failed."
            .to_string(),
        parameters: vec![
            required("kind", "string", "ERROR, CLIENT_ERROR or SERVER_ERROR"),
            p(
                "message",
                "string",
                "Explanation; required for CLIENT_ERROR and SERVER_ERROR, ignored for ERROR",
            ),
        ],
        example: json!({
            "type": "send_memcached_error",
            "kind": "CLIENT_ERROR",
            "message": "cannot increment or decrement non-numeric value"
        }),
        log_template: None,
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_memcached_connection".to_string(),
        description: "Close the client connection without sending anything further.".to_string(),
        parameters: vec![],
        example: json!({ "type": "close_memcached_connection" }),
        log_template: None,
    }
}

// ---------------------------------------------------------------------------
// Protocol / Server
// ---------------------------------------------------------------------------

impl Protocol for MemcachedProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_values_action(),
            send_status_action(),
            send_number_action(),
            send_stats_action(),
            send_version_action(),
            send_error_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Memcached"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            MEMCACHED_GET_EVENT.clone(),
            MEMCACHED_STORE_EVENT.clone(),
            MEMCACHED_DELETE_EVENT.clone(),
            MEMCACHED_ARITHMETIC_EVENT.clone(),
            MEMCACHED_TOUCH_EVENT.clone(),
            MEMCACHED_STATS_EVENT.clone(),
            MEMCACHED_VERSION_EVENT.clone(),
            MEMCACHED_FLUSH_ALL_EVENT.clone(),
            MEMCACHED_UNKNOWN_COMMAND_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Memcached"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Narrow on purpose. A bare "cache" would hijack keyword resolution for every
        // caching-adjacent protocol in the registry, which is how three BLE profiles
        // claiming "file"/"transfer"/"stream" broke FTP and NFS.
        vec!["memcached", "memcache", "memcached server"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // 11211 is above 1023; PrivilegedPort here would be dead code.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(11211)
            // The one peer-chosen length in the text protocol is a storage command's declared
            // `<bytes>`; it is refused against this before any of the data block is read.
            // Tested from the wire in tests/server/memcached/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::memcached::protocol::MAX_VALUE_LEN)
            .implementation(
                "Hand-rolled memcached *text* protocol (src/server/memcached/protocol.rs) \
                 over TCP. get/gets/set/add/replace/append/prepend/cas/delete/incr/decr/\
                 touch/stats/version/flush_all/quit. Storage-command data blocks are read by \
                 the declared byte count, never by scanning for CRLF, so a payload \
                 containing CRLF frames correctly. The binary protocol is not implemented \
                 (deprecated upstream in 1.6) and neither are the meta commands (mg/ms/md).",
            )
            .llm_control(
                "The model IS the cache. It decides what every key holds, whether a store \
                 succeeds, what the counters read and what stats to report. No value is \
                 stored anywhere in this server.",
            )
            .e2e_testing(
                "libmemcached 1.0.18's C tools are the independent peer, in \
                 tests/server/memcached/real_client_test.rs: memcat reads a model-invented \
                 value (it parses the VALUE header and reads exactly that many bytes, so a \
                 wrong count shows up as an empty or truncated result rather than a pass), \
                 and memstat and memping accept our STAT/END and VERSION replies. They are a \
                 separate C implementation invoked as subprocesses, never linked. Neither \
                 test is #[ignore]d and both now FAIL rather than skip when the binaries are \
                 absent; until September 2026 they printed SKIPPED and returned Ok(()), a \
                 silent pass, which is what held this at Experimental. The always-running \
                 raw-socket tests remain the byte-level check - exact VALUE/END framing, byte \
                 counts, a payload containing CRLF, and a rejected storage header consuming \
                 its data block instead of leaving it to be parsed as commands. Untested \
                 against any client for the binary protocol or the meta commands, neither of \
                 which is implemented.",
            )
            .notes(
                "STORES NOTHING BY DESIGN: there is no map or table in the Rust code, so \
                 two successive gets of the same key are two independent questions to the \
                 model and may legitimately differ. Use a script handler or the generic \
                 SQLite facility if you need a key to keep its value. Every command costs \
                 one LLM call; `noreply` is honoured, so a noreply store still costs a call \
                 but sends nothing.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Memcached text-protocol server where the model answers every lookup"
    }

    fn example_prompt(&self) -> &'static str {
        "pretend to be a memcached server on port 11211 holding session data for a web app"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 11211,
                "base_stack": "memcached",
                "instruction": "Act as a session cache. Keys look like session:<id> and hold \
                                a JSON user object. Report STORED for any set."
            }),
            json!({
                "type": "open_server",
                "port": 11211,
                "base_stack": "memcached",
                "event_handlers": [{
                    "event_pattern": "memcached_get",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_memcached_values', 'values': [{'key': k, 'value': 'v-' + k} for k in event['keys']]}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 11211,
                "base_stack": "memcached",
                "event_handlers": [
                    {
                        "event_pattern": "memcached_get",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_memcached_values", "values": []}]
                        }
                    },
                    {
                        "event_pattern": "memcached_store",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_memcached_status", "status": "STORED"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for MemcachedProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::MemcachedServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_memcached_values" => {
                let entries = action
                    .get("values")
                    .and_then(|v| v.as_array())
                    .context("send_memcached_values requires a 'values' array")?;

                let mut items = Vec::with_capacity(entries.len());
                let mut any_cas = false;
                for entry in entries {
                    let key = entry
                        .get("key")
                        .and_then(|v| v.as_str())
                        .context("each value needs a 'key'")?
                        .to_string();
                    if key.len() > protocol::MAX_KEY_LEN {
                        return Err(anyhow::anyhow!(
                            "key '{}' is {} bytes; memcached allows at most {}",
                            key,
                            key.len(),
                            protocol::MAX_KEY_LEN
                        ));
                    }
                    if key.bytes().any(|b| b <= b' ' || b == 127) {
                        return Err(anyhow::anyhow!(
                            "key '{}' contains whitespace or a control character, which the \
                             text protocol cannot express",
                            key
                        ));
                    }
                    let data = decode_value(entry, "value", "value_encoding")?;
                    if data.len() > protocol::MAX_VALUE_LEN {
                        return Err(anyhow::anyhow!(
                            "value for '{}' is {} bytes; memcached's item limit is {}",
                            key,
                            data.len(),
                            protocol::MAX_VALUE_LEN
                        ));
                    }
                    let flags = entry.get("flags").and_then(|v| v.as_u64()).unwrap_or(0);
                    let cas_unique = entry.get("cas_unique").and_then(|v| v.as_u64());
                    any_cas |= cas_unique.is_some();
                    items.push(ValueItem {
                        key,
                        flags: u32::try_from(flags).context("flags exceed 32 bits")?,
                        data,
                        cas_unique,
                    });
                }

                Ok(ActionResult::Output(protocol::encode_values(
                    &items, any_cas,
                )))
            }

            "send_memcached_status" => {
                let status = action
                    .get("status")
                    .and_then(|v| v.as_str())
                    .context("send_memcached_status requires 'status'")?;
                let line =
                    protocol::status_line(&status.to_ascii_uppercase()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Unknown memcached status '{}'. Use one of STORED, NOT_STORED, \
                         EXISTS, NOT_FOUND, DELETED, TOUCHED, OK, ERROR",
                            status
                        )
                    })?;
                Ok(ActionResult::Output(line.as_bytes().to_vec()))
            }

            "send_memcached_number" => {
                let value = action
                    .get("value")
                    .and_then(|v| v.as_u64())
                    .context("send_memcached_number requires a non-negative integer 'value'")?;
                Ok(ActionResult::Output(format!("{}\r\n", value).into_bytes()))
            }

            "send_memcached_stats" => {
                let map = action
                    .get("stats")
                    .and_then(|v| v.as_object())
                    .context("send_memcached_stats requires a 'stats' object")?;
                let entries: Vec<(String, String)> = map
                    .iter()
                    .map(|(k, v)| {
                        let rendered = match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        (k.clone(), rendered)
                    })
                    .collect();
                Ok(ActionResult::Output(protocol::encode_stats(&entries)))
            }

            "send_memcached_version" => {
                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .context("send_memcached_version requires 'version'")?;
                if version.contains(['\r', '\n']) {
                    return Err(anyhow::anyhow!("version string must not contain CR or LF"));
                }
                Ok(ActionResult::Output(
                    format!("VERSION {}\r\n", version).into_bytes(),
                ))
            }

            "send_memcached_error" => {
                let kind = action
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .context("send_memcached_error requires 'kind'")?
                    .to_ascii_uppercase();
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .replace(['\r', '\n'], " ");
                let line = match kind.as_str() {
                    "ERROR" => "ERROR\r\n".to_string(),
                    "CLIENT_ERROR" | "SERVER_ERROR" => {
                        if message.is_empty() {
                            return Err(anyhow::anyhow!("{} requires a 'message'", kind));
                        }
                        format!("{} {}\r\n", kind, message)
                    }
                    other => {
                        return Err(anyhow::anyhow!(
                            "Unknown error kind '{}': use ERROR, CLIENT_ERROR or SERVER_ERROR",
                            other
                        ))
                    }
                };
                Ok(ActionResult::Output(line.into_bytes()))
            }

            "close_memcached_connection" => Ok(ActionResult::CloseConnection),

            // Not offered to the model, but the dashboard's "disconnect this peer" injects it
            // through the peer command task, which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),

            _ => Err(anyhow::anyhow!("Unknown Memcached action: {}", action_type)),
        }
    }
}
