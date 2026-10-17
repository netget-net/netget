//! DICT protocol actions: what the model is told, and how its answers become wire bytes.
//!
//! Every action is rendered by [`super::wire`], so the model supplies words, database names and
//! free text and never a status line, a quote or a dot. The executor has no per-connection
//! state; the one piece of state that changes rendering — `OPTION MIME` — is applied by the
//! session loop afterwards (see `wire::apply_mime`).

use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct DictProtocol;

impl DictProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DictProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for DictProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no command after the 220 \
                              banner before the server closes it. Default 300, the window a \
                              `manual` rule gives a human to answer one event - the peer may be \
                              NetGet's own TCP client with the banner parked for its operator. \
                              Lower it for a listener exposed to strangers."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::FIRST_COMMAND_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the server waits for the next command after answering \
                              one. Default 300: an interactive DICT session issues several \
                              lookups down one connection, and dict(1) itself sends QUIT as \
                              soon as it has its answer."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_dict_definitions_action(),
            send_dict_matches_action(),
            send_dict_databases_action(),
            send_dict_strategies_action(),
            send_dict_text_action(),
            send_dict_error_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DICT"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DICT_DEFINE_EVENT.clone(),
            DICT_MATCH_EVENT.clone(),
            DICT_SHOW_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DICT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dict", "dictionary", "rfc 2229", "dict.org"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // 2628 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2628)
            .implementation(
                "Hand-written RFC 2229 line protocol over tokio TCP: 220 banner with msg-id, \
                 RFC 2229 parameter quoting, dot-stuffed text blocks and OPTION MIME rendered \
                 by NetGet",
            )
            .llm_control(
                "The dictionary: definitions (DEFINE), matches (MATCH), the database and \
                 strategy lists, database and server information, and 5xx refusals",
            )
            .e2e_testing(
                "tests/server/dict/real_client_test.rs drives the real dict(1) client \
                 (dict 1.13, Debian/Ubuntu package `dict`, `brew install dict`): a lookup, \
                 `-m -s prefix`, `-D`, `-S`, `-i`, `-I` and `-M`, asserting on what dict(1) \
                 parsed and printed. The test fails, never skips, when the binary is absent. \
                 tests/server/dict/e2e_test.rs covers the mocked-model path on a raw socket.",
            )
            .notes(
                "Implements CLIENT, DEFINE, MATCH, SHOW DB/DATABASES, SHOW STRAT/STRATEGIES, \
                 SHOW INFO, SHOW SERVER, STATUS, HELP, OPTION MIME and QUIT. AUTH, SASLAUTH and \
                 SASLRESP answer 502; any other OPTION answers 503; an unknown command answers \
                 500 without consulting the model. CLIENT, STATUS, HELP, OPTION and QUIT are \
                 answered by NetGet itself. The model is the dictionary: there are no real \
                 databases, and `!`/`*` are passed to the model as given. Command lines are \
                 capped at the RFC's 1024 bytes including CRLF. On backend failure, a reply \
                 that does not fit the command, or no reply at all, the peer gets `420 Server \
                 temporarily unavailable` and the connection closes. No pcap oracle: this \
                 Wireshark build has no DICT dissector.",
            )
            .max_inbound_bytes(wire::MAX_LINE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DICT dictionary server (RFC 2229) - the model is the dictionary"
    }
    fn example_prompt(&self) -> &'static str {
        "DICT server on port 2628 - a dictionary of invented words, with a 'fantasy' database"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 2628,
                "base_stack": "dict",
                "instruction": "DICT server with one database 'fantasy' (Fantasy Lexicon) that \
                                defines invented words in the style of an old encyclopedia"
            }),
            json!({
                "type": "open_server",
                "port": 2628,
                "base_stack": "dict",
                "event_handlers": [{
                    "event_pattern": "dict_define",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\nword = json.load(sys.stdin)['event'].get('word', '')\nprint(json.dumps({'actions': [{'type': 'send_dict_definitions', 'word': word, 'definitions': [{'database': 'echo', 'database_description': 'Echo Dictionary', 'text': word + '\\n  n. the word you asked about'}]}]}))"
                    }
                }, {
                    "event_pattern": "dict_show",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dict_databases",
                            "databases": [{"name": "echo", "description": "Echo Dictionary"}]
                        }]
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 2628,
                "base_stack": "dict",
                "event_handlers": [{
                    "event_pattern": "dict_define",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dict_definitions",
                            "word": "netget",
                            "definitions": [{
                                "database": "tech",
                                "database_description": "Technical Terms",
                                "text": "netget\n  n. a server whose every reply is decided by a model"
                            }]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for DictProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
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

            crate::server::dict::DictServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        let rendered = match action_type {
            "send_dict_definitions" => render_definitions_action(&action)?,
            "send_dict_matches" => render_matches_action(&action)?,
            "send_dict_databases" => {
                wire::render_databases(&pairs(&action, "databases", "name", "description")?)
            }
            "send_dict_strategies" => {
                wire::render_strategies(&pairs(&action, "strategies", "name", "description")?)
            }
            "send_dict_text" => {
                let code = code_of(&action)?;
                let text = action.get("text").and_then(Value::as_str).unwrap_or("");
                wire::render_text(code, text).ok_or_else(|| {
                    anyhow!(
                        "send_dict_text code must be 112 (SHOW INFO), 113 (HELP) or 114 \
                         (SHOW SERVER), got {code}"
                    )
                })?
            }
            "send_dict_error" => {
                let code = code_of(&action)?;
                let message = action.get("message").and_then(Value::as_str).unwrap_or("");
                wire::render_error(code, message).ok_or_else(|| {
                    let allowed: Vec<String> = wire::ERROR_CODES
                        .iter()
                        .map(|(c, _)| c.to_string())
                        .collect();
                    anyhow!(
                        "send_dict_error code must be one of {}, got {code}",
                        allowed.join(", ")
                    )
                })?
            }
            "close_connection" => return Ok(ActionResult::CloseConnection),
            _ => return Err(anyhow!("Unknown DICT action: {}", action_type)),
        };
        Ok(ActionResult::Output(rendered.into_bytes()))
    }
}

fn code_of(action: &Value) -> Result<u16> {
    let code = action
        .get("code")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .context("Missing or non-numeric 'code' parameter")?;
    u16::try_from(code).map_err(|_| anyhow!("code {code} is not a DICT status code"))
}

fn str_field<'a>(item: &'a Value, key: &str) -> &'a str {
    item.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `[{<name_key>, <desc_key>}]` → pairs, refusing an entry with no name — an empty atom would
/// render as `""`, a listing line naming nothing.
fn pairs(
    action: &Value,
    list: &str,
    name_key: &str,
    desc_key: &str,
) -> Result<Vec<(String, String)>> {
    let items = match action.get(list) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .with_context(|| format!("'{list}' must be an array"))?,
    };
    items
        .iter()
        .map(|item| {
            let name = str_field(item, name_key).trim();
            if name.is_empty() {
                return Err(anyhow!(
                    "every entry in '{list}' needs a non-empty '{name_key}'"
                ));
            }
            Ok((name.to_string(), str_field(item, desc_key).to_string()))
        })
        .collect()
}

fn render_definitions_action(action: &Value) -> Result<String> {
    let default_word = action.get("word").and_then(Value::as_str).unwrap_or("");
    let items = match action.get("definitions") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => v
            .as_array()
            .context("'definitions' must be an array")?
            .clone(),
    };
    let mut definitions = Vec::with_capacity(items.len());
    for item in &items {
        let word = item
            .get("word")
            .and_then(Value::as_str)
            .unwrap_or(default_word);
        if word.trim().is_empty() {
            return Err(anyhow!(
                "send_dict_definitions needs 'word' (the headword each 151 line names) - copy \
                 it from the dict_define event"
            ));
        }
        let database = str_field(item, "database").trim();
        if database.is_empty() {
            return Err(anyhow!("every definition needs a non-empty 'database'"));
        }
        definitions.push(wire::Definition {
            word: word.to_string(),
            database: database.to_string(),
            database_description: str_field(item, "database_description").to_string(),
            text: str_field(item, "text").to_string(),
        });
    }
    Ok(wire::render_definitions(&definitions))
}

fn render_matches_action(action: &Value) -> Result<String> {
    let matches = pairs(action, "matches", "database", "word")?;
    for (_, word) in &matches {
        if word.trim().is_empty() {
            return Err(anyhow!("every match needs a non-empty 'word'"));
        }
    }
    Ok(wire::render_matches(&matches))
}

fn send_dict_definitions_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_definitions".to_string(),
        description: "Answer DEFINE with one or more definitions. NetGet writes the 150/151/250 \
                      status lines and the dot-terminated text blocks; give plain text. An \
                      empty 'definitions' list answers 552 (no match)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "word".to_string(),
                type_hint: "string".to_string(),
                description: "The headword the definitions are for - normally the event's \
                              'word'. A definition may override it with its own 'word'."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "definitions".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {database, database_description, text}: the database \
                              name (a short atom such as 'wn'), its human description, and the \
                              definition text (may span several lines)."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dict_definitions",
            "word": "serendipity",
            "definitions": [{
                "database": "wn",
                "database_description": "WordNet (r) 3.0",
                "text": "serendipity\n    n 1: good luck in making unexpected discoveries"
            }]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT definitions of {word}")
                .with_debug("DICT send_dict_definitions: word={word}"),
        ),
    }
}

fn send_dict_matches_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_matches".to_string(),
        description: "Answer MATCH with the words that match. NetGet writes the 152 block and \
                      the 250. An empty 'matches' list answers 552 (no match)."
            .to_string(),
        parameters: vec![Parameter {
            name: "matches".to_string(),
            type_hint: "array".to_string(),
            description: "Array of {database, word}".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dict_matches",
            "matches": [
                {"database": "wn", "word": "serene"},
                {"database": "wn", "word": "serendipity"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT matches")
                .with_debug("DICT send_dict_matches"),
        ),
    }
}

fn send_dict_databases_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_databases".to_string(),
        description: "Answer SHOW DB with the databases this dictionary offers (110 block). An \
                      empty list answers 554 (no databases present)."
            .to_string(),
        parameters: vec![Parameter {
            name: "databases".to_string(),
            type_hint: "array".to_string(),
            description: "Array of {name, description}".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dict_databases",
            "databases": [
                {"name": "wn", "description": "WordNet (r) 3.0"},
                {"name": "jargon", "description": "The Jargon File"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT database list")
                .with_debug("DICT send_dict_databases"),
        ),
    }
}

fn send_dict_strategies_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_strategies".to_string(),
        description: "Answer SHOW STRAT with the match strategies this dictionary supports \
                      (111 block). An empty list answers 555 (no strategies available)."
            .to_string(),
        parameters: vec![Parameter {
            name: "strategies".to_string(),
            type_hint: "array".to_string(),
            description: "Array of {name, description}".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dict_strategies",
            "strategies": [
                {"name": "exact", "description": "Match headwords exactly"},
                {"name": "prefix", "description": "Match prefixes"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT strategy list")
                .with_debug("DICT send_dict_strategies"),
        ),
    }
}

fn send_dict_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_text".to_string(),
        description: "Answer SHOW INFO <db> (code 112) or SHOW SERVER (code 114) with free \
                      text. NetGet writes the status line, the dot-terminated block and the 250."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "112 for SHOW INFO, 114 for SHOW SERVER (113 is HELP)".to_string(),
                required: true,
            },
            Parameter {
                name: "text".to_string(),
                type_hint: "string".to_string(),
                description: "The information text; may span several lines".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dict_text",
            "code": 112,
            "text": "WordNet 3.0\nA lexical database of English."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT {code} text")
                .with_debug("DICT send_dict_text: code={code}"),
        ),
    }
}

fn send_dict_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dict_error".to_string(),
        description: "Refuse the command with a DICT 5xx status: 550 unknown database, 551 \
                      unknown strategy, 552 no match, 554 no databases, 555 no strategies, \
                      530 access denied, 501 bad parameters, 502 not implemented. Any other \
                      code is rejected."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "A 5xx DICT status code".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "One line of text; omit to use the RFC's own wording".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dict_error",
            "code": 550,
            "message": "Invalid database, use \"SHOW DB\" for list of databases"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DICT {code} {message}")
                .with_debug("DICT send_dict_error: code={code}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the DICT connection after any reply".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("DICT connection closed")
                .with_debug("DICT close_connection"),
        ),
    }
}

/// `DEFINE database word`
pub static DICT_DEFINE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dict_define",
        "Client sent DEFINE: look up a word. database is a name from your database list, '*' \
         (all databases) or '!' (stop at the first database that has it).",
        json!({
            "type": "send_dict_definitions",
            "word": "serendipity",
            "definitions": [{
                "database": "wn",
                "database_description": "WordNet (r) 3.0",
                "text": "serendipity\n    n 1: good luck in making unexpected discoveries"
            }]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database name, '*' or '!'".to_string(),
            required: true,
        },
        Parameter {
            name: "word".to_string(),
            type_hint: "string".to_string(),
            description: "The word to define".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DICT DEFINE {database} {word}")
            .with_debug("DICT dict_define: database={database} word={word}"),
    )
    .with_actions(vec![
        send_dict_definitions_action(),
        send_dict_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "send_dict_error", "code": 552}))
});

/// `MATCH database strategy word`
pub static DICT_MATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dict_match",
        "Client sent MATCH: list headwords matching word under strategy ('.' means your \
         default strategy). database is a name, '*' or '!'.",
        json!({
            "type": "send_dict_matches",
            "matches": [{"database": "wn", "word": "serendipity"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database name, '*' or '!'".to_string(),
            required: true,
        },
        Parameter {
            name: "strategy".to_string(),
            type_hint: "string".to_string(),
            description: "Strategy name, or '.' for the server default".to_string(),
            required: true,
        },
        Parameter {
            name: "word".to_string(),
            type_hint: "string".to_string(),
            description: "The word to match against".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DICT MATCH {database} {strategy} {word}")
            .with_debug("DICT dict_match: database={database} strategy={strategy} word={word}"),
    )
    .with_actions(vec![
        send_dict_matches_action(),
        send_dict_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "send_dict_error", "code": 551}))
});

/// `SHOW DB` / `SHOW STRAT` / `SHOW INFO database` / `SHOW SERVER`
pub static DICT_SHOW_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dict_show",
        "Client sent SHOW. what = 'databases' (answer send_dict_databases), 'strategies' \
         (send_dict_strategies), 'info' (send_dict_text code 112 about 'database') or 'server' \
         (send_dict_text code 114).",
        json!({
            "type": "send_dict_databases",
            "databases": [{"name": "wn", "description": "WordNet (r) 3.0"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "what".to_string(),
            type_hint: "string".to_string(),
            description: "What is being shown".to_string(),
            required: true,
        }
        .with_choices(["databases", "strategies", "info", "server"]),
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "The database SHOW INFO asks about (only when what is 'info')".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DICT SHOW {what}")
            .with_debug("DICT dict_show: what={what}"),
    )
    .with_actions(vec![
        send_dict_databases_action(),
        send_dict_strategies_action(),
        send_dict_text_action(),
        send_dict_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_dict_text",
        "code": 114,
        "text": "NetGet DICT server\nThe model is the dictionary."
    }))
});
