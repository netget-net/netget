//! Bolt actions: what the model is told, and what its answers become.
//!
//! The model answers two questions — may this login in, and what does this Cypher query return —
//! and never anything about the protocol's mechanics. Its answers are validated here and handed
//! to the session as [`ActionResult::Custom`]; the session owns the state machine, turns a
//! `send_bolt_records` answer into RUN's SUCCESS, the RECORDs PULL asks for and the summary, and
//! writes every byte.

use super::values;
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

/// `ActionResult::Custom` names the session recognises.
pub const LOGIN_RESULT: &str = "bolt_login";
pub const RECORDS_RESULT: &str = "bolt_records";
pub const FAILURE_RESULT: &str = "bolt_failure";

/// The code a login rejection carries when the model names none.
pub const UNAUTHORIZED: &str = "Neo.ClientError.Security.Unauthorized";

pub struct BoltProtocol;

impl BoltProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BoltProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BoltProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "Password every basic-auth login must present. NetGet compares it \
                              itself (constant time) and refuses a mismatch with \
                              Neo.ClientError.Security.Unauthorized without asking anyone; the \
                              credential never reaches an event. Unset: any password passes to \
                              the bolt_authenticate event, which decides."
                    .to_string(),
                required: false,
                example: json!("s3cret"),
                default: None,
            },
            ParameterDefinition {
                name: "neo4j_version".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Neo4j version the server claims (default {}): the HELLO agent is \
                     'Neo4j/<version>' - drivers refuse any agent not starting 'Neo4j/' - and \
                     CALL dbms.components() reports it.",
                    super::DEFAULT_NEO4J_VERSION
                ),
                required: false,
                example: json!("5.26.0"),
                default: Some(json!(super::DEFAULT_NEO4J_VERSION)),
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a new connection may take to send the 20-byte Bolt \
                              handshake (default 30). Bolt is client-speaks-first and every \
                              driver sends the handshake the moment it connects."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::FIRST_BYTE_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the server waits for the next message once the handshake \
                              is done (default 300). Drivers pool connections and leave them \
                              idle between queries, so this is deliberately long. It never runs \
                              while a query is waiting on the model or on a human."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_bolt_login_action(),
            reject_bolt_login_action(),
            send_bolt_records_action(),
            send_bolt_failure_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Bolt"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![BOLT_AUTHENTICATE_EVENT.clone(), BOLT_QUERY_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BOLT"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bolt", "neo4j", "cypher", "graph database", "cypher-shell"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(7687)
            // 7687 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Neo4j's Bolt protocol, hand-written over tokio TCP: the 60 60 B0 17 handshake \
                 negotiating Bolt 5.0-5.8, a depth-bounded PackStream codec and message \
                 chunking, and the server state machine (HELLO/LOGON, RUN/PULL/DISCARD, \
                 BEGIN/COMMIT/ROLLBACK, RESET, ROUTE, LOGOFF, TELEMETRY, GOODBYE) owned by NetGet",
            )
            .llm_control(
                "The graph database: whether a login is accepted, and what each Cypher query \
                 returns - columns, rows (plain values, nodes, relationships, paths), update \
                 statistics - or which Neo4j error it fails with. NetGet stores no graph.",
            )
            .e2e_testing(
                "tests/server/bolt/real_client_test.rs drives the real cypher-shell (Neo4j's \
                 Java client, neo4j-java-driver 6.2) against a script handler and a mocked \
                 model: a query printed row for row, nodes and paths rendered as graph values, \
                 stats, a model-chosen error printed as that error, a wrong password refused, \
                 an explicit transaction and neo4j:// routing. It fails, never skips, when \
                 cypher-shell is absent. tests/server/bolt/e2e_test.rs covers the mocked-model \
                 path on a raw socket.",
            )
            .notes(
                "Negotiates the highest of Bolt 5.0-5.8 the client offers (cypher-shell \
                 2026.09 offers 5.8; the 5.7+ handshake manifest is declined). 5.0 \
                 authenticates in HELLO, 5.1+ in LOGON. FAILURE carries {code, message} before \
                 5.7 and the GQL error object (gql_status 50N42, neo4j_code) from 5.7. \
                 Answered by NetGet without a model call: HELLO, ROUTE (a single-server \
                 routing table naming the address the client used), BEGIN/COMMIT/ROLLBACK, \
                 RESET, TELEMETRY, and three admin queries cypher-shell sends on connect - CALL \
                 db.ping(), CALL dbms.licenseAgreementDetails() and CALL dbms.components(). \
                 PULL/DISCARD require explicit integer n and typed qid over the model's rows; \
                 known messages require exact arity. Owned model/injected actions are preflighted \
                 before copies at JSON depth36/nodes65536/retained8MiB; emitted RECORDs include \
                 their structure/list envelopes in the strict wire-depth32 check. Messages are capped at 1 \
                 MiB summed over chunks and PackStream nesting at 32; either refusal is a \
                 Neo.ClientError.Request.Invalid FAILURE and a close. Not implemented: TLS \
                 (bolt+s), the handshake manifest (Bolt 6), notifications, temporal and \
                 spatial values in answers. No pcap oracle: this Wireshark build has no Bolt \
                 dissector.",
            )
            .max_inbound_bytes(super::packstream::MAX_MESSAGE_BYTES)
            // LLM failure: FAILURE Neo.TransientError.General.DatabaseUnavailable with a fixed
            // message per WireFailure category; the connection stays usable after RESET.
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Neo4j graph database over Bolt - the model answers every Cypher query"
    }

    fn example_prompt(&self) -> &'static str {
        "Neo4j Bolt server on port 7687 - a small movie graph: people who ACTED_IN and DIRECTED \
         movies"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 7687,
                "base_stack": "bolt",
                "instruction": "Neo4j graph database of a film club: Person nodes (name, born) \
                                who ACTED_IN or DIRECTED Movie nodes (title, released). Accept \
                                any login. Answer Cypher queries with plausible rows."
            }),
            json!({
                "type": "open_server",
                "port": 7687,
                "base_stack": "bolt",
                "event_handlers": [{
                    "event_pattern": "bolt_authenticate",
                    "handler": {"type": "static", "actions": [{"type": "accept_bolt_login"}]}
                }, {
                    "event_pattern": "bolt_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\nq = json.load(sys.stdin)['event'].get('query', '')\nif 'Person' in q:\n    a = [{'type': 'send_bolt_records', 'fields': ['name'], 'records': [['Alice'], ['Bob']]}]\nelse:\n    a = [{'type': 'send_bolt_failure', 'code': 'Neo.ClientError.Statement.SyntaxError', 'message': 'This graph only knows Person nodes'}]\nprint(json.dumps({'actions': a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 7687,
                "base_stack": "bolt",
                "event_handlers": [{
                    "event_pattern": "bolt_authenticate",
                    "handler": {"type": "static", "actions": [{"type": "accept_bolt_login"}]}
                }, {
                    "event_pattern": "bolt_query",
                    "handler": {"type": "static", "actions": [{
                        "type": "send_bolt_records",
                        "fields": ["n"],
                        "records": [[{"$node": {"id": 1, "labels": ["Person"],
                                                 "properties": {"name": "Alice"}}}]]
                    }]}
                }]
            }),
        )
    }
}

impl Server for BoltProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(params
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let string = |name: &str| -> anyhow::Result<Option<String>> {
                Ok(params
                    .map(|p| p.get_optional_string(name))
                    .transpose()?
                    .flatten())
            };
            let config = super::BoltConfig {
                password: string("password")?,
                neo4j_version: string("neo4j_version")?
                    .unwrap_or_else(|| super::DEFAULT_NEO4J_VERSION.to_string()),
                first_byte_timeout: secs("first_byte_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::FIRST_BYTE_TIMEOUT),
                idle_timeout: secs("idle_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::IDLE_TIMEOUT),
            };
            crate::server::bolt::BoltServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                config,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        if !values::action_within_budget(&action) {
            crate::utils::json_budget::drop_iteratively(action);
            return Err(anyhow!(
                "Bolt action exceeds the in-memory depth/node/retained-content budget"
            ));
        }
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "accept_bolt_login" => Ok(ActionResult::Custom {
                name: LOGIN_RESULT.to_string(),
                data: json!({"accept": true}),
            }),
            "reject_bolt_login" => {
                let code = action
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or(UNAUTHORIZED);
                if !code.starts_with("Neo.ClientError.Security.")
                    || !values::valid_failure_code(code)
                {
                    return Err(anyhow!(
                        "reject_bolt_login code must be a Neo.ClientError.Security.* status \
                         such as {UNAUTHORIZED}, got '{code}'"
                    ));
                }
                let message = action
                    .get("message")
                    .and_then(Value::as_str)
                    .filter(|m| !m.trim().is_empty())
                    .unwrap_or("The client is unauthorized due to authentication failure.");
                Ok(ActionResult::Custom {
                    name: LOGIN_RESULT.to_string(),
                    data: json!({"accept": false, "code": code, "message": message}),
                })
            }
            "send_bolt_records" => {
                values::query_answer(&action).map_err(|e| anyhow!("send_bolt_records: {e}"))?;
                Ok(ActionResult::Custom {
                    name: RECORDS_RESULT.to_string(),
                    data: action.clone(),
                })
            }
            "send_bolt_failure" => {
                let code = action
                    .get("code")
                    .and_then(Value::as_str)
                    .context("send_bolt_failure needs a 'code'")?;
                if !values::valid_failure_code(code) {
                    return Err(anyhow!(
                        "send_bolt_failure code must look like Neo.ClientError.<Category>.<Title>, \
                         Neo.TransientError.<Category>.<Title> or \
                         Neo.DatabaseError.<Category>.<Title>, got '{code}'"
                    ));
                }
                let message = action
                    .get("message")
                    .and_then(Value::as_str)
                    .filter(|m| !m.trim().is_empty())
                    .context("send_bolt_failure needs a non-empty 'message'")?;
                Ok(ActionResult::Custom {
                    name: FAILURE_RESULT.to_string(),
                    data: json!({"code": code, "message": message}),
                })
            }
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown Bolt action: {}", action_type)),
        }
    }
}

fn accept_bolt_login_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_bolt_login".to_string(),
        description: "Let this login in. NetGet answers the client's LOGON with SUCCESS and the \
                      connection can run queries."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "accept_bolt_login"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Bolt login accepted")
                .with_debug("Bolt accept_bolt_login"),
        ),
    }
}

fn reject_bolt_login_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_bolt_login".to_string(),
        description: "Refuse this login. The client receives a FAILURE with the code (default \
                      Neo.ClientError.Security.Unauthorized) and the connection closes."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "A Neo.ClientError.Security.* status, e.g. \
                              Neo.ClientError.Security.Unauthorized or \
                              Neo.ClientError.Security.AuthenticationRateLimit"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "The message the client prints".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "reject_bolt_login",
            "code": "Neo.ClientError.Security.Unauthorized",
            "message": "The client is unauthorized due to authentication failure."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Bolt login rejected: {code}")
                .with_debug("Bolt reject_bolt_login: code={code}"),
        ),
    }
}

fn send_bolt_records_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bolt_records".to_string(),
        description: "Answer the Cypher query with a result: column names and rows. NetGet sends \
                      the column list, streams the rows as the client pulls them, and ends with \
                      the summary. A query that returns nothing (a CREATE without RETURN) has an \
                      empty 'fields' and 'records'. A value may be any JSON; a graph value is \
                      {\"$node\": {id, labels, properties}}, {\"$relationship\": {id, type, \
                      start, end, properties}} or {\"$path\": {nodes: [...], relationships: \
                      [...]}} where relationships[i] joins nodes[i] and nodes[i+1]."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "fields".to_string(),
                type_hint: "array".to_string(),
                description: "Column names, in order - the names after RETURN / AS".to_string(),
                required: true,
            },
            Parameter {
                name: "records".to_string(),
                type_hint: "array".to_string(),
                description: "Rows; each row is an array with one value per field, in field \
                              order"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "stats".to_string(),
                type_hint: "object".to_string(),
                description: "Update counts for a write, e.g. {\"nodes_created\": 1, \
                              \"properties_set\": 2}. Keys: nodes_created, nodes_deleted, \
                              relationships_created, relationships_deleted, properties_set, \
                              labels_added, labels_removed, indexes_added, indexes_removed, \
                              constraints_added, constraints_removed, system_updates"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "r (read, default), w (write), rw (read and write) or s (schema)"
                    .to_string(),
                required: false,
            }
            .with_choices(["r", "w", "rw", "s"]),
        ],
        example: json!({
            "type": "send_bolt_records",
            "fields": ["name", "born"],
            "records": [["Keanu Reeves", 1964], ["Carrie-Anne Moss", 1967]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Bolt result")
                .with_debug("Bolt send_bolt_records"),
        ),
    }
}

fn send_bolt_failure_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bolt_failure".to_string(),
        description: "Fail the query with a Neo4j error, which the client prints. Common codes: \
                      Neo.ClientError.Statement.SyntaxError (bad Cypher), \
                      Neo.ClientError.Statement.EntityNotFound, \
                      Neo.ClientError.Schema.ConstraintValidationFailed, \
                      Neo.ClientError.Security.Forbidden, \
                      Neo.ClientError.Database.DatabaseNotFound, \
                      Neo.TransientError.Transaction.DeadlockDetected."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Neo.ClientError.*, Neo.TransientError.* or Neo.DatabaseError.* \
                              status code"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "The error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_bolt_failure",
            "code": "Neo.ClientError.Statement.SyntaxError",
            "message": "Invalid input 'RETRUN': expected 'RETURN' (line 1, column 1 (offset: 0))"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Bolt FAILURE {code}")
                .with_debug("Bolt send_bolt_failure: code={code}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the Bolt connection without answering".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Bolt connection closed")
                .with_debug("Bolt close_connection"),
        ),
    }
}

/// The `answer_with` field of `bolt_authenticate`: what the login is decided on.
///
/// Told "act as a Neo4j graph database that accepts any login. Reject any query that is not
/// valid Cypher with Neo4j's syntax error", llama3.1:8b answered the login with
/// `reject_bolt_login` five runs in five - "Reject" was the instruction's operative verb, and
/// nothing in the login event said that no query was being decided yet. The request now says
/// what the login turns on, and that query rules wait for the query.
pub fn login_answer_with(principal: &str, scheme: &str, credentials_present: bool) -> String {
    let user = if principal.is_empty() {
        "no user name".to_string()
    } else {
        format!("user \"{principal}\"")
    };
    let credential = if credentials_present {
        "a credential"
    } else {
        "no credential"
    };
    format!(
        "decide only whether {user} (scheme {scheme}, {credential}) may log in. \
         accept_bolt_login unless your instructions refuse this user, this scheme, or a login \
         without a credential. No query has been sent yet: rules about queries - rejecting \
         invalid Cypher, refusing writes - are applied to each query when it arrives, never \
         to the login"
    )
}

/// HELLO (Bolt 5.0) or LOGON (5.1+) with the client's credentials.
pub static BOLT_AUTHENTICATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bolt_authenticate",
        "A client is logging in to the graph database - this decision is about the login \
         only, before any query has been sent. Decide whether this user may connect. Rules \
         your instructions give about queries (reject invalid Cypher, refuse writes, ...) do \
         not apply here: queries arrive later as bolt_query. The credential itself is never \
         shown; when the server has a configured password NetGet has already checked it.",
        json!({"type": "accept_bolt_login"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "user_agent".to_string(),
            type_hint: "string".to_string(),
            description: "The client's own name, e.g. neo4j-cypher-shell/v2026.09.0".to_string(),
            required: true,
        },
        Parameter {
            name: "scheme".to_string(),
            type_hint: "string".to_string(),
            description: "Auth scheme: basic, none, bearer, kerberos or a custom one".to_string(),
            required: true,
        },
        Parameter {
            name: "principal".to_string(),
            type_hint: "string".to_string(),
            description: "The user name (empty for scheme none)".to_string(),
            required: true,
        },
        Parameter {
            name: "credentials_present".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the client sent a credential at all".to_string(),
            required: true,
        },
        Parameter {
            name: "password_configured".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the server has a password and the client's matched it"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "What this login is decided on: the user, the scheme and whether a \
                          credential was sent - never a query, which has not been sent yet"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Bolt login {principal} ({scheme})")
            .with_debug("Bolt bolt_authenticate: principal={principal} scheme={scheme}"),
    )
    .with_actions(vec![
        accept_bolt_login_action(),
        reject_bolt_login_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "reject_bolt_login",
        "code": "Neo.ClientError.Security.Unauthorized",
        "message": "The client is unauthorized due to authentication failure."
    }))
});

/// The clauses a Cypher statement can begin with.
const CYPHER_LEADING_CLAUSES: &[&str] = &[
    "MATCH",
    "OPTIONAL",
    "MERGE",
    "CREATE",
    "RETURN",
    "WITH",
    "UNWIND",
    "CALL",
    "USE",
    "SHOW",
    "LOAD",
    "FOREACH",
    "DELETE",
    "DETACH",
    "SET",
    "REMOVE",
    "EXPLAIN",
    "PROFILE",
    "CYPHER",
    "DROP",
    "ALTER",
    "GRANT",
    "DENY",
    "REVOKE",
    "START",
    "STOP",
    "TERMINATE",
    "FINISH",
];

/// The `answer_with` field of `bolt_query`: hold the query against the instructions first, and
/// say whether it even begins like Cypher.
///
/// Told "reject any query that is not valid Cypher with Neo4j's syntax error", llama3.1:8b
/// answered `SELECT name FROM people` with rows - the event example's Alice and Bob - in every
/// run of the real-model eval (`bolt/syntax-error`, seed 42), and a hint that only said to
/// check validity first changed nothing when the prompt was replayed. Naming the query's
/// first word and whether it is a Cypher clause - a fact NetGet can read off the text, and no
/// substitute for Neo4j's parser - turned five replayed seeds in five into the syntax error,
/// while a MATCH under the same hint still got its rows.
///
/// A first version gave "a write they forbid" as an example of a refusal, and in the eval the
/// model refused `SELECT name FROM people` with `Neo.ClientError.Security.Forbidden` "Write
/// operations are not allowed" five runs in five: cypher-shell sends every query with `mode`
/// write, and the example turned that field into a reason. The hint says what `mode` is.
///
/// "Fields are the names after RETURN" was not enough for an aliased item: asked
/// `MATCH (m:Movie) RETURN count(m) AS movies`, llama3.1:8b named the column `count(m)` or
/// `count` on 13 replayed seeds in 20 (the record often keyed `movies` all the same, which the
/// executor refuses), so cypher-shell printed no `movies` column. With the columns read off the
/// query by [`return_columns`] and named exactly, all 20 named it `movies`
/// (`eval-results/2026-11-08-weak-cases-replay/`).
pub fn query_answer_with(query: &str) -> String {
    let first = query
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|w| !w.is_empty())
        .unwrap_or("")
        .to_ascii_uppercase();
    let fact = if first.is_empty() {
        "This query is empty.".to_string()
    } else if CYPHER_LEADING_CLAUSES.contains(&first.as_str()) {
        format!("This query begins with {first}, a Cypher clause.")
    } else {
        format!("This query begins with {first}, which is not a Cypher clause.")
    };
    let fields = match return_columns(query) {
        Some(columns) => format!(
            "exactly {} - the column names after RETURN, an AS alias where there is one -",
            serde_json::to_string(&columns).unwrap_or_default()
        ),
        None => "the names after RETURN".to_string(),
    };
    format!(
        "first hold the query against your instructions. If they refuse it - for instance \
         because it is not valid Cypher - answer send_bolt_failure with the Neo4j code that \
         says why (Neo.ClientError.Statement.SyntaxError for invalid Cypher). {fact} 'mode' \
         is only the access mode the client asked for (cypher-shell asks for write on every \
         query), never a reason to refuse unless your instructions forbid writes. Otherwise \
         answer send_bolt_records whose fields are {fields} and whose rows are what your \
         instructions say the graph holds"
    )
}

/// The column names a query's final `RETURN` gives its result, as Neo4j names them: an item's
/// `AS` alias where it has one, otherwise the item's text as written (`p.name`, `count(m)`).
///
/// Read off the text the way `CYPHER_LEADING_CLAUSES` reads the first word - a fact the model
/// is handed, not a parse of Cypher. `None` whenever the answer is not plain: no top-level
/// `RETURN`, `RETURN *`, an unbalanced bracket or quote, or an item with nothing in it. The
/// last top-level `RETURN` is the one whose columns the client receives (an earlier one belongs
/// to a `CALL { ... }` subquery or a `UNION` branch with the same columns).
pub fn return_columns(query: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = query.chars().collect();
    // Byte-free scan over chars: depth 0 positions outside strings, comments and backticks.
    let mut top = vec![false; chars.len()];
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == '\\' && q != '`' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => top[i] = depth == 0,
        }
        i += 1;
    }
    if quote.is_some() || depth != 0 {
        return None;
    }
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_';
    // Top-level keyword occurrences, as char offsets.
    let keyword_at = |kw: &str, at: usize| -> bool {
        let n = kw.chars().count();
        at + n <= chars.len()
            && (0..n).all(|k| top[at + k])
            && chars[at..at + n]
                .iter()
                .zip(kw.chars())
                .all(|(a, b)| a.to_ascii_uppercase() == b)
            && (at == 0 || !is_word_char(chars[at - 1]))
            && (at + n == chars.len() || !is_word_char(chars[at + n]))
    };
    let start = (0..chars.len())
        .rev()
        .find(|&at| keyword_at("RETURN", at))?
        + "RETURN".len();
    let end = (start..chars.len())
        .find(|&at| {
            ["ORDER", "SKIP", "LIMIT", "UNION"]
                .iter()
                .any(|kw| keyword_at(kw, at))
                || (top[at] && chars[at] == ';')
        })
        .unwrap_or(chars.len());
    let mut body_start = start;
    while body_start < end && chars[body_start].is_whitespace() {
        body_start += 1;
    }
    if keyword_at("DISTINCT", body_start) {
        body_start += "DISTINCT".len();
    }
    let mut columns = Vec::new();
    let mut item_start = body_start;
    for at in body_start..=end {
        if at == end || (top[at] && chars[at] == ',') {
            let item_end = at;
            let alias_at = (item_start..item_end).rev().find(|&k| keyword_at("AS", k));
            let name: String = match alias_at {
                Some(k) => chars[k + 2..item_end].iter().collect(),
                None => chars[item_start..item_end].iter().collect(),
            };
            let name = name.trim();
            let name = name
                .strip_prefix('`')
                .and_then(|n| n.strip_suffix('`'))
                .unwrap_or(name);
            if name.is_empty() || name == "*" {
                return None;
            }
            columns.push(name.to_string());
            item_start = at + 1;
        }
    }
    (!columns.is_empty()).then_some(columns)
}

/// RUN: one Cypher query.
pub static BOLT_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bolt_query",
        "A client ran a Cypher query against the graph database. Answer with the rows it \
         returns (send_bolt_records) or the Neo4j error it fails with (send_bolt_failure).",
        json!({
            "type": "send_bolt_records",
            "fields": ["name"],
            "records": [["Alice"], ["Bob"]]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The Cypher text".to_string(),
            required: true,
        },
        Parameter {
            name: "parameters".to_string(),
            type_hint: "object".to_string(),
            description: "The query's $parameters by name".to_string(),
            required: true,
        },
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "The database the client named, when it named one".to_string(),
            required: false,
        },
        Parameter {
            name: "mode".to_string(),
            type_hint: "string".to_string(),
            description: "read or write: the access mode the client asked for".to_string(),
            required: true,
        }
        .with_choices(["read", "write"]),
        Parameter {
            name: "in_transaction".to_string(),
            type_hint: "boolean".to_string(),
            description: "True inside an explicit BEGIN ... COMMIT transaction".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which answer this query takes: send_bolt_failure when the \
                          instructions refuse it, its rows otherwise - with the query's first \
                          word and whether that is a Cypher clause"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Bolt query: {query}")
            .with_debug("Bolt bolt_query: query={query} mode={mode}"),
    )
    .with_actions(vec![
        send_bolt_records_action(),
        send_bolt_failure_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_bolt_failure",
        "code": "Neo.ClientError.Statement.SyntaxError",
        "message": "Invalid input 'RETRUN': expected 'RETURN' (line 1, column 1 (offset: 0))"
    }))
});
