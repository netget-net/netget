use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, Parameter, ParameterDefinition,
    },
    protocol::{ConnectContext, EventType},
    state::AppState,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct BoltClientProtocol;
impl BoltClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn a(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let intent = match name {
        "bolt_login" => "request native authentication; await acknowledgement",
        "bolt_logoff" => "request native logoff; await acknowledgement",
        "bolt_run" => "submit one query; await result field metadata",
        "bolt_pull" => "request a bounded result page; await completion",
        "bolt_discard" => "discard remaining results; await completion",
        "bolt_begin" => "request an explicit transaction; await acknowledgement",
        "bolt_commit" => "request transaction commit; await acknowledgement",
        "bolt_rollback" => "request transaction rollback; await acknowledgement",
        "bolt_reset" => "request session recovery; await acknowledgement",
        "disconnect" => "close the connection and cancel pending I/O",
        _ => unreachable!("only declared Bolt actions receive a log template"),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_debug(format!("Bolt {name}: {intent}")),
        ),
    }
}
fn tx_parameters() -> Vec<Parameter> {
    vec![p("database","string","Optional database; omission leaves native default",false),p("mode","string","read or write; native default write",false),p("transaction_timeout_ms","integer","Optional server transaction timeout1..30000ms, separate from client whole-operation deadline",false),p("bookmarks","array","Up to16 native opaque causal bookmarks; no local causal guarantee",false)]
}
pub fn actions() -> Vec<ActionDefinition> {
    let mut run=vec![p("query","string","Unmodified Cypher text, at most64KiB",true),p("parameters","object","Plain JSON parameter map with signed64-bit integers; graph, temporal, spatial and byte input types excluded",false)];
    run.extend(tx_parameters());
    vec![
        a("bolt_login","Authenticate basic credentials, or none when both fields are omitted. Sends LOGON only in the authentication phase and Bolt5.1+.",vec![p("username","string","Basic principal; username and password must appear together",false),p("password","string","Bounded password, never returned in events or incidental diagnostics",false)],json!({"type":"bolt_login","username":"neo4j","password":"fixture-password"})),
        a("bolt_logoff","Native LOGOFF from READY, Bolt5.1+; no token file or backend password change",vec![],json!({"type":"bolt_logoff"})),
        a("bolt_run","RUN one query. A native SUCCESS establishes field order and one cursor; it does not complete or commit the query. Inside an explicit transaction, database/mode/bookmarks/timeout overrides are refused.",run,json!({"type":"bolt_run","query":"RETURN $name AS name","parameters":{"name":"Alice"},"mode":"read"})),
        a("bolt_pull","PULL1..500 records (default100). Emits one complete page only after native SUCCESS; has_more keeps the cursor. Never requests unbounded PULL.",vec![p("n","integer","Record page count1..500",false)],json!({"type":"bolt_pull","n":100})),
        a("bolt_discard","DISCARD all remaining records without exposing them; native completion summary is required",vec![],json!({"type":"bolt_discard"})),
        a("bolt_begin","BEGIN one explicit transaction; one open result at a time",tx_parameters(),json!({"type":"bolt_begin","mode":"read"})),
        a("bolt_commit","COMMIT only after the result was consumed/discarded; native SUCCESS acknowledges the commit and may carry bookmark",vec![],json!({"type":"bolt_commit"})),
        a("bolt_rollback","Native ROLLBACK after the result was consumed/discarded",vec![],json!({"type":"bolt_rollback"})),
        a("bolt_reset","Native RESET between operations, including failure recovery. Ends local transaction/cursor only after SUCCESS; pending-operation cancellation uses disconnect",vec![],json!({"type":"bolt_reset"})),
        a("disconnect","Send best-effort GOODBYE when idle and close; cancel owned pending I/O immediately",vec![],json!({"type":"disconnect"})),
    ]
}
fn event(id: &str, description: &str, parameters: Vec<Parameter>) -> EventType {
    let example = match id {
        "bolt_connected" => json!({"type":"bolt_login"}),
        "bolt_authentication" => json!({"type":"bolt_run","query":"RETURN 42 AS answer"}),
        "bolt_query_started" => json!({"type":"bolt_pull","n":100}),
        "bolt_failure" => json!({"type":"bolt_reset"}),
        _ => json!({"type":"disconnect"}),
    };
    EventType::new(id, description, example)
        .with_parameters(parameters)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("bolt_connected","Native connection, negotiated Bolt version and validated HELLO; authentication status is separate",vec![p("endpoint","string","Selected direct Bolt endpoint",true),p("version","string","Negotiated5.x version",true),p("server","object","Native HELLO metadata",true),p("authentication_verified","boolean","Only true after native authentication SUCCESS",true),p("authentication_metadata","object|null","Native startup LOGON metadata only when performed;5.0 auth metadata remains in server HELLO metadata",true),p("phase","string","authentication or ready",true)])
});
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bolt_authentication",
        "Native LOGON/LOGOFF acknowledgement; credentials excluded",
        vec![
            p("operation", "string", "login or logoff", true),
            p(
                "authentication_verified",
                "boolean",
                "Native login SUCCESS; false after LOGOFF",
                true,
            ),
            p(
                "metadata",
                "object",
                "Native advertised address or credentials-expired flag, if provided",
                true,
            ),
            p("phase", "string", "Current local protocol phase", true),
        ],
    )
});
pub static RUN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bolt_query_started",
        "RUN SUCCESS established field order and one result cursor; no completion inferred",
        vec![
            p(
                "fields",
                "array",
                "Native ordered field names, including repeated/empty names if a peer sends them",
                true,
            ),
            p(
                "qid",
                "integer|null",
                "Native explicit transaction cursor identifier, optional in auto-commit",
                true,
            ),
            p(
                "metadata",
                "object",
                "Native RUN metadata; timing units milliseconds",
                true,
            ),
            p(
                "in_transaction",
                "boolean",
                "Explicit transaction active",
                true,
            ),
        ],
    )
});
pub static PAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("bolt_result_page","Complete native PULL page or DISCARD receipt, emitted only after SUCCESS",vec![p("operation","string","pull or discard",true),p("fields","array","Ordered field names; records are positional arrays",true),p("records","array","Validated values: primitives/list/map, typed graph/temporal/spatial objects. Byte content omitted with length; nonfinite floats named explicitly",true),p("has_more","boolean","Native flag, false when absent",true),p("summary","object","Native metadata including type r/w/rw/s, stats, bookmark, database, timings or statuses when present; no fields invented",true),p("in_transaction","boolean","Explicit transaction remains active",true)])
});
pub static TX_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bolt_session_result",
        "Native BEGIN/COMMIT/ROLLBACK/RESET SUCCESS",
        vec![
            p(
                "operation",
                "string",
                "begin, commit, rollback or reset",
                true,
            ),
            p(
                "metadata",
                "object",
                "Native acknowledgement metadata, including bookmark only when returned",
                true,
            ),
            p(
                "in_transaction",
                "boolean",
                "Local state after validated success",
                true,
            ),
            p("phase", "string", "Current protocol phase", true),
        ],
    )
});
pub static FAILURE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("bolt_failure","Native FAILURE or IGNORED. Tentative records are omitted and query failures require RESET",vec![p("operation","string","Selected operation",true),p("ignored","boolean","True only for native IGNORED",true),p("failure","object|null","Pre5.7 code/message;5.7+ neo4j_code/gql_status/description/diagnostic_record/cause. Credential reflections redacted",true),p("records_discarded","integer","Tentative records withheld before failure",true),p("phase","string","failed, or defunct for authentication/logoff/reset failure",true)])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bolt_request_error",
        "Local selected action refusal; terminal transport/schema/deadline failures update client status",
        vec![
            p(
                "category",
                "string",
                "The action category identifies a local refusal before any wire message",
                true,
            ),
            p(
                "error",
                "string",
                "Fixed bounded category text; no credential or peer payload",
                true,
            ),
            p(
                "backend_outcome",
                "string",
                "not_sent; the refused action produced no wire message",
                true,
            ),
        ],
    )
});
impl Protocol for BoltClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "bolt"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BOLT"
    }
    fn description(&self) -> &'static str {
        "Selected negotiated Neo4j-compatible queries and bounded result pages"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bolt", "neo4j", "cypher", "graph"]
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn example_prompt(&self) -> &'static str {
        "Query a Neo4j-compatible Bolt service and report native results and failures"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            AUTH_EVENT.clone(),
            RUN_EVENT.clone(),
            PAGE_EVENT.clone(),
            TX_EVENT.clone(),
            FAILURE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition{name:"username".into(),type_hint:"string".into(),description:"Optional basic startup username; requires password. With neither,5.1+ waits for a login action;5.0 uses HELLO none authentication.".into(),required:false,example:json!("neo4j"),default:None},
        ParameterDefinition{name:"password".into(),type_hint:"string".into(),description:"Optional bounded basic password, used during authentication and omitted from protocol events and incidental diagnostics.".into(),required:false,example:json!("fixture-password"),default:None},
        ParameterDefinition{name:"request_timeout_secs".into(),type_hint:"integer".into(),description:"Whole connection/handshake/HELLO and each selected operation deadline1..30 seconds; default15. No idle session deadline.".into(),required:false,example:json!(15),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))},
    ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(7687).implementation("Direct native Bolt5.0..5.4/5.6..5.8 legacy negotiation, selected authentication, Cypher RUN and bounded PULL/DISCARD, transactions and RESET").llm_control("Typed queries/JSON parameters/results/native errors, common memory, event handlers and injection; no local graph database").e2e_testing("tests/client/bolt: isolated official Neo4j Community peer and native cypher-shell, NetGet pair, handler/model paths, bounds/deadlines and owned cancellation; full existing server suite retained").notes("Native TCP and certificate-verified bolt+s; browser TCP only. One ordered operation/result cursor/explicit transaction, messages1MiB, page500records/4MiB, fields256, query/text64KiB, JSON/wire depth32/nodes65536/retained8MiB, map256/list10000 parameters, event/action queues8, injection queue16/followups4, deadline1..30s. Latest bounded password retained only to redact credential reflections; no credentials file or graph store. Records tentative until PULL SUCCESS. Native metadata remains optional and native failure codes/GQL cause are preserved with reflected credentials omitted. Timeout/transport failure closes with unknown backend outcome. No routing/neo4j URI/pool, handshake manifest, Bolt6/5.5, TLS trust overrides/client certificates, bearer/Kerberos/impersonation, temporal/spatial/graph/byte input values, unbounded PULL, multiple simultaneous result streams, pending RESET interruption, automatic reconnect/retry/replay or conformance claim. Existing server model-as-database behavior remains.").max_inbound_bytes(crate::server::bolt::packstream::MAX_MESSAGE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"bolt","base_stack":"bolt","remote_addr":"bolt://127.0.0.1:7687","instruction":"Authenticate anonymously if permitted, return42 as answer and consume one page"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([
            {"event_pattern":"bolt_connected","handler":{"type":"static","actions":[{"type":"bolt_login"}]}},
            {"event_pattern":"bolt_authentication","handler":{"type":"static","actions":[{"type":"bolt_run","query":"RETURN 42 AS answer"}]}},
            {"event_pattern":"bolt_query_started","handler":{"type":"static","actions":[{"type":"bolt_pull","n":100}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut script = fixed.clone();
        script["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\njson.dump({'actions':[{'type':'bolt_run','query':'RETURN 42 AS answer'}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for BoltClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        if !super::api::within_budget(&value) {
            crate::utils::json_budget::drop_iteratively(value);
            bail!("Bolt action depth/node/retained-content limit")
        }
        match super::api::action(&value)? {
            super::api::Action::Disconnect => Ok(ClientActionResult::Disconnect),
            _ => Ok(ClientActionResult::Custom {
                name: "bolt".into(),
                data: value,
            }),
        }
    }
}
