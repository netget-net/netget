use super::codec::{
    self, AccountReply, AccountStatus, AuthReply, AuthStatus, AuthorReply, AuthorStatus,
};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType, SpawnContext,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct TacacsProtocol;
impl TacacsProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(crate::protocol::log_template::LogTemplate::new().with_info(
            match name {
                "respond_tacacs_authentication" => "TACACS+ terminal authentication reply",
                "respond_tacacs_authorization" => {
                    "TACACS+ authorization reply, {reply.arguments_len} arguments"
                }
                "record_tacacs_accounting" => "TACACS+ volatile accounting reply",
                "authenticate_tacacs" => "TACACS+ authentication requested in a fresh session",
                "authorize_tacacs" => {
                    "TACACS+ authorization requested, {request.arguments_len} arguments"
                }
                "account_tacacs" => {
                    "TACACS+ accounting requested, {request.arguments_len} arguments"
                }
                "disconnect" => "TACACS+ disconnect and cancel pending work",
                _ => "TACACS+ typed action",
            },
        )),
    }
}
fn authentication() -> ActionDefinition {
    action("respond_tacacs_authentication","Give the terminal ASCII/PAP LOGIN verdict; no built-in accounts or identity backend. Default FAIL. Native transport supplies prompts and session correlation.",vec![parameter("reply","object","status:pass|fail|error; optional server_message/data printable ASCII<=1024bytes. no_echo false for terminal replies.",true)],json!({"type":"respond_tacacs_authentication","reply":{"status":"fail"}}))
}
fn authorization() -> ActionDefinition {
    action("respond_tacacs_authorization","Choose PASS_ADD/PASS_REPLACE/FAIL/ERROR and ordered typed arguments. No automatic binding to a previous authentication session; no device policy store.",vec![parameter("reply","object","status:pass_add|pass_replace|fail|error; optional arguments:[{name,value,mandatory(defaulttrue)}],server_message,data.<=32args,eachwire<=255ASCIIbytes; message/data<=1024.",true)],json!({"type":"respond_tacacs_authorization","reply":{"status":"fail"}}))
}
fn accounting() -> ActionDefinition {
    action("record_tacacs_accounting","Record this validated accounting request in the bounded shared volatile access log before a SUCCESS reply. Does not persist, bill or retain records beyond common log eviction/process loss. Default ERROR.",vec![parameter("reply","object","status:success|error; optional printable ASCII server_message/data<=1024bytes.",true)],json!({"type":"record_tacacs_accounting","reply":{"status":"error"}}))
}
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_authentication","Selected legacy ASCII/PAP credentials after native bounded prompts. Password is supplied only to the chosen common handler; use deterministic rules for actual credential policy.",authentication().example.clone()).with_parameters(vec![parameter("request","object","username,password,method,privilege_level,port,remote_address,source_addr,session_id. Transport shared secret never appears.",true)]).with_actions(vec![authentication()])
});
pub static AUTHOR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_authorization","A separate authorization session with context and ordered mandatory/optional arguments; no asserted authentication binding.",authorization().example.clone()).with_parameters(vec![parameter("request","object","authentication_method,authentication_type,service,privilege_level,username,port,remote_address,arguments,source_addr,session_id",true)]).with_actions(vec![authorization()])
});
pub static ACCOUNT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_accounting","START/STOP/WATCHDOG/UPDATE accounting record; SUCCESS only after bounded shared access recording, not durability.",accounting().example.clone()).with_parameters(vec![parameter("request","object","record_type plus typed authorization context and ordered arguments,source_addr,session_id",true)]).with_actions(vec![accounting()])
});
pub fn duration_parameter(name: &str, default: u64, description: &str) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "number".into(),
        description: description.into(),
        required: false,
        example: json!(default),
        default: Some(json!(default)),
    }
}
pub fn secret_parameter() -> ParameterDefinition {
    ParameterDefinition{name:"shared_secret".into(),type_hint:"string".into(),description:"Required nonempty1..255UTF8bytes for legacy MD5 body obfuscation; no integrity or secure transport. Startup-only; never emitted in events.".into(),required:true,example:json!("replace-with-a-unique-client-secret"),default:None}
}
pub fn reply(action: &Value) -> Result<Value> {
    ensure!(codec::within_json_budget(action), "TACACS JSON budget");
    ensure!(
        action
            .as_object()
            .is_some_and(|m| m.len() == 2 && m.contains_key("type") && m.contains_key("reply")),
        "only type/reply accepted"
    );
    Ok(action["reply"].clone())
}
impl Protocol for TacacsProtocol {
    fn protocol_name(&self) -> &'static str {
        "TACACS"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TACACS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["tacacs", "tacacs+"]
    }
    fn description(&self) -> &'static str {
        "Selected legacy TACACS+ ASCII/PAP login, authorization and volatile accounting"
    }
    fn example_prompt(&self) -> &'static str {
        "Run a legacy TACACS+ endpoint with deterministic denial policy"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![authentication(), authorization(), accounting()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            AUTH_EVENT.clone(),
            AUTHOR_EVENT.clone(),
            ACCOUNT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![secret_parameter(),ParameterDefinition{name:"client_secrets".into(),type_hint:"array".into(),description:"Optional exact-IP overrides:[{client_ip,shared_secret}],<=64unique addresses. Immutable transport configuration; no CIDR or secret rotation.".into(),required:false,example:json!([]),default:Some(json!([]))},duration_parameter("io_timeout_seconds",codec::DEFAULT_IO_SECONDS,"Whole packet read deadline1..300seconds; includes a peer that sends no first byte"),duration_parameter("handler_timeout_seconds",codec::DEFAULT_HANDLER_SECONDS,"Common handler deadline1..300seconds, including manual interception"),ParameterDefinition{name:"llm_fallback".into(),type_hint:"boolean".into(),description:"Opt unmatched credential/AAA events into model calls; explicit handlers always run. Defaultfalse denies authentication/authorization and errors accounting.".into(),required:false,example:json!(true),default:Some(json!(codec::DEFAULT_LLM_FALLBACK))}]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(49).request_only("TACACS+ packets answer a pending AAA session; no unsolicited peer message API").max_inbound_bytes(codec::MAX_BODY_BYTES+12).implementation("Native bounded RFC8907 legacy TCP header, MD5 chained body obfuscation and typed selected AAA bodies; existing md-5 only")
 .llm_control("Common static/script/manual/model verdicts and shared memory; native ASCII prompts; llm_fallback=false denies unmatched authentication/authorization and errors accounting")
 .e2e_testing("Required pinned unmodified nwaples/tacplus0.0.3 SDK-backed client/server plus Python tacacs_plus2.6; exact real wire golden fixtures, failures, bounds, deadlines and cancellation")
 .notes("Experimental selected RFC8907 legacy scope, not full RFC compliance. TCP49 only; obfuscation is not encryption, integrity or secure transport. RFC9887 TLS1.3/mutual certificates/port300 excluded. One session per TCP connection, SINGLE_CONNECT declined, unknown header flag bits ignored, unencrypted flag refused; cryptographic client session IDs, strict session/type/version/odd-even sequence and no wrapping. ASCII LOGIN GETUSER up to3 retries/GETPASS and PAP LOGIN minor1 only; no CHAP/MSCHAP, ENABLE, change-password, SENDPASS/SENDAUTH, RESTART retry, FOLLOW redirect or multiplexing. Printable ASCII subset, username no spaces; full PRECIS/Unicode excluded.16KiB bodies,32ordered args,255byte short fields,1024byte messages/data,8authentication rounds,256connections;30spacket/handler default configurable1..300s,10swrite. Default FAIL/FAIL/ERROR; handler failures/multiple or wrong reply types ERROR before acceptance. Accounting SUCCESS records in common bounded volatile access log before reply; eviction and process loss apply, no durable storage, journal, billing or exactly-once claim. No account/policy domain store or authentication-to-authorization binding. Authentication password is typed chosen-handler input and follows the common access-log retention; startup shared secrets never enter events. Per-client exact-IP secrets supported; no CIDR/rotation. No fuzz/production-capture claim.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
 .batching(crate::protocol::metadata::BatchingMode::Unsupported)
 .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"tacacs","port":49,"startup_params":{"shared_secret":"replace-with-a-unique-client-secret"}});
        let mut llm = base.clone();
        llm["startup_params"]["llm_fallback"] = json!(true);
        llm["instruction"] =
            json!("Deny every authentication and authorization; error accounting unless recorded");
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"tacacs_authentication","handler":{"type":"script","language":"python","code":"import json,sys\nx=json.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'respond_tacacs_authentication','reply':{'status':'fail'}}]}))"}}]);
        let mut deterministic = base;
        deterministic["event_handlers"] = json!([{"event_pattern":"tacacs_authentication","handler":{"type":"static","actions":[authentication().example]}},{"event_pattern":"tacacs_authorization","handler":{"type":"static","actions":[authorization().example]}},{"event_pattern":"tacacs_accounting","handler":{"type":"static","actions":[accounting().example]}}]);
        StartupExamples::new(llm, script, deterministic)
    }
}
impl Server for TacacsProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::TacacsServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action = codec::owned_json(action)?;
        let v = reply(&action)?;
        match action["type"].as_str() {
            Some("respond_tacacs_authentication") => {
                let r: AuthReply = serde_json::from_value(v.clone())?;
                ensure!(
                    matches!(
                        r.status,
                        AuthStatus::Pass | AuthStatus::Fail | AuthStatus::Error
                    ) && !r.no_echo,
                    "only terminal verdicts"
                );
                codec::auth_reply_body(&r)?;
            }
            Some("respond_tacacs_authorization") => {
                let r: AuthorReply = serde_json::from_value(v.clone())?;
                ensure!(r.status != AuthorStatus::Follow, "FOLLOW excluded");
                codec::author_reply_body(&r)?;
            }
            Some("record_tacacs_accounting") => {
                let r: AccountReply = serde_json::from_value(v.clone())?;
                ensure!(r.status != AccountStatus::Follow, "FOLLOW excluded");
                codec::account_reply_body(&r)?;
            }
            _ => bail!("Unknown TACACS server action"),
        };
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap().into(),
            data: v,
        })
    }
}
