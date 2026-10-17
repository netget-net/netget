use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ManageSieveProtocol;
impl ManageSieveProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("ManageSieve {name}"))),
    }
}

/// Response codes a handler may put on NO (and WARNINGS on OK), RFC 5804 section 1.3.
pub const CODES: &[&str] = &[
    "NONEXISTENT",
    "ACTIVE",
    "ALREADYEXISTS",
    "QUOTA",
    "QUOTA/MAXSCRIPTS",
    "QUOTA/MAXSIZE",
    "TRYLATER",
    "AUTH-TOO-WEAK",
    "ENCRYPT-NEEDED",
];

fn ok() -> ActionDefinition {
    action(
        "managesieve_ok",
        "Succeed: accept the login, or the PUTSCRIPT, CHECKSCRIPT, SETACTIVE, DELETESCRIPT, RENAMESCRIPT or HAVESPACE command",
        vec![
            parameter("message", "string", "Human-readable text after OK", false),
            parameter("warnings", "boolean", "Mark the OK with the WARNINGS code (a script was accepted with warnings in message)", false),
        ],
        json!({"type": "managesieve_ok"}),
    )
}
fn no() -> ActionDefinition {
    action(
        "managesieve_no",
        "Fail the login or command with a message and optionally a response code: NONEXISTENT, ACTIVE, ALREADYEXISTS, QUOTA, QUOTA/MAXSCRIPTS, QUOTA/MAXSIZE, TRYLATER",
        vec![
            parameter("message", "string", "Why, e.g. a script's syntax error", true),
            parameter("code", "string", "Response code, e.g. NONEXISTENT", false),
        ],
        json!({"type": "managesieve_no", "code": "NONEXISTENT", "message": "There is no script by that name"}),
    )
}
fn scripts() -> ActionDefinition {
    action(
        "managesieve_scripts",
        "Answer LISTSCRIPTS with the user's scripts and which one (at most one) is active",
        vec![parameter("scripts", "array", "[{name, active}]", true)],
        json!({"type": "managesieve_scripts", "scripts": [{"name": "vacation", "active": true}, {"name": "spam"}]}),
    )
}
fn script() -> ActionDefinition {
    action(
        "managesieve_script",
        "Answer GETSCRIPT with the script's text",
        vec![parameter("script", "string", "The Sieve script", true)],
        json!({"type": "managesieve_script", "script": "require \"fileinto\";\nfileinto \"Junk\";\n"}),
    )
}

fn answers() -> Vec<ActionDefinition> {
    vec![ok(), no(), scripts(), script()]
}

pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "managesieve_auth",
        "A client authenticated with SASL PLAIN; accept or refuse the credentials",
        ok().example.clone(),
    )
    .with_parameters(vec![
        parameter("user", "string", "The authentication identity", true),
        parameter("password", "string", "The password the client gave", true),
        parameter(
            "authorize_as",
            "string",
            "The authorization identity, when it differs",
            false,
        ),
    ])
    .with_actions(vec![ok(), no()])
});

pub static COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "managesieve_command",
        "An authenticated user sent a script command. LISTSCRIPTS wants managesieve_scripts, GETSCRIPT wants managesieve_script, the rest managesieve_ok; any of them may get managesieve_no.",
        scripts().example.clone(),
    )
    .with_parameters(vec![
        parameter("user", "string", "The logged-in user", true),
        parameter("command", "string", "LISTSCRIPTS, GETSCRIPT, PUTSCRIPT, CHECKSCRIPT, SETACTIVE, DELETESCRIPT, RENAMESCRIPT or HAVESPACE", true),
        parameter("name", "string", "The script name (empty for SETACTIVE means deactivate)", false),
        parameter("new_name", "string", "RENAMESCRIPT's new name", false),
        parameter("script", "string", "PUTSCRIPT's or CHECKSCRIPT's script text", false),
        parameter("size", "number", "HAVESPACE's size in bytes", false),
    ])
    .with_actions(answers())
});

impl Protocol for ManageSieveProtocol {
    fn protocol_name(&self) -> &'static str {
        "ManageSieve"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ManageSieve"
    }
    fn description(&self) -> &'static str {
        "ManageSieve (RFC 5804) server: users log in and list, upload, check, activate, rename and delete Sieve scripts; the handler keeps the scripts"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["managesieve", "sieve", "rfc5804", "mail filter"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        answers()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![AUTH_EVENT.clone(), COMMAND_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "sieve_extensions".into(),
                type_hint: "string".into(),
                description: "Space-separated SIEVE capability the greeting advertises".into(),
                required: false,
                example: json!("fileinto vacation"),
                default: Some(json!(super::DEFAULT_EXTENSIONS)),
            },
            ParameterDefinition {
                name: "implementation".into(),
                type_hint: "string".into(),
                description: "IMPLEMENTATION capability text".into(),
                required: false,
                example: json!("Example Sieve server"),
                default: Some(json!(super::DEFAULT_IMPLEMENTATION)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(4190)
            .implementation("Native RFC 5804 line and literal parser over Tokio TCP; capabilities, SASL PLAIN (initial response or continuation), name and UTF-8 checks, response codes and literals are Rust's")
            .llm_control("Who may log in, and every script command's answer: the script list, script text, and acceptance or refusal with a response code")
            .e2e_testing("tests/server/managesieve: sievelib 1.5.0 (independent, Python) logs in and lists, uploads, reads, checks, activates, renames and deletes scripts; a wrong password is refused")
            .notes("No STARTTLS (not advertised) and no SASL mechanism but PLAIN. Scripts are not parsed by NetGet: the handler accepts or refuses them. No storage: the handler keeps scripts in memory or SQLite. 8 KiB lines, 1 MiB scripts, 3 failed logins, 300 s idle.")
            .request_only("ManageSieve answers each command; the server sends nothing unprompted")
            .answers_on_failure()
            .max_inbound_bytes(super::proto::MAX_LITERAL)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ManageSieve server on port 4190 where alice/secret keeps her Sieve scripts"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"managesieve","port":4190,"instruction":"alice/secret may log in; keep her scripts in memory"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"managesieve_auth","handler":{"type":"static","actions":[{"type":"managesieve_ok"}]}},
            {"event_pattern":"managesieve_command","handler":{"type":"static","actions":[{"type":"managesieve_scripts","scripts":[]}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\ne=i['event']\nif i['event_type_id']=='managesieve_auth':\n    a={'type':'managesieve_ok'} if (e['user'],e['password'])==('alice','secret') else {'type':'managesieve_no','message':'bad credentials'}\nelif e['command']=='LISTSCRIPTS':\n    a={'type':'managesieve_scripts','scripts':[]}\nelif e['command']=='GETSCRIPT':\n    a={'type':'managesieve_no','code':'NONEXISTENT','message':'no such script'}\nelse:\n    a={'type':'managesieve_ok'}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for ManageSieveProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let text = |k: &str, max: usize| -> Result<()> {
            if let Some(x) = v.get(k).filter(|x| !x.is_null()) {
                ensure!(
                    x.as_str().is_some_and(|s| s.len() <= max),
                    "{k} is text up to {max} bytes"
                );
            }
            Ok(())
        };
        match v["type"].as_str() {
            Some("managesieve_ok") => text("message", 4096)?,
            Some("managesieve_no") => {
                text("message", 4096)?;
                ensure!(v["message"].is_string(), "message says why");
                if let Some(c) = v.get("code").filter(|c| !c.is_null()) {
                    ensure!(
                        c.as_str().is_some_and(|c| CODES.contains(&c)),
                        "code is one of {}",
                        CODES.join(", ")
                    );
                }
            }
            Some("managesieve_scripts") => {
                let list = v["scripts"].as_array().filter(|a| a.len() <= 1024);
                let Some(list) = list else {
                    bail!("scripts is an array of up to 1024 {{name, active}}")
                };
                ensure!(
                    list.iter().all(|s| s["name"]
                        .as_str()
                        .is_some_and(|n| super::proto::valid_name(n.as_bytes()))),
                    "each script has a valid name"
                );
                ensure!(
                    list.iter().filter(|s| s["active"] == true).count() <= 1,
                    "at most one script is active"
                );
            }
            Some("managesieve_script") => {
                text("script", super::proto::MAX_LITERAL).and_then(|_| {
                    ensure!(v["script"].is_string(), "script is the script text");
                    Ok(())
                })?
            }
            _ => bail!("Unknown ManageSieve server action"),
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
