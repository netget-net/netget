use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::managesieve::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ManageSieveClientProtocol;
impl ManageSieveClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn name() -> Parameter {
    parameter("name", "string", "The script name", true)
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        action("managesieve_list", "LISTSCRIPTS: the user's scripts and which is active", vec![], json!({"type": "managesieve_list"})),
        action("managesieve_get", "GETSCRIPT: fetch a script's text", vec![name()], json!({"type": "managesieve_get", "name": "vacation"})),
        action(
            "managesieve_put",
            "PUTSCRIPT: upload (or replace) a script; the server validates it and may refuse it with its errors",
            vec![name(), parameter("script", "string", "The Sieve script text", true)],
            json!({"type": "managesieve_put", "name": "spam", "script": "require \"fileinto\";\nif header :contains \"subject\" \"[SPAM]\" { fileinto \"Junk\"; }\n"}),
        ),
        action(
            "managesieve_check",
            "CHECKSCRIPT: have the server validate a script without storing it",
            vec![parameter("script", "string", "The Sieve script text", true)],
            json!({"type": "managesieve_check", "script": "keep;\n"}),
        ),
        action(
            "managesieve_set_active",
            "SETACTIVE: make a script the active one (an empty name deactivates all)",
            vec![parameter("name", "string", "The script to activate, or empty", true)],
            json!({"type": "managesieve_set_active", "name": "spam"}),
        ),
        action("managesieve_delete", "DELETESCRIPT: delete a script (the server refuses the active one)", vec![name()], json!({"type": "managesieve_delete", "name": "old"})),
        action(
            "managesieve_rename",
            "RENAMESCRIPT: rename a script",
            vec![name(), parameter("new_name", "string", "The new script name", true)],
            json!({"type": "managesieve_rename", "name": "spam", "new_name": "junk"}),
        ),
        action(
            "managesieve_have_space",
            "HAVESPACE: ask whether a script of this size may be stored under this name",
            vec![name(), parameter("size", "number", "The script size in bytes", true)],
            json!({"type": "managesieve_have_space", "name": "big", "size": 100000}),
        ),
        action("disconnect", "LOGOUT and close the connection", vec![], json!({"type": "disconnect"})),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "managesieve_connected",
        "Logged in to the ManageSieve server",
        json!({"type": "managesieve_list"}),
    )
    .with_parameters(vec![
        parameter(
            "implementation",
            "string",
            "The server's IMPLEMENTATION capability",
            false,
        ),
        parameter(
            "sieve_extensions",
            "array",
            "The Sieve extensions the server supports",
            true,
        ),
        parameter(
            "capabilities",
            "object",
            "Every capability the server announced",
            true,
        ),
    ])
    .with_actions(all_actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "managesieve_response",
        "The server answered a command",
        json!({"type": "managesieve_list"}),
    )
    .with_parameters(vec![
        parameter(
            "command",
            "string",
            "The command answered, e.g. PUTSCRIPT",
            true,
        ),
        parameter("status", "string", "OK when the command succeeded, NO when the server refused it, BYE when it is closing the connection", true),
        parameter(
            "code",
            "string",
            "The response code, e.g. NONEXISTENT or WARNINGS",
            false,
        ),
        parameter(
            "message",
            "string",
            "The server's text, e.g. a script's syntax errors",
            false,
        ),
        parameter(
            "scripts",
            "array",
            "For LISTSCRIPTS: [{name, active}]",
            false,
        ),
        parameter("script", "string", "For GETSCRIPT: the script text", false),
    ])
    .with_actions(all_actions())
});

impl Protocol for ManageSieveClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ManageSieve"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ManageSieve"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["managesieve", "managesieve client", "sieve scripts"]
    }
    fn description(&self) -> &'static str {
        "ManageSieve client: logs in and manages a user's Sieve scripts on a server"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p = |n: &str, d: &str, required: bool, example: Value| ParameterDefinition {
            name: n.into(),
            type_hint: "string".into(),
            description: d.into(),
            required,
            example,
            default: None,
        };
        vec![
            p(
                "user",
                "The user to log in as (SASL PLAIN)",
                true,
                json!("alice"),
            ),
            p("password", "The user's password", true, json!("secret")),
            p(
                "authorize_as",
                "An authorization identity other than the user",
                false,
                json!("bob"),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's RFC 5804 parser as a client: greeting capabilities, SASL PLAIN with an initial response, non-synchronizing literals for scripts")
            .llm_control("Which scripts to list, read, upload, check, activate, rename and delete")
            .e2e_testing("tests/client/managesieve: Dovecot 2.4.5 with Pigeonhole 2.4.5 (independent, C), which compiles every uploaded script")
            .notes("No STARTTLS: use it only on trusted networks. One command at a time.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Log in to the ManageSieve server at 127.0.0.1:4190 as alice and install a spam filter"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"managesieve","remote_addr":"127.0.0.1:4190","instruction":"List my scripts","startup_params":{"user":"alice","password":"secret"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"managesieve_connected","handler":{"type":"static","actions":[{"type":"managesieve_list"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"managesieve_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'managesieve_put','name':'keep','script':'keep;\\n'},{'type':'managesieve_set_active','name':'keep'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for ManageSieveClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let has = |k: &str| v[k].as_str().is_some();
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("managesieve_list") => {}
            Some("managesieve_get" | "managesieve_delete" | "managesieve_set_active") => {
                ensure!(has("name"), "name is the script name")
            }
            Some("managesieve_put") => {
                ensure!(has("name") && has("script"), "name and script are required")
            }
            Some("managesieve_check") => ensure!(has("script"), "script is required"),
            Some("managesieve_rename") => ensure!(
                has("name") && has("new_name"),
                "name and new_name are required"
            ),
            Some("managesieve_have_space") => ensure!(
                has("name") && v["size"].as_u64().is_some(),
                "name and size are required"
            ),
            _ => bail!("Unknown ManageSieve client action"),
        }
        if let Some(s) = v["script"].as_str() {
            ensure!(
                s.len() <= crate::server::managesieve::proto::MAX_LITERAL,
                "the script is over 1 MiB"
            );
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
