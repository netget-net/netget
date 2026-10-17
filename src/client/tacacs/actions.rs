use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::tacacs::{
    actions::{action, duration_parameter, parameter, secret_parameter},
    codec,
};
use crate::state::app_state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct TacacsClientProtocol;
impl TacacsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn authenticate() -> ActionDefinition {
    action(
        "authenticate_tacacs",
        "Open one fresh legacy TCP session for ASCII/PAP LOGIN; bounded GETUSER/GETPASS uses these credentials. No account fallback or automatic replay.",
        vec![
            parameter("username", "string", "Nonempty printable ASCII, no spaces; at most255bytes", true),
            parameter("password", "string", "Printable ASCII password at most255bytes; redacted in action logs", true),
            parameter("method", "string", "ascii(default) or pap", false),
            parameter("privilege_level", "number", "0..15, default1", false),
            parameter("port", "string", "Printable ASCII NAS port at most255bytes", false),
            parameter("remote_address", "string", "Printable ASCII originating address at most255bytes", false),
        ],
        json!({"type":"authenticate_tacacs","username":"alice","password":"replace-me","method":"pap"}),
    )
}
fn authorize() -> ActionDefinition {
    action("authorize_tacacs","Request separate authorization and report PASS_ADD/PASS_REPLACE effective typed arguments. Unknown mandatory results deny authorization; no device policy is applied.",vec![parameter("request","object","username,port,remote_address,authentication_method(defaulttacacs_plus),authentication_type(defaultascii),service(defaultlogin),privilege_level(default1),arguments:[{name,value,mandatory(defaulttrue)}].<=32args,eachwire<=255printableASCIIbytes.",true),parameter("handled_mandatory_arguments","array","Names this caller can consume;<=32. Defaultservice/cmd/cmd-arg/priv-lvl. Unknown mandatory effective arguments deny, unknown optional ones ignored. priv-lvl must parse0..15.",false)],json!({"type":"authorize_tacacs","request":{"username":"alice","arguments":[{"name":"service","value":"shell"},{"name":"cmd","value":"show"},{"name":"cmd-arg","value":"version"}]}}))
}
fn account() -> ActionDefinition {
    action("account_tacacs","Send one START/STOP/WATCHDOG/UPDATE record and report the peer's reply. SUCCESS means the peer asserts recording, not durability or exactly-once processing.",vec![parameter("record_type","string","start|stop|watchdog|update (START+WATCHDOG)",true),parameter("request","object","Same typed context/arguments as authorize_tacacs",true)],json!({"type":"account_tacacs","record_type":"start","request":{"username":"alice","arguments":[{"name":"task_id","value":"42"}]}}))
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Cancel pending TCP exchange, handlers, queued actions and the command handle",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn all() -> Vec<ActionDefinition> {
    vec![authenticate(), authorize(), account(), disconnect()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_connected","Legacy connector ready after bounded name resolution. Every AAA operation opens its own TCP session; readiness does not confirm server availability.",authorize().example.clone()).with_parameters(vec![parameter("remote_addr","string","Configured endpoint",true)]).with_actions(all())
});
pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_authentication_result","Correlated terminal authentication result; RESTART/FOLLOW treated as FAIL without retry or redirect. Credentials absent.",disconnect().example.clone()).with_parameters(vec![parameter("request","object","Credential-free username/method/context",true),parameter("reply","object","Typed terminal status/message/data",true),parameter("authenticated","boolean","True only for PASS",true)]).with_actions(all())
});
pub static AUTHOR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_authorization_result","Correlated reply, effective arguments and safe mandatory-argument decision. No device policy applied.",disconnect().example.clone()).with_parameters(vec![parameter("request","object","Typed authorization context",true),parameter("reply","object","Typed reply and ordered wire arguments",true),parameter("authorized","boolean","PASS_ADD/PASS_REPLACE plus supported mandatory args and valid priv-lvl",true)]).with_actions(all())
});
pub static ACCOUNT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tacacs_accounting_result",
        "Correlated record response; server success is not a durability guarantee.",
        disconnect().example.clone(),
    )
    .with_parameters(vec![
        parameter("request", "object", "Typed accounting context", true),
        parameter("record_type", "string", "start/stop/watchdog/update", true),
        parameter(
            "reply",
            "object",
            "Typed accounting status, message and data from the peer",
            true,
        ),
        parameter("recorded_by_peer", "boolean", "True only for SUCCESS", true),
        parameter(
            "durable_storage_confirmed",
            "boolean",
            "Always false: a peer reply cannot confirm durable storage",
            true,
        ),
    ])
    .with_actions(all())
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tacacs_error","Session transport/framing/correlation/unsupported-flow error. No implicit request retry or fallback.",disconnect().example.clone()).with_parameters(vec![parameter("error","string","Bounded transport or validation description, without request credentials",true)]).with_actions(all())
});
impl Protocol for TacacsClientProtocol {
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
        "Selected legacy TACACS+ AAA connector with typed correlated results"
    }
    fn example_prompt(&self) -> &'static str {
        "Request legacy TACACS+ authorization using deterministic handlers"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        all()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            AUTH_EVENT.clone(),
            AUTHOR_EVENT.clone(),
            ACCOUNT_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            secret_parameter(),
            duration_parameter(
                "io_timeout_seconds",
                codec::DEFAULT_IO_SECONDS,
                "DNS/connect/whole-packet deadline1..300seconds;10swrite",
            ),
            duration_parameter(
                "handler_timeout_seconds",
                codec::DEFAULT_HANDLER_SECONDS,
                "Event handler deadline1..300seconds; injection stays independent",
            ),
        ]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(49).request_only("TACACS+ results answer one pending AAA session; no unsolicited peer message API").max_inbound_bytes(codec::MAX_BODY_BYTES+12).implementation("Native selected RFC8907 legacy header, existing MD5 chained body obfuscation and typed ASCII/PAP/authorization/accounting; one fresh TCP connection per session").llm_control("Common client handlers/shared memory, typed results and bounded injection independent of parked handlers").e2e_testing("Required unmodified nwaples/tacplus0.0.3 SDK-backed server, calibrated against Python tacacs_plus2.6 and actual literal wire; sequence/version/ID errors, bounds, single-flight, deadlines and owned cancellation")
 .notes("Experimental selected legacy RFC8907 TCP49 only; not secure transport or full RFC compliance. RFC9887 TLS1.3/mutual authentication/port300 excluded. Logical readiness after name resolution; each operation opens fresh TCP, no SINGLE_CONNECT negotiation or multiplexing. Cryptographic random session IDs; strict response version/type/ID/sequence/obfuscation flags, unknown header flags ignored, no wrapping. ASCII LOGIN responds to GETUSER/GETPASS up to8rounds; GETDATA/round exhaustion abort; PAPLOGIN minor1 single pair. RESTART/FOLLOW fail without retry/redirect, no backup/local account fallback. Printable ASCII subset only; full PRECIS/Unicode, CHAP/MSCHAP/ENABLE/password-change/SENDAUTH excluded.16KiBbody,32wireargs/handled names,255byte short fields,1024byte reply strings; effective PASS_ADD may combine64arguments. Unhandled mandatory effective arguments deny; optional unknown ignored,priv-lvl0..15; reports decisions without applying device policy. Accounting peer SUCCESS is a recording assertion only; no durable retention/billing/exactly-once claim. Startup shared_secret remains private transport configuration; client events and injected-action logs omit/redact passwords. One in-flight exchange,32queued events/actions,depth8;16injected command capacity. DNS/connect/packet deadlines30s default1..300s,10swrite;handler30s default1..300s. No replay after any partial failure. Caller injection timeout does not itself cancel the exchange; disconnect/removal does. No protocol account/store, fuzz or production-capture claim.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
 .batching(crate::protocol::metadata::BatchingMode::Unsupported)
 .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_client","base_stack":"tacacs","remote_addr":"127.0.0.1:49","startup_params":{"shared_secret":"replace-with-a-unique-client-secret"}});
        let mut llm = base.clone();
        llm["instruction"] = json!("Request authorization for alice to run show version");
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"tacacs_connected","handler":{"type":"script","language":"python","code":format!("import json,sys\njson.load(sys.stdin)\nprint({:?})",json!({"actions":[authorize().example]}).to_string())}}]);
        let mut fixed = base;
        fixed["event_handlers"] = json!([{"event_pattern":"tacacs_connected","handler":{"type":"static","actions":[authorize().example]}}]);
        StartupExamples::new(llm, script, fixed)
    }
}
impl Client for TacacsClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::TacacsClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let action = codec::owned_json(action)?;
        if action["type"] == "disconnect" {
            ensure!(
                action.as_object().is_some_and(|m| m.len() == 1),
                "disconnect only type"
            );
            return Ok(ClientActionResult::Disconnect);
        }
        super::transport::parse(action.clone())?;
        Ok(ClientActionResult::Custom {
            name: "tacacs_command".into(),
            data: action,
        })
    }
}
