use super::rpc;
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
pub struct NetconfProtocol;
impl NetconfProtocol {
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
    let log_template = match name {
        "netconf_rpc_reply" => LogTemplate::new()
            .with_info("-> NETCONF reply ok={ok} data={preview(data_xml,80)} errors={errors_len}"),
        "netconf_auth_decision" => {
            LogTemplate::new().with_info("-> NETCONF SSH authentication allowed={allowed}")
        }
        // The client shares this helper; config may carry secrets, so only the operation.
        "netconf_rpc" => LogTemplate::new().with_info("-> NETCONF {operation}"),
        _ => LogTemplate::new().with_info(format!("-> NETCONF {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn reply_action() -> ActionDefinition {
    action(
        "netconf_rpc_reply",
        "Answer the pending <rpc>. Rust supplies message-id, the base namespace and the <rpc-reply> envelope. Supply exactly one of: ok=true; data_xml (get/get-config: content placed inside <data>, '' for empty); output_xml (custom RPC output elements); errors (rpc-error list).",
        vec![
            parameter("ok", "boolean", "true for an <ok/> reply (edit-config, lock, unlock, commit, discard-changes, validate, custom without output)", false),
            parameter("data_xml", "string", "XML elements for <data>, each with its own xmlns, e.g. <interfaces xmlns=\"urn:example:if\"><interface><name>eth0</name></interface></interfaces>", false),
            parameter("output_xml", "string", "Custom RPC output elements placed directly under <rpc-reply>", false),
            parameter("errors", "array", "[{error_type: transport|rpc|protocol|application, error_tag: RFC 6241 tag such as invalid-value, lock-denied, data-missing, access-denied, operation-failed, error_severity: error|warning, error_message, error_path, error_info_xml}]", false),
        ],
        json!({"type":"netconf_rpc_reply","data_xml":"<system xmlns=\"urn:example:system\"><hostname>router1</hostname></system>"}),
    )
}

fn auth_action() -> ActionDefinition {
    action(
        "netconf_auth_decision",
        "Accept or reject the SSH password for this NETCONF connection. No built-in accounts; default denial.",
        vec![parameter("allowed", "boolean", "True only if these credentials should be allowed", true)],
        json!({"type":"netconf_auth_decision","allowed":false}),
    )
}

pub static RPC_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netconf_rpc",
        "A NETCONF <rpc> that passed envelope, capability and datastore checks. Data and acceptance come from the handler; there is no built-in datastore.",
        reply_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "get, get-config, edit-config, lock, unlock, commit, discard-changes, validate, or a custom RPC's element name", true),
        parameter("namespace", "string", "Operation namespace; the base namespace for standard operations", true),
        parameter("message_id", "string", "The request's message-id (echoed by Rust)", true),
        parameter("session_id", "number", "This NETCONF session's id", true),
        parameter("username", "string", "Authenticated SSH user", true),
        parameter("source", "string", "get-config/validate datastore: running, candidate or startup", false),
        parameter("target", "string", "edit-config/lock/unlock datastore", false),
        parameter("filter_type", "string", "subtree or xpath", false),
        parameter("filter_xml", "string", "Subtree filter content", false),
        parameter("filter_select", "string", "XPath filter expression (only with :xpath)", false),
        parameter("config_xml", "string", "edit-config <config> content, with namespace declarations", false),
        parameter("default_operation", "string", "merge, replace or none", false),
        parameter("test_option", "string", "edit-config test-option (only with :validate)", false),
        parameter("error_option", "string", "edit-config error-option", false),
        parameter("custom", "boolean", "true for an operation outside the base namespace", false),
        parameter("input_xml", "string", "Custom RPC input children", false),
    ])
    .with_actions(vec![reply_action()])
});

pub static AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netconf_auth",
        "SSH password authentication before a NETCONF session. Use a deterministic handler for real credentials.",
        auth_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("username", "string", "Login name the SSH client presented; compare it with your own account list", true),
        parameter("password", "string", "SSH password supplied by the peer", true),
    ])
    .with_actions(vec![auth_action()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for NetconfProtocol {
    fn protocol_name(&self) -> &'static str {
        "NETCONF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SSH>NETCONF"
    }
    fn description(&self) -> &'static str {
        "NETCONF server over SSH (RFC 6241/6242) with handler-controlled datastores"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "netconf",
            "rfc6241",
            "rfc6242",
            "yang",
            "network configuration",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply_action(), auth_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RPC_EVENT.clone(), AUTH_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "capabilities",
                "array",
                "Capabilities advertised beside base:1.0 and base:1.1. Datastore and option rules follow them: candidate/commit need :candidate, startup needs :startup, edit-config on running needs :writable-running, validate needs :validate, xpath filters need :xpath.",
                json!([rpc::WRITABLE_RUNNING, "urn:example:system?module=example-system"]),
                Some(json!([rpc::WRITABLE_RUNNING])),
            ),
            startup(
                "host_key_path",
                "string",
                "OpenSSH private host key to serve. Omitted: a fresh Ed25519 key per start, whose fingerprint and public key are logged so clients can pin them.",
                json!("/etc/netget/netconf_host_ed25519"),
                None,
            ),
            startup(
                "handshake_timeout_secs",
                "number",
                "Seconds (1..=600) from TCP accept to a completed NETCONF <hello> exchange",
                json!(30),
                Some(json!(super::HANDSHAKE_TIMEOUT.as_secs())),
            ),
            startup(
                "idle_timeout_secs",
                "number",
                "Seconds (1..=86400) a session may sit without traffic; a parked handler does not count",
                json!(600),
                Some(json!(super::IDLE_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(830))
            .well_known_port(830)
            .implementation("russh 0.45 SSH server with the netconf subsystem; native RFC 6242 end-of-message and chunked framing; bounded flat XML parser (no DTD, depth 32, 1 MiB messages); RFC 6241 envelopes owned by Rust")
            .llm_control("SSH password decisions; every RPC's data, acceptance and rpc-error; custom RPCs in their own namespace")
            .e2e_testing("tests/server/netconf: framing and envelope checks, native session lifecycle, and ncclient 0.7.1 (independent Python client) over NETCONF 1.0 and 1.1")
            .notes("No built-in datastore: get/get-config/edit-config are answered by the handler (use server memory or the SQLite facility to persist). copy-config, delete-config, confirmed commit, url, notifications, call-home and NETCONF over TLS are excluded. kill-session ends another live session of this server. One NETCONF channel per SSH connection; password authentication only.")
            .request_only("NETCONF replies answer a pending <rpc> with its message-id; notifications are not implemented, so nothing is sent unprompted")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "NETCONF server on port 830 for a router whose hostname is edge1"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"netconf","port":830,"instruction":"Router edge1: answer get-config with its hostname; accept edit-config"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"netconf_auth","handler":{"type":"static","actions":[{"type":"netconf_auth_decision","allowed":false}]}},
            {"event_pattern":"netconf_rpc","handler":{"type":"script","language":"python","code":"respond([{'type':'netconf_rpc_reply','ok':True}] if event['operation'] != 'get-config' else [{'type':'netconf_rpc_reply','data_xml':''}])"}}
        ]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"netconf_auth","handler":{"type":"static","actions":[{"type":"netconf_auth_decision","allowed":false}]}},
            {"event_pattern":"netconf_rpc","handler":{"type":"static","actions":[{"type":"netconf_rpc_reply","errors":[{"error_type":"application","error_tag":"operation-not-supported"}]}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Server for NetconfProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("netconf_rpc_reply") => {
                reply_body(&v)?;
                Ok(ActionResult::Custom {
                    name: "netconf_rpc_reply".into(),
                    data: v,
                })
            }
            Some("netconf_auth_decision") => {
                ensure!(v["allowed"].is_boolean(), "allowed must be boolean");
                Ok(ActionResult::Custom {
                    name: "netconf_auth_decision".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown NETCONF server action"),
        }
    }
}

/// Validate a reply action into the envelope body Rust will render.
pub fn reply_body(v: &Value) -> Result<rpc::ReplyBody> {
    let present: Vec<&str> = ["ok", "data_xml", "output_xml", "errors"]
        .into_iter()
        .filter(|k| v.get(*k).is_some_and(|x| !x.is_null()))
        .collect();
    ensure!(
        present.len() == 1,
        "netconf_rpc_reply needs exactly one of ok, data_xml, output_xml, errors"
    );
    Ok(match present[0] {
        "ok" => {
            ensure!(v["ok"] == true, "ok must be true; use errors to refuse");
            rpc::ReplyBody::Ok
        }
        "data_xml" => rpc::ReplyBody::Data(super::xml::parse_fragment(
            v["data_xml"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("data_xml must be a string"))?,
        )?),
        "output_xml" => rpc::ReplyBody::Output(super::xml::parse_fragment(
            v["output_xml"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("output_xml must be a string"))?,
        )?),
        _ => {
            let list = v["errors"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("errors must be an array"))?;
            ensure!(
                !list.is_empty() && list.len() <= 64,
                "errors must hold 1..=64 entries"
            );
            rpc::ReplyBody::Errors(
                list.iter()
                    .map(rpc::RpcError::from_value)
                    .collect::<Result<_>>()?,
            )
        }
    })
}
