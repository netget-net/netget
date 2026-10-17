use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::netconf::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct NetconfClientProtocol;
impl NetconfClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub const OPERATIONS: &[&str] = &[
    "get",
    "get-config",
    "edit-config",
    "lock",
    "unlock",
    "commit",
    "discard-changes",
    "validate",
    "close-session",
    "kill-session",
    "custom",
];

fn rpc_action() -> ActionDefinition {
    action(
        "netconf_rpc",
        "Send one NETCONF <rpc>. Rust assigns the message-id, enforces the server's advertised capabilities for candidate/startup/validate/rollback, and raises netconf_rpc_reply with the correlated reply.",
        vec![
            parameter("operation", "string", "get, get-config, edit-config, lock, unlock, commit, discard-changes, validate, close-session, kill-session or custom", true),
            parameter("source", "string", "get-config/validate datastore: running, candidate or startup", false),
            parameter("target", "string", "edit-config/lock/unlock datastore: running, candidate or startup", false),
            parameter("filter_xml", "string", "Subtree filter content for get/get-config, with xmlns", false),
            parameter("config_xml", "string", "edit-config <config> content, with xmlns", false),
            parameter("default_operation", "string", "edit-config default-operation: merge, replace or none", false),
            parameter("error_option", "string", "edit-config error-option", false),
            parameter("session_id", "number", "kill-session target", false),
            parameter("input_xml", "string", "custom: exactly one operation element in its own namespace", false),
        ],
        json!({"type":"netconf_rpc","operation":"get-config","source":"running"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the NETCONF session and SSH connection without close-session",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![rpc_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netconf_connected",
        "NETCONF session established after SSH authentication and <hello> exchange",
        rpc_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "session_id",
            "number",
            "Server-assigned NETCONF session id",
            true,
        ),
        parameter(
            "server_capabilities",
            "array",
            "Capabilities the server advertised",
            true,
        ),
        parameter(
            "base_version",
            "string",
            "Negotiated base version: 1.0 or 1.1",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("netconf_rpc_reply", "Correlated <rpc-reply> for the last request", disconnect_action().example.clone())
        .with_parameters(vec![
            parameter("operation", "string", "The request's operation", true),
            parameter("message_id", "string", "The request's message-id", true),
            parameter("ok", "boolean", "Present and true for <ok/>", false),
            parameter("data_xml", "string", "<data> content for get/get-config", false),
            parameter("output_xml", "string", "Custom RPC output elements", false),
            parameter("errors", "array", "rpc-error entries: error_type, error_tag, error_severity, error_message, error_path, error_info_xml", false),
        ])
        .with_actions(actions())
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    required: bool,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
        example,
        default,
    }
}

impl Protocol for NetconfClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NETCONF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SSH>NETCONF"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["netconf", "rfc6241", "yang", "network configuration"]
    }
    fn description(&self) -> &'static str {
        "NETCONF client over SSH with pinned host keys and correlated structured RPCs"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), REPLY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("username", "string", "Login name for SSH password authentication on the NETCONF device", true, json!("admin"), None),
            startup("password", "string", "Password for SSH password authentication; never placed in events or logs", true, json!("secret"), None),
            startup("host_key_sha256", "string", "Required pinned server host key, OpenSSH form SHA256:<base64>. A different key fails the handshake.", true, json!("SHA256:<trusted fingerprint>"), None),
            startup("base_versions", "array", "Base versions to offer: [\"1.0\"], [\"1.1\"] or both", false, json!(["1.0", "1.1"]), Some(json!(["1.0", "1.1"]))),
            startup("handshake_timeout_secs", "number", "Seconds (1..=600) for TCP, SSH, authentication and <hello>", false, json!(30), Some(json!(crate::server::netconf::HANDSHAKE_TIMEOUT.as_secs()))),
            startup("reply_timeout_secs", "number", "Seconds (1..=3600) to wait for each <rpc-reply>", false, json!(60), Some(json!(super::REPLY_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(830)
            .implementation("russh 0.45 SSH client with mandatory host-key pin and password auth; netconf subsystem with native RFC 6242 framing and the shared bounded XML codec")
            .llm_control("Which RPCs to send (get, get-config, edit-config, lock/unlock, commit, discard-changes, validate, close/kill-session, custom) and what to do with each reply")
            .e2e_testing("tests/client/netconf: the Python netconf 2.1.0 server (independent) over base 1.0 and 1.1, plus framing, correlation, pin-refusal and command-injection checks")
            .notes("One outstanding RPC at a time; replies are matched on message-id. Password authentication only. Notifications, NETCONF over TLS, url and confirmed commit are excluded. 1 MiB messages.")
            .max_inbound_bytes(crate::server::netconf::wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the NETCONF device at 192.0.2.1:830 and read its running configuration"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"netconf","remote_addr":"127.0.0.1:830","instruction":"Read the running configuration","startup_params":{"username":"admin","password":"secret","host_key_sha256":"SHA256:<trusted fingerprint>"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"netconf_connected","handler":{"type":"static","actions":[{"type":"netconf_rpc","operation":"get-config","source":"running"}]}},
            {"event_pattern":"netconf_rpc_reply","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"respond([{'type':'netconf_rpc','operation':'get-config','source':'running'}])"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Client for NetconfClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("netconf_rpc") => {
                let op = v["operation"].as_str().unwrap_or("");
                ensure!(OPERATIONS.contains(&op), "unknown NETCONF operation '{op}'");
                Ok(ClientActionResult::Custom {
                    name: "netconf_rpc".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown NETCONF client action"),
        }
    }
}
