//! DC protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::{
    log_template::LogTemplate,
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType,
};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

/// DC client state for tracking user information
#[derive(Clone, Debug)]
pub struct DcClientState {
    pub nickname: Option<String>,
    pub description: Option<String>,
    pub email: Option<String>,
    pub share_size: u64,
    pub is_operator: bool,
}

impl DcClientState {
    pub fn new() -> Self {
        Self {
            nickname: None,
            description: None,
            email: None,
            share_size: 0,
            is_operator: false,
        }
    }
}

/// DC protocol action handler
pub struct DcProtocol {
    /// Map of active connections to their DC state
    clients: Arc<Mutex<HashMap<ConnectionId, DcClientState>>>,
}

impl DcProtocol {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a connection to the protocol handler
    pub async fn add_connection(&self, connection_id: ConnectionId) {
        self.clients
            .lock()
            .await
            .insert(connection_id, DcClientState::new());
    }

    /// Remove a connection from the protocol handler
    pub async fn remove_connection(&self, connection_id: &ConnectionId) {
        self.clients.lock().await.remove(connection_id);
    }

    /// Set client nickname
    pub async fn set_nickname(&self, connection_id: ConnectionId, nickname: String) {
        if let Some(client) = self.clients.lock().await.get_mut(&connection_id) {
            client.nickname = Some(nickname);
        }
    }

    /// Get client nickname
    pub async fn get_nickname(&self, connection_id: &ConnectionId) -> Option<String> {
        self.clients
            .lock()
            .await
            .get(connection_id)
            .and_then(|c| c.nickname.clone())
    }

    /// Set client info
    pub async fn set_client_info(
        &self,
        connection_id: ConnectionId,
        description: Option<String>,
        email: Option<String>,
        share_size: u64,
    ) {
        if let Some(client) = self.clients.lock().await.get_mut(&connection_id) {
            if let Some(desc) = description {
                client.description = Some(desc);
            }
            if let Some(em) = email {
                client.email = Some(em);
            }
            client.share_size = share_size;
        }
    }

    /// Set operator status
    pub async fn set_operator(&self, connection_id: ConnectionId, is_op: bool) {
        if let Some(client) = self.clients.lock().await.get_mut(&connection_id) {
            client.is_operator = is_op;
        }
    }

    /// Get client state
    pub async fn get_client_state(&self, connection_id: &ConnectionId) -> Option<DcClientState> {
        self.clients.lock().await.get(connection_id).cloned()
    }

    /// Get all connected nicknames
    pub async fn get_all_nicknames(&self) -> Vec<String> {
        self.clients
            .lock()
            .await
            .values()
            .filter_map(|c| c.nickname.clone())
            .collect()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DcProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "hub_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name of the DC hub".to_string(),
                required: false,
                example: serde_json::json!("NetGet DC Hub"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "hub_topic".to_string(),
                type_hint: "string".to_string(),
                description: "Hub topic/description".to_string(),
                required: false,
                example: serde_json::json!("Welcome to NetGet DC Hub"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // DC could have async actions like broadcast_message in the future
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_dc_lock_action(),
            send_dc_hello_action(),
            send_dc_hubname_action(),
            send_dc_message_action(),
            send_dc_broadcast_action(),
            send_dc_userlist_action(),
            send_dc_search_result_action(),
            send_dc_kick_action(),
            send_dc_redirect_action(),
            send_dc_raw_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DC_COMMAND_RECEIVED_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dc", "direct connect", "dc++", "nmdc", "via dc"]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .well_known_port(411)
                .implementation("Manual NMDC protocol implementation - text-based with pipe delimiters")
                .llm_control("Authentication (Lock/Key/Hello), chat messages, search results, user management (kick/redirect)")
                .e2e_testing("tokio::net::TcpStream speaking NMDC by hand (tests/server/dc/): the $Lock handshake, chat, search, kick/redirect, the injected-peer path, and the fail-closed reply when the model is unreachable. No third-party DC++ client, so this stays Experimental")
                .notes("NMDC protocol only (ADC not supported). No key validation or P2P connection handling. Commands are bounded at 64 KiB; interpolated action values have | \\r \\n stripped so one field cannot inject a second command.")
                .max_inbound_bytes(crate::server::dc::MAX_COMMAND_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DC (Direct Connect) hub server - peer-to-peer file sharing protocol with chat and search capabilities"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a DC hub server"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: greet every command with a private message to the
        // client, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "dc_command_received":
    actions = [{"type": "send_dc_message",
                "target": event.get("client_nickname", "user"),
                "message": "Hello from NetGet"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 411,
                "base_stack": "dc",
                "instruction": "Direct Connect hub server. Accept users with $Hello, send hub name, and broadcast welcome messages. Support chat and search."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 411,
                "base_stack": "dc",
                "event_handlers": [{
                    "event_pattern": "dc_command_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 411,
                "base_stack": "dc",
                "event_handlers": [{
                    "event_pattern": "dc_command_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dc_lock",
                            "lock": "EXTENDEDPROTOCOLABCABCABCABCABCABC",
                            "pk": "NetGetHub"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DcProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dc::DcServer;

            let listen_addr = ctx.legacy_listen_addr();
            DcServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        use crate::server::dc::nmdc_field as f;

        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        // Every arm below builds `$Something {}|`, so a `|` inside any interpolated value ends
        // the command early and the remainder is parsed by the client as a second command.
        // `f()` strips the three framing characters; `send_dc_raw` is deliberately exempt,
        // because sending an arbitrary frame is what it is for.
        match action_type {
            "send_dc_lock" => {
                let lock = action
                    .get("lock")
                    .and_then(|v| v.as_str())
                    .unwrap_or("EXTENDEDPROTOCOLABCABCABCABCABCABC");
                let pk = action
                    .get("pk")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NetGetHub");

                let msg = format!("$Lock {} Pk={}|", f(lock), f(pk));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_hello" => {
                let nickname = action
                    .get("nickname")
                    .and_then(|v| v.as_str())
                    .context("Missing nickname")?;

                let msg = format!("$Hello {}|", f(nickname));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_hubname" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing hub name")?;

                let msg = format!("$HubName {}|", f(name));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_message" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing target")?;
                let source = action
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Hub");
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing message")?;

                let (target, source, message) = (f(target), f(source), f(message));
                let msg = format!(
                    "$To: {} From: {} $<{}> {}|",
                    target, source, source, message
                );
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_broadcast" => {
                let source = action
                    .get("source")
                    .and_then(|v| v.as_str())
                    .context("Missing source")?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing message")?;

                let msg = format!("<{}> {}|", f(source), f(message));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_userlist" => {
                let users = action
                    .get("users")
                    .and_then(|v| v.as_array())
                    .context("Missing users array")?;

                let user_list: Vec<String> =
                    users.iter().filter_map(|u| u.as_str().map(f)).collect();

                let msg = format!("$NickList {}$$|", user_list.join("$$"));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_search_result" => {
                let source = action
                    .get("source")
                    .and_then(|v| v.as_str())
                    .context("Missing source")?;
                let filename = action
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .context("Missing filename")?;
                let size = action
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .context("Missing size")?;
                let slots = action.get("slots").and_then(|v| v.as_u64()).unwrap_or(1);
                let hub_name = action
                    .get("hub_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NetGetHub");

                // $SR source filename\x05size slots/totalslots\x05hubname|
                let msg = format!(
                    "$SR {} {}\x05{} {}/{}\x05{}|",
                    f(source),
                    f(filename),
                    size,
                    slots,
                    slots,
                    f(hub_name)
                );
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_kick" => {
                let nickname = action
                    .get("nickname")
                    .and_then(|v| v.as_str())
                    .context("Missing nickname")?;

                let msg = format!("$Kick {}|", f(nickname));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_redirect" => {
                let address = action
                    .get("address")
                    .and_then(|v| v.as_str())
                    .context("Missing address")?;

                let msg = format!("$ForceMove {}|", f(address));
                Ok(ActionResult::Output(msg.into_bytes()))
            }
            "send_dc_raw" => {
                let mut command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing command")?
                    .to_string();

                // Ensure pipe terminator
                if !command.ends_with('|') {
                    command.push('|');
                }

                Ok(ActionResult::Output(command.into_bytes()))
            }
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown DC action: {}", action_type)),
        }
    }
}

/// Event type ID for DC command received
pub static DC_COMMAND_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_command_received",
        "A Direct Connect client sent a hub command. Answer with the action matching the stage \
         of the handshake: reply to $Key/$ValidateNick with send_dc_hello and send_dc_hubname, \
         to $GetNickList with send_dc_userlist, to $Search with send_dc_search_result, to chat \
         and $To: with send_dc_message or send_dc_broadcast. send_dc_raw sends any other NMDC \
         command verbatim.",
        json!({
            "type": "send_dc_hello",
            "nickname": "alice"
        }),
    )
    // All ten sync actions can answer this event - it is the protocol's only event and covers
    // every stage of the NMDC handshake. `call_llm` builds the model's tool list from the event
    // type, not from get_sync_actions(), so without this the model was offered none of them.
    .with_actions(vec![
        send_dc_lock_action(),
        send_dc_hello_action(),
        send_dc_hubname_action(),
        send_dc_message_action(),
        send_dc_broadcast_action(),
        send_dc_userlist_action(),
        send_dc_search_result_action(),
        send_dc_kick_action(),
        send_dc_redirect_action(),
        send_dc_raw_action(),
        wait_for_more_action(),
        close_connection_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The DC command received (without pipe terminator)".to_string(),
            required: true,
        },
        Parameter {
            name: "command_type".to_string(),
            type_hint: "string".to_string(),
            description: "Parsed command type (e.g., ValidateNick, MyINFO, Search)".to_string(),
            required: true,
        },
        Parameter {
            name: "client_nickname".to_string(),
            type_hint: "string".to_string(),
            description: "Client's nickname if set".to_string(),
            required: false,
        },
    ])
});

// Action definitions
fn send_dc_lock_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_lock".to_string(),
        description: "Send $Lock challenge for authentication".to_string(),
        parameters: vec![
            Parameter {
                name: "lock".to_string(),
                type_hint: "string".to_string(),
                description: "Lock string (default: random string)".to_string(),
                required: false,
            },
            Parameter {
                name: "pk".to_string(),
                type_hint: "string".to_string(),
                description: "PK string (default: NetGetHub)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dc_lock",
            "lock": "EXTENDEDPROTOCOLABCABCABCABCABCABC",
            "pk": "NetGetHub"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $Lock challenge")
                .with_debug("DC send_dc_lock: pk={pk}"),
        ),
    }
}

fn send_dc_hello_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_hello".to_string(),
        description: "Accept user with $Hello".to_string(),
        parameters: vec![Parameter {
            name: "nickname".to_string(),
            type_hint: "string".to_string(),
            description: "Client nickname to accept".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_hello",
            "nickname": "alice"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $Hello {nickname}")
                .with_debug("DC send_dc_hello: nickname={nickname}"),
        ),
    }
}

fn send_dc_hubname_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_hubname".to_string(),
        description: "Send hub name to client".to_string(),
        parameters: vec![Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "Hub name".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_hubname",
            "name": "NetGet DC Hub"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $HubName '{name}'")
                .with_debug("DC send_dc_hubname: name={name}"),
        ),
    }
}

fn send_dc_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_message".to_string(),
        description: "Send chat message from hub or user to specific client".to_string(),
        parameters: vec![
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Target nickname".to_string(),
                required: true,
            },
            Parameter {
                name: "source".to_string(),
                type_hint: "string".to_string(),
                description: "Source nickname (default: Hub)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Message text".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dc_message",
            "target": "alice",
            "source": "HubBot",
            "message": "Welcome to the hub!"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC PM {source}->{target}")
                .with_debug("DC send_dc_message: from={source} to={target}"),
        ),
    }
}

fn send_dc_broadcast_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_broadcast".to_string(),
        description: "Broadcast message to all connected clients".to_string(),
        parameters: vec![
            Parameter {
                name: "source".to_string(),
                type_hint: "string".to_string(),
                description: "Source nickname or hub name".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Message text".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dc_broadcast",
            "source": "Hub",
            "message": "Server maintenance in 5 minutes"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC broadcast from {source}")
                .with_debug("DC send_dc_broadcast: source={source}"),
        ),
    }
}

fn send_dc_userlist_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_userlist".to_string(),
        description: "Send list of connected users".to_string(),
        parameters: vec![Parameter {
            name: "users".to_string(),
            type_hint: "array".to_string(),
            description: "Array of nicknames".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_userlist",
            "users": ["alice", "bob", "charlie"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $NickList ({users_len} users)")
                .with_debug("DC send_dc_userlist: count={users_len}"),
        ),
    }
}

fn send_dc_search_result_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_search_result".to_string(),
        description: "Send search result to client".to_string(),
        parameters: vec![
            Parameter {
                name: "source".to_string(),
                type_hint: "string".to_string(),
                description: "Source nickname (who has the file)".to_string(),
                required: true,
            },
            Parameter {
                name: "filename".to_string(),
                type_hint: "string".to_string(),
                description: "File name".to_string(),
                required: true,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description: "File size in bytes".to_string(),
                required: true,
            },
            Parameter {
                name: "slots".to_string(),
                type_hint: "number".to_string(),
                description: "Available slots (default: 1)".to_string(),
                required: false,
            },
            Parameter {
                name: "hub_name".to_string(),
                type_hint: "string".to_string(),
                description: "Hub name (default: NetGetHub)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dc_search_result",
            "source": "bob",
            "filename": "ubuntu-22.04.iso",
            "size": 3654957056u64,
            "slots": 2,
            "hub_name": "NetGetHub"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $SR {filename} ({size}B)")
                .with_debug(
                    "DC send_dc_search_result: source={source} file={filename} size={size}",
                ),
        ),
    }
}

fn send_dc_kick_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_kick".to_string(),
        description: "Kick user from hub".to_string(),
        parameters: vec![Parameter {
            name: "nickname".to_string(),
            type_hint: "string".to_string(),
            description: "User to kick".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_kick",
            "nickname": "alice"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $Kick {nickname}")
                .with_debug("DC send_dc_kick: nickname={nickname}"),
        ),
    }
}

fn send_dc_redirect_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_redirect".to_string(),
        description: "Redirect user to another hub".to_string(),
        parameters: vec![Parameter {
            name: "address".to_string(),
            type_hint: "string".to_string(),
            description: "Target hub address (host:port)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_redirect",
            "address": "hub.example.com:411"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC $ForceMove {address}")
                .with_debug("DC send_dc_redirect: address={address}"),
        ),
    }
}

/// Declared, not merely executable.
///
/// `execute_action` has always handled `wait_for_more` and `close_connection`, and the
/// protocol's CLAUDE.md lists both as available actions - but neither was in
/// `get_sync_actions()` or on any event, so `call_llm` never offered them and the model could
/// only reach them by guessing a name it had not been shown.
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        // The old text was "Correct when the command received so far is incomplete", which
        // cannot happen: the server raises an event only once it has read the `|` terminator,
        // so every command reaching the model is already whole. There is no accumulating state
        // here and none is needed. What the action is genuinely for is the very common NMDC
        // case of a command that wants no reply.
        description: "Answer this command with nothing and keep the connection open. Correct \
            for the many NMDC commands a hub does not reply to ($Version, $MyINFO, $GetINFO). \
            You will never be shown a partial command - the hub raises an event only after the \
            closing '|' - so this is not for reassembling anything."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: None,
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Disconnect this client without sending anything further.".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: None,
    }
}

fn send_dc_raw_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_raw".to_string(),
        description: "Send raw NMDC command (for advanced use)".to_string(),
        parameters: vec![Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "Raw command (auto-adds | if missing)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_raw",
            "command": "$HubTopic Welcome to NetGet!"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DC raw command")
                .with_debug("DC send_dc_raw: command={command}"),
        ),
    }
}
