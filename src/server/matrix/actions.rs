//! What the model decides as a Matrix homeserver: who may log in (when no `user_passwords` table is
//! given), whether a room may be created or joined, whether a message is accepted — and
//! what it says back, as its own user, into any room. Rust owns the client-server API's
//! shapes, tokens, room membership and `/sync` delivery.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT: &str = "matrix_accept";
pub const REJECT: &str = "matrix_reject";
pub const SEND: &str = "matrix_send";
/// The server name in user and room ids when the operator names none.
pub const DEFAULT_SERVER_NAME: &str = "localhost";
/// The localpart of the model's own user.
pub const DEFAULT_BOT_USER: &str = "netget";
/// A request body past this is refused (Synapse's default `max_upload_size` is far larger,
/// but nothing the client-server API sends here is).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Default, Clone)]
pub struct MatrixProtocol;

impl MatrixProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    info: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn accept_action() -> ActionDefinition {
    action(
        ACCEPT,
        "Allow the request (the login, the room, the join, the message).",
        vec![],
        json!({"type": ACCEPT}),
        "-> Matrix accept",
    )
}

pub fn reject_action() -> ActionDefinition {
    action(
        REJECT,
        "Refuse the request with a Matrix error, e.g. M_FORBIDDEN.",
        vec![
            p(
                "errcode",
                "string",
                "Matrix error code (default M_FORBIDDEN)",
                false,
            ),
            p(
                "error",
                "string",
                "Human-readable reason shown to the client",
                false,
            ),
        ],
        json!({"type": REJECT, "errcode": "M_FORBIDDEN", "error": "This room is closed"}),
        "-> Matrix reject {errcode}",
    )
}

pub fn send_action() -> ActionDefinition {
    action(
        SEND,
        "Post a message into a room as NetGet's own user (who joins the room if needed). Implies accepting the request being answered.",
        vec![
            p(
                "room_id",
                "string",
                "Room to post in (default: the room of the event being answered)",
                false,
            ),
            p(
                "body",
                "string",
                "Text of an m.text message",
                false,
            ),
            p(
                "msgtype",
                "string",
                "Message type for body: m.text (default), m.notice or m.emote",
                false,
            ),
            p(
                "content",
                "object",
                "Full event content instead of body/msgtype",
                false,
            ),
            p(
                "event_type",
                "string",
                "Event type (default m.room.message)",
                false,
            ),
        ],
        json!({"type": SEND, "body": "Welcome to the room"}),
        "-> Matrix send {body}",
    )
}

fn ev(id: &str, description: &str, params: Vec<Parameter>, send: bool) -> EventType {
    let mut actions = vec![accept_action(), reject_action()];
    if send {
        actions.push(send_action());
    }
    EventType::new(id, description, json!({"type": ACCEPT}))
        .with_parameters(params)
        .with_actions(actions)
}

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "matrix_login",
        "A client logs in with a password (only asked when no user_passwords table was configured; the password is not shown). Accept or reject.",
        vec![
            p("user_id", "string", "The full Matrix user id", true),
            p("device_id", "string", "The device the client logs in as", true),
        ],
        false,
    )
});

pub static CREATE_ROOM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "matrix_create_room",
        "A user asks to create a room. Accept (optionally posting a greeting with matrix_send) or reject.",
        vec![
            p("user_id", "string", "The full user id of who asks", true),
            p("name", "string", "The requested room name, if any", false),
            p("invite", "array", "Users the creator invites", true),
        ],
        true,
    )
});

pub static JOIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "matrix_join",
        "A user asks to join a room. Accept or reject.",
        vec![
            p("user_id", "string", "The full user id of who asks", true),
            p("room_id", "string", "The room id it happened in", true),
            p("room_name", "string", "The room's name, if any", false),
            p(
                "invited",
                "boolean",
                "Whether the user had been invited",
                true,
            ),
        ],
        true,
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "matrix_room_message",
        "A user sends an event into a room. Accept it (it is delivered to the room), reply with matrix_send (which also accepts it), or reject it (nobody sees it).",
        vec![
            p("room_id", "string", "The room id it happened in", true),
            p("room_name", "string", "The room's name, if any", false),
            p("sender", "string", "The full user id of who sent it", true),
            p("event_type", "string", "e.g. m.room.message", true),
            p("content", "object", "The event content, e.g. {msgtype, body}", true),
            p("members", "array", "The room's members", true),
        ],
        true,
    )
});

pub fn check(v: &Value) -> Result<()> {
    let s = |k: &str| v.get(k).filter(|x| !x.is_null());
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT => Ok(()),
        REJECT => {
            if let Some(c) = s("errcode") {
                let c = c.as_str().unwrap_or_default();
                if !c.starts_with("M_") || c.len() > 64 {
                    bail!("errcode must be a Matrix error code such as M_FORBIDDEN");
                }
            }
            Ok(())
        }
        SEND => {
            match (s("body"), s("content")) {
                (None, None) => bail!("matrix_send needs body or content"),
                (_, Some(c)) if !c.is_object() => bail!("content must be an object"),
                (Some(b), _) if !b.is_string() => bail!("body must be a string"),
                _ => {}
            }
            if let Some(m) = s("msgtype").and_then(Value::as_str) {
                if !matches!(m, "m.text" | "m.notice" | "m.emote") {
                    bail!("msgtype must be m.text, m.notice or m.emote");
                }
            }
            if let Some(r) = s("room_id") {
                if !r.as_str().is_some_and(|r| r.starts_with('!')) {
                    bail!("room_id must be a room id such as !abc:localhost");
                }
            }
            Ok(())
        }
        other => bail!("Unknown Matrix action {other:?}"),
    }
}

/// The event content a `matrix_send` posts.
pub fn send_content(v: &Value) -> Value {
    if let Some(c) = v.get("content").filter(|c| c.is_object()) {
        return c.clone();
    }
    json!({
        "msgtype": v["msgtype"].as_str().unwrap_or("m.text"),
        "body": v["body"].as_str().unwrap_or_default(),
    })
}

impl Protocol for MatrixProtocol {
    fn protocol_name(&self) -> &'static str {
        "Matrix"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Matrix"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["matrix", "homeserver", "synapse", "element", "chat", "8008"]
    }
    fn description(&self) -> &'static str {
        "Matrix homeserver (client-server API v3): password login, rooms with invites and joins, messages delivered through long-polling /sync; the model gates logins, rooms and messages and talks in rooms as its own user"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept_action(), reject_action(), send_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            LOGIN_EVENT.clone(),
            CREATE_ROOM_EVENT.clone(),
            JOIN_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "server_name".into(),
                type_hint: "string".into(),
                description: "The homeserver's name, the part after ':' in user and room ids".into(),
                required: false,
                example: json!("example.org"),
                default: Some(json!(DEFAULT_SERVER_NAME)),
            },
            ParameterDefinition {
                name: "user_passwords".into(),
                type_hint: "object".into(),
                description: "Accounts as {localpart: password}; when given, Rust checks passwords and the model is not asked about logins".into(),
                required: false,
                example: json!({"alice": "wonderland"}),
                default: None,
            },
            ParameterDefinition {
                name: "bot_user".into(),
                type_hint: "string".into(),
                description: "Localpart of the user the model speaks as in rooms".into(),
                required: false,
                example: json!("assistant"),
                default: Some(json!(DEFAULT_BOT_USER)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(8008)
            .implementation("HTTP/1.1 via hyper (src/server/matrix): /_matrix/client/versions, v3 login (m.login.password), logout, account/whoami, createRoom (name, invite), join and rooms/{id}/join, rooms/{id}/send (with transaction-id idempotence), rooms/{id}/messages, joined_rooms, joined_members, user filters, and /sync with since tokens, invites and long polling (timeout capped at 30 s); tokens, membership and per-user delivery queues in src/server/matrix/hub.rs")
            .llm_control("Logins (unless user_passwords is given), room creation, joins and every message: accept, reject with a Matrix errcode, or answer in the room as its own user")
            .e2e_testing("tests/server/matrix: matrix-nio (an independent Python client) logs in, creates a room inviting a second nio client that joins, sends, and receives the model's reply through /sync; refusals and bounds over raw HTTP")
            .notes("No federation, no end-to-end encryption (keys endpoints are 404 M_UNRECOGNIZED), no media repository, no registration, no presence or typing. Rooms are state the server holds while it runs; room history keeps the last 200 events and each user's undelivered queue 1000. A handler failure is a 500 M_UNKNOWN with a generic message; the message it was asked about is not delivered.")
            .request_only("Every response answers an HTTP request")
            .answers_on_failure()
            .max_inbound_bytes(MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Matrix homeserver on port 8008 where the bot answers every message in the room"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"matrix","port":0,
            "startup_params":{"user_passwords":{"alice":"wonderland","bob":"builder"}},
            "instruction":"Accept rooms and joins; answer every m.text message with matrix_send, replying 'echo: ' plus its body"});
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"matrix_room_message","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nb=e['content'].get('body','')\nprint(json.dumps({'actions':[{'type':'matrix_send','body':'echo: '+b}] if e['sender'].startswith('@alice') else [{'type':'matrix_accept'}]}))"}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        let mut static_example = base.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for MatrixProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        let name = action["type"].as_str().unwrap_or_default().to_string();
        Ok(ActionResult::Custom { name, data: action })
    }
}
