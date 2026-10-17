//! What the model does as a Matrix user: create rooms (inviting people), join, invite,
//! leave, read a room's recent history and send messages. Logging in, `/sync` and
//! transaction ids are Rust's.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct MatrixClientProtocol;
impl MatrixClientProtocol {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> Matrix {name}"))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "matrix_create_room",
            "Create a room and optionally invite users into it.",
            vec![
                p("name", "string", "The room's name", false),
                p("topic", "string", "The room's topic", false),
                p(
                    "invite",
                    "array",
                    "Full user ids to invite, e.g. [\"@bob:example.org\"]",
                    false,
                ),
            ],
            json!({"type": "matrix_create_room", "name": "standup", "invite": ["@bob:localhost"]}),
        ),
        action(
            "matrix_join",
            "Join a room (accepting an invite), by id or alias.",
            vec![p(
                "room",
                "string",
                "Room id (!abc:server) or alias (#name:server)",
                true,
            )],
            json!({"type": "matrix_join", "room": "!abc:localhost"}),
        ),
        action(
            "matrix_send",
            "Send a message into a room you are in.",
            vec![
                p(
                    "room_id",
                    "string",
                    "The room id, e.g. !abc:localhost",
                    true,
                ),
                p("body", "string", "Text of an m.text message", false),
                p(
                    "msgtype",
                    "string",
                    "m.text (default), m.notice or m.emote",
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
            json!({"type": "matrix_send", "room_id": "!abc:localhost", "body": "hello"}),
        ),
        action(
            "matrix_invite",
            "Invite a user into a room you are in.",
            vec![
                p(
                    "room_id",
                    "string",
                    "The room id, e.g. !abc:localhost",
                    true,
                ),
                p("user_id", "string", "Full user id to invite", true),
            ],
            json!({"type": "matrix_invite", "room_id": "!abc:localhost", "user_id": "@bob:localhost"}),
        ),
        action(
            "matrix_leave",
            "Leave a room (or decline an invite).",
            vec![p(
                "room_id",
                "string",
                "The room id, e.g. !abc:localhost",
                true,
            )],
            json!({"type": "matrix_leave", "room_id": "!abc:localhost"}),
        ),
        action(
            "matrix_messages",
            "Read a room's most recent events.",
            vec![
                p(
                    "room_id",
                    "string",
                    "The room id, e.g. !abc:localhost",
                    true,
                ),
                p(
                    "limit",
                    "number",
                    "How many events, newest first (default 10, at most 100)",
                    false,
                ),
            ],
            json!({"type": "matrix_messages", "room_id": "!abc:localhost", "limit": 10}),
        ),
        action(
            "disconnect",
            "Log out and end this session.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": "matrix_send", "room_id": "!abc:localhost", "body": "hello"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "matrix_connected",
        "Logged in; the client now follows /sync. Events from before this moment are not replayed.",
        vec![
            p("user_id", "string", "Who the client is logged in as", true),
            p("device_id", "string", "The device id it logged in as", true),
            p("joined_rooms", "array", "Rooms it is already in", true),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "matrix_message",
        "Someone else posted an event in a room the client is in.",
        vec![
            p("room_id", "string", "The room id it happened in", true),
            p("sender", "string", "The full user id of who sent it", true),
            p("event_type", "string", "e.g. m.room.message", true),
            p(
                "content",
                "object",
                "Its content, e.g. {msgtype, body}",
                true,
            ),
            p("event_id", "string", "The event id, e.g. $abc", true),
        ],
    )
});

pub static INVITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "matrix_invite",
        "The client was invited into a room; matrix_join accepts, matrix_leave declines.",
        vec![
            p("room_id", "string", "The room id it happened in", true),
            p("sender", "string", "The full user id of who invited", false),
            p("room_name", "string", "The room's name, if shown", false),
        ],
    )
});

pub static MEMBER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "matrix_member",
        "Another user's membership in a room changed (joined, left, was invited).",
        vec![
            p("room_id", "string", "The room id it happened in", true),
            p("user_id", "string", "Whose membership", true),
            p("membership", "string", "join, leave, invite or ban", true),
        ],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "matrix_response",
        "The homeserver answered an action (create_room gives room_id; messages gives events). A send that succeeds raises no event; one that fails does.",
        vec![
            p("operation", "string", "The action that was performed", true),
            p("status", "number", "The HTTP status the homeserver answered with", true),
            p("result", "object", "The answer: {room_id}, {events}, …", true),
            p("errcode", "string", "Matrix error code when it failed", false),
            p("error", "string", "The server's error text when it failed", false),
        ],
    )
});

/// The HTTP request an action makes (method, path under /_matrix/client/v3, body); `txn`
/// numbers a send.
pub fn request(v: &Value, txn: &str) -> Result<(&'static str, String, Option<Value>)> {
    let enc = |s: &str| urlencoding::encode(s).into_owned();
    let room_id = || -> Result<String> {
        let r = v["room_id"].as_str().context("room_id required")?;
        ensure!(
            r.starts_with('!'),
            "room_id must be a room id such as !abc:server"
        );
        Ok(enc(r))
    };
    Ok(match v["type"].as_str().unwrap_or_default() {
        "matrix_create_room" => {
            let mut body = json!({"preset": "private_chat"});
            if let Some(n) = v["name"].as_str() {
                body["name"] = json!(n);
            }
            if let Some(t) = v["topic"].as_str() {
                body["topic"] = json!(t);
            }
            if !v["invite"].is_null() {
                let users: Vec<&str> = v["invite"]
                    .as_array()
                    .context("invite must be an array of user ids")?
                    .iter()
                    .map(|u| u.as_str().filter(|u| u.starts_with('@') && u.contains(':')))
                    .collect::<Option<_>>()
                    .context("invite entries must be full user ids such as @bob:server")?;
                body["invite"] = json!(users);
            }
            ("POST", "createRoom".into(), Some(body))
        }
        "matrix_join" => {
            let r = v["room"].as_str().context("room required")?;
            ensure!(
                r.starts_with('!') || r.starts_with('#'),
                "room must be a room id or alias"
            );
            ("POST", format!("join/{}", enc(r)), Some(json!({})))
        }
        "matrix_send" => {
            let content = match (
                v.get("content").filter(|c| !c.is_null()),
                v["body"].as_str(),
            ) {
                (Some(c), _) => {
                    ensure!(c.is_object(), "content must be an object");
                    c.clone()
                }
                (None, Some(b)) => {
                    let msgtype = v["msgtype"].as_str().unwrap_or("m.text");
                    ensure!(
                        matches!(msgtype, "m.text" | "m.notice" | "m.emote"),
                        "msgtype must be m.text, m.notice or m.emote"
                    );
                    json!({"msgtype": msgtype, "body": b})
                }
                (None, None) => bail!("matrix_send needs body or content"),
            };
            let kind = v["event_type"].as_str().unwrap_or("m.room.message");
            ensure!(
                !kind.is_empty() && kind.len() <= 255,
                "event_type is invalid"
            );
            (
                "PUT",
                format!("rooms/{}/send/{}/{}", room_id()?, enc(kind), enc(txn)),
                Some(content),
            )
        }
        "matrix_invite" => {
            let u = v["user_id"].as_str().context("user_id required")?;
            ensure!(
                u.starts_with('@') && u.contains(':'),
                "user_id must be a full user id"
            );
            (
                "POST",
                format!("rooms/{}/invite", room_id()?),
                Some(json!({"user_id": u})),
            )
        }
        "matrix_leave" => (
            "POST",
            format!("rooms/{}/leave", room_id()?),
            Some(json!({})),
        ),
        "matrix_messages" => {
            let limit = v["limit"].as_u64().unwrap_or(10).clamp(1, 100);
            (
                "GET",
                format!("rooms/{}/messages?dir=b&limit={limit}", room_id()?),
                None,
            )
        }
        t => bail!("Unknown Matrix client action {t:?}"),
    })
}

impl Protocol for MatrixClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Matrix"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Matrix"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["matrix", "matrix client", "synapse", "element", "chat bot"]
    }
    fn description(&self) -> &'static str {
        "Matrix client (client-server API v3): logs in with a password, follows /sync, and creates, joins and talks in rooms"
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
            MESSAGE_EVENT.clone(),
            INVITE_EVENT.clone(),
            MEMBER_EVENT.clone(),
            RESPONSE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "The account to log in as: a localpart (alice) or a full user id"
                    .into(),
                required: true,
                example: json!("alice"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "That account's password (m.login.password)".into(),
                required: true,
                example: json!("wonderland"),
                default: None,
            },
            ParameterDefinition {
                name: "device_id".into(),
                type_hint: "string".into(),
                description: "Device id to log in as (default: the server assigns one)".into(),
                required: false,
                example: json!("NETGET"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("HTTP/1.1 via hyper, one connection per request: v3 login (m.login.password), long-polling /sync (25 s) raising messages, invites and membership changes, createRoom, join, invite, leave, rooms/{id}/send with transaction ids, rooms/{id}/messages, logout")
            .llm_control("Which rooms to create, join or leave, whom to invite, what to say, and how to answer every message and invite")
            .e2e_testing("tests/client/matrix: Synapse (the reference homeserver), with a matrix-nio user as the other participant reading what NetGet said")
            .notes("No end-to-end encryption (encrypted rooms' messages arrive as m.room.encrypted and cannot be read), no media, no registration. Events from before login are not replayed. Answers are capped at 4 MiB. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Log into the Matrix homeserver at 127.0.0.1:8008 as alice and answer every message in the rooms you are invited to"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"matrix","remote_addr":"127.0.0.1:8008",
            "startup_params":{"user":"alice","password":"wonderland"},
            "instruction":"Join every room you are invited to and answer 'pong' to every 'ping'"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"matrix_connected","handler":{"type":"static","actions":[{"type":"matrix_create_room","name":"netget","invite":["@bob:localhost"]}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='matrix_invite': a=[{'type':'matrix_join','room':e['room_id']}]\nelif t=='matrix_message' and e['content'].get('body')=='ping': a=[{'type':'matrix_send','room_id':e['room_id'],'body':'pong'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for MatrixClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        request(&v, "0")?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
