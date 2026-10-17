//! What the model does as an ActivityPub instance: answer Follow requests, post notes (to
//! followers and named actors), like, follow and unfollow — in answer to every activity
//! that arrives, signed, at an inbox. Rust owns WebFinger, actor documents, keys, HTTP
//! Signatures and delivery.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT: &str = "activitypub_accept";
pub const REJECT: &str = "activitypub_reject";
pub const POST: &str = "activitypub_post";
pub const LIKE: &str = "activitypub_like";
pub const FOLLOW: &str = "activitypub_follow";
pub const UNFOLLOW: &str = "activitypub_unfollow";
/// The actors an instance hosts when none are configured.
pub const DEFAULT_ACTORS: &[&str] = &["netget"];
/// A note's text is at most this long.
pub const MAX_CONTENT: usize = 10_000;

#[derive(Default, Clone)]
pub struct ActivityPubProtocol;

impl ActivityPubProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
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
        log_template: Some(LogTemplate::new().with_info(format!(
            "-> ActivityPub {}",
            name.trim_start_matches("activitypub_")
        ))),
    }
}

fn as_param() -> Parameter {
    p(
        "as",
        "string",
        "Which local actor acts (default: the one whose inbox it was, else the first)",
        false,
    )
}

pub fn post_action() -> ActionDefinition {
    action(
        POST,
        "Publish a note: delivered to the actor's followers and to anyone in `to`.",
        vec![
            p(
                "content",
                "string",
                "The note's text (plain text; NetGet makes the HTML)",
                true,
            ),
            p(
                "to",
                "array",
                "Extra recipients: actor URLs or handles like alice@example.social",
                false,
            ),
            p(
                "public",
                "boolean",
                "Address it to the public as well (default true)",
                false,
            ),
            p(
                "in_reply_to",
                "string",
                "The id of the note this answers",
                false,
            ),
            as_param(),
        ],
        json!({"type": POST, "content": "Hello, fediverse", "public": true}),
    )
}

pub fn target_param() -> Parameter {
    p(
        "target",
        "string",
        "An actor URL or a handle like alice@example.social",
        true,
    )
}

pub fn shared_actions() -> Vec<ActionDefinition> {
    vec![
        post_action(),
        action(LIKE, "Like an object, telling its author.",
            vec![p("object", "string", "The id of the object liked", true),
                 p("to", "string", "Whom to tell: the author's actor URL or handle (default: whoever sent the event)", false), as_param()],
            json!({"type": LIKE, "object": "https://example.social/notes/1"})),
        action(FOLLOW, "Follow a remote actor (it answers with Accept or Reject).",
            vec![target_param(), as_param()],
            json!({"type": FOLLOW, "target": "alice@example.social"})),
        action(UNFOLLOW, "Stop following a remote actor.",
            vec![target_param(), as_param()],
            json!({"type": UNFOLLOW, "target": "alice@example.social"})),
    ]
}

pub fn all_actions() -> Vec<ActionDefinition> {
    let mut v = vec![
        action(
            ACCEPT,
            "Accept the Follow request being answered: the follower is added and sent an Accept.",
            vec![],
            json!({"type": ACCEPT}),
        ),
        action(
            REJECT,
            "Refuse the Follow request being answered: the follower is sent a Reject.",
            vec![],
            json!({"type": REJECT}),
        ),
    ];
    v.extend(shared_actions());
    v
}

pub static ACTIVITY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "activitypub_activity",
        "A signed activity arrived at an inbox (Follow, Undo, Create, Like, Announce, …). The signature, digest and date were verified and the actor is the signer. For a Follow, answer activitypub_accept or activitypub_reject.",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("to_actor", "string", "The local actor whose inbox it was (absent for the shared inbox)", false),
        p("type", "string", "The activity type, e.g. Follow, Create, Like, Undo", true),
        p("id", "string", "The activity's id", false),
        p("actor", "string", "The sender's actor URL (proven by its signature)", true),
        p("actor_handle", "string", "The sender as user@host, when its document names a username", false),
        p("object_type", "string", "The type of the object, e.g. Note", false),
        p("object_id", "string", "The object's id (for a Follow: whom it follows)", false),
        p("content", "string", "A note's text, HTML removed", false),
        p("in_reply_to", "string", "What a note answers", false),
    ])
    .with_actions(all_actions())
});

pub fn check(v: &Value) -> Result<()> {
    let s = |k: &str| v.get(k).filter(|x| !x.is_null());
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT | REJECT => {}
        POST => {
            let c = v["content"].as_str().context("content is required")?;
            ensure!(
                !c.is_empty() && c.len() <= MAX_CONTENT,
                "content must be 1-{MAX_CONTENT} bytes"
            );
            if let Some(to) = s("to") {
                ensure!(
                    to.as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string)),
                    "to must be a list of actors"
                );
            }
        }
        LIKE => {
            v["object"].as_str().context("object is required")?;
        }
        FOLLOW | UNFOLLOW => {
            let t = v["target"].as_str().context("target is required")?;
            ensure!(
                t.starts_with("http") || t.contains('@'),
                "target must be an actor URL or user@host"
            );
        }
        other => bail!("Unknown ActivityPub action {other:?}"),
    }
    Ok(())
}

impl Protocol for ActivityPubProtocol {
    fn protocol_name(&self) -> &'static str {
        "ActivityPub"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>ActivityPub"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "activitypub",
            "fediverse",
            "mastodon",
            "webfinger",
            "federation",
        ]
    }
    fn description(&self) -> &'static str {
        "ActivityPub instance (server-to-server): WebFinger, actors with RSA keys, signed inboxes and delivery; the model answers Follows and posts, likes and follows as its actors"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![ACTIVITY_EVENT.clone()]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "actors".into(),
                type_hint: "array".into(),
                description: "Usernames of the actors this instance hosts".into(),
                required: false,
                example: json!(["netget", "bot"]),
                default: Some(json!(DEFAULT_ACTORS)),
            },
            ParameterDefinition {
                name: "base_url".into(),
                type_hint: "string".into(),
                description: "The public URL ids are built from, e.g. https://social.example (default: http:// and the address it listens on)".into(),
                required: false,
                example: json!("https://social.example"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1 (src/server/activitypub): WebFinger, NodeInfo 2.1, Person actors with RSA-2048 keys, followers/following/outbox collections, notes; inboxes (per actor and shared) verify draft-cavage HTTP Signatures (rsa-sha256) over (request-target), host, date and digest, with the signer's key fetched and the activity's actor required to be the signer; outgoing GETs and deliveries are signed the same way (reqwest)")
            .llm_control("Every verified activity: whether to accept Follows, and what to post, like and follow in answer")
            .e2e_testing("tests/server/activitypub: Fedify 2.4.2 — its CLI resolves and parses NetGet's actor (webfinger, lookup), and an actor built on the Fedify library follows NetGet's actor and verifies its signed Accept and Create; raw HTTP for refused signatures and bounds")
            .notes("No object integrity proofs, no RFC 9421 signatures (Fedify falls back to draft-cavage after a 401), no authorized-fetch enforcement on GETs, no media, no Announce/boost sending, no persistence: followers, outboxes and notes live while the server runs (bounded). Inbox POSTs and fetched documents are capped at 1 MiB, deliveries at 100 inboxes per post.")
            .request_only("Every response answers an HTTP request; deliveries are separate requests")
            .answers_on_failure()
            .max_inbound_bytes(super::instance::MAX_DOCUMENT)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ActivityPub instance hosting @netget that accepts every follower and greets them with a post"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"activitypub","port":0,
            "instruction":"Accept every Follow and post a public greeting naming the new follower"});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"activitypub_activity","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[]\nif e['type']=='Follow': a=[{'type':'activitypub_accept'},{'type':'activitypub_post','content':'Welcome '+e['actor']}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for ActivityPubProtocol {
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
