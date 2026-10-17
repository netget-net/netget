//! What the model does as one fediverse actor: look actors up, follow and unfollow, post
//! notes, like and fetch. The actor is real: NetGet serves its document, key and inbox on a
//! local port, because federation only works when the other side can fetch the signer's
//! key and deliver Accepts back.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::activitypub::actions::{self as server, action, p, target_param};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const LOOKUP: &str = "activitypub_lookup";
pub const FETCH: &str = "activitypub_fetch";
/// The client's actor when none is named.
pub const DEFAULT_USERNAME: &str = "netget";
/// Where the client's actor is served when nowhere is named.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:0";

#[derive(Default)]
pub struct ActivityPubClientProtocol;
impl ActivityPubClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut v = vec![
        action(
            LOOKUP,
            "Find an actor by handle (WebFinger) or URL and read its profile.",
            vec![target_param()],
            json!({"type": LOOKUP, "target": "alice@example.social"}),
        ),
        action(
            FETCH,
            "Fetch any ActivityStreams object by URL (signed by this actor).",
            vec![p("url", "string", "The object's URL, e.g. a note id", true)],
            json!({"type": FETCH, "url": "https://example.social/notes/1"}),
        ),
    ];
    v.extend(server::shared_actions().into_iter().map(|mut a| {
        a.parameters.retain(|p| p.name != "as");
        a
    }));
    v.push(action(
        "disconnect",
        "Stop: the actor's endpoint goes away.",
        vec![],
        json!({"type": "disconnect"}),
    ));
    v
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": server::FOLLOW, "target": "alice@example.social"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "activitypub_ready",
        "The actor is up: its document, key and inbox are being served.",
        vec![
            p("actor_id", "string", "This actor's URL", true),
            p("handle", "string", "This actor as user@host", true),
            p(
                "remote",
                "string",
                "The remote_addr the client was opened with (a handle, URL or host)",
                true,
            ),
        ],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("activitypub_response", "What an action came to.", vec![
        p("operation", "string", "The action that was performed", true),
        p("ok", "boolean", "Whether it succeeded", true),
        p("result", "object", "lookup: the actor's profile; fetch: the object; follow/post/like: the actor and delivery statuses", false),
        p("error", "string", "Why the action failed (the remote's status, or a refused signature or lookup)", false),
    ])
});

pub static ACTIVITY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("activitypub_activity", "A signed activity arrived at this actor's inbox (Accept or Reject of a Follow, a Create, a Like, …); its signature was verified.", vec![
        p("type", "string", "The activity type, e.g. Accept, Create", true),
        p("actor", "string", "The sender's actor URL (proven by its signature)", true),
        p("actor_handle", "string", "The sender as user@host", false),
        p("object_type", "string", "The type of the object", false),
        p("object_id", "string", "The object's id", false),
        p("content", "string", "A note's text, HTML removed", false),
        p("in_reply_to", "string", "What a note answers", false),
    ])
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        LOOKUP => {
            let t = v["target"].as_str().context("target is required")?;
            ensure!(
                t.starts_with("http") || t.contains('@'),
                "target must be an actor URL or user@host"
            );
            Ok(())
        }
        FETCH => {
            let u = v["url"].as_str().context("url is required")?;
            ensure!(
                u.starts_with("http://") || u.starts_with("https://"),
                "url must be http(s)"
            );
            Ok(())
        }
        server::ACCEPT | server::REJECT => bail!("a client answers no Follow requests"),
        _ => server::check(v),
    }
}

impl Protocol for ActivityPubClientProtocol {
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
            "follow",
            "mastodon client",
            "webfinger lookup",
        ]
    }
    fn description(&self) -> &'static str {
        "One fediverse actor: looks actors up, follows, posts, likes and fetches, with signed requests, and hears what arrives at its inbox"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            ACTIVITY_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "This actor's username".into(),
                required: false,
                example: json!("bot"),
                default: Some(json!(DEFAULT_USERNAME)),
            },
            ParameterDefinition {
                name: "listen".into(),
                type_hint: "string".into(),
                description: "Address the actor's document and inbox are served on (remote servers must reach it)".into(),
                required: false,
                example: json!("0.0.0.0:8443"),
                default: Some(json!(DEFAULT_LISTEN)),
            },
            ParameterDefinition {
                name: "base_url".into(),
                type_hint: "string".into(),
                description: "The public URL remote servers reach the actor at (default: http:// and the listen address)".into(),
                required: false,
                example: json!("https://bot.example"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's instance with a single actor: WebFinger resolution, signed GETs and deliveries (draft-cavage rsa-sha256), and its own document, key and verified inbox served on a local port")
            .llm_control("Whom to look up, follow and unfollow, what to post and like, and how to answer what arrives at the inbox")
            .e2e_testing("tests/client/activitypub: an actor built on the Fedify 2.4.2 library, which verifies NetGet's signed Follow, answers it with a signed Accept NetGet verifies, receives NetGet's signed Create, and serves the WebFinger a lookup resolves")
            .notes("The remote must be able to reach the actor's listen address. No media, no boosts, no persistence. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Follow alice@example.social and say hello to her"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"activitypub","remote_addr":"alice@example.social",
            "instruction":"Follow alice and, once she accepts, send her a hello note"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"activitypub_ready","handler":{"type":"static","actions":[{"type":server::FOLLOW,"target":"alice@example.social"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='activitypub_ready': a=[{'type':'activitypub_follow','target':e['remote']}]\nelif t=='activitypub_activity' and e['type']=='Accept': a=[{'type':'activitypub_post','content':'hello','to':[e['actor']],'public':False}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for ActivityPubClientProtocol {
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
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
