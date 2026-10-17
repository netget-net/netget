use crate::protocol::log_template::LogTemplate;
use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, Parameter, ParameterDefinition,
    },
    protocol::{ConnectContext, EventType},
    state::AppState,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct NostrClientProtocol;
impl NostrClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
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
        log_template: Some(LogTemplate::new().with_info(format!("Nostr {name} queued"))),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        action("nostr_publish", "Sign and publish a native NIP-01 event with this client's private startup identity. Only the public signed event goes on the wire; a later correlated OK reports acceptance or refusal.", vec![p("kind", "integer", "NIP-01 kind0..65535; no local kind/archive policy", true), p("content", "string", "Unmodified UTF8 content, at most64KiB", true), p("tags", "array", "At most2000 nonempty string arrays,32 items each; default empty", false), p("created_at", "integer", "Nonnegative Unix seconds; default current time", false)], json!({"type":"nostr_publish","kind":1,"content":"hello from NetGet","tags":[["t","film"]]})),
        action("nostr_subscribe", "Send REQ with1..10 selected NIP-01 filters. Reusing an id replaces its filters; EOSE keeps the live subscription open. Limit0 requests only future events.", vec![p("subscription_id", "string", "Nonempty id, at most64 Unicode characters", true), p("filters", "array", "OR between filters, AND within each: ids/authors full lowercase hex, kinds, since/until, limit0..500, or #single-letter tag lists. No extension search/count/auth.", true)], json!({"type":"nostr_subscribe","subscription_id":"film","filters":[{"kinds":[1],"#t":["film"],"limit":0}]})),
        action("nostr_close", "Send CLOSE and forget the selected subscription locally. NIP-01 provides no close acknowledgement; already-selected relay frames can still arrive and are ignored.", vec![p("subscription_id", "string", "An open subscription id", true)], json!({"type":"nostr_close","subscription_id":"film"})),
        action("nostr_relay_info", "Fetch selected optional NIP-11 metadata from the same relay URL. Advertised capabilities and limits are informational; no automatic AUTH, COUNT or payment.", vec![], json!({"type":"nostr_relay_info"})),
        action("disconnect", "Cancel pending I/O and stop this WebSocket client", vec![], json!({"type":"disconnect"})),
    ]
}
fn event(id: &str, description: &str, parameters: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type":"nostr_subscribe","subscription_id":"film","filters":[{"kinds":[1],"limit":0}]})).with_parameters(parameters).with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nostr_connected",
        "Verified WebSocket upgrade; this client's public signing identity",
        vec![
            p("relay_url", "string", "WS or WSS endpoint", true),
            p(
                "pubkey",
                "string",
                "Public signing key only; relay identity is separate NIP-11 self",
                true,
            ),
        ],
    )
});
pub static EVENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("nostr_received_event", "A complete event with validated content hash and BIP-340 signature",vec![p("subscription_id","string","Current local subscription id",true),p("event","object","Full public native event: id,pubkey,created_at,kind,tags,content,sig",true),p("stored_phase","boolean","True before EOSE, false afterwards; does not imply local storage",true),p("matches_current_filters","boolean","Informational current-filter match; already-selected frames can reflect earlier filters after replacement",true)])
});
pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nostr_publish_result",
        "Correlated native OK, or a bounded wait that expired without an OK",
        vec![
            p("id", "string", "Published event id", true),
            p(
                "status",
                "string",
                "ok or timeout; timeout does not prove relay rejection",
                true,
            ),
            p(
                "accepted",
                "boolean|null",
                "Native OK boolean, null on timeout",
                true,
            ),
            p(
                "message",
                "string",
                "Native relay message, fixed deadline text on timeout",
                true,
            ),
            p(
                "reason_prefix",
                "string|null",
                "Native machine-readable reason prefix, including unknown extension prefixes",
                true,
            ),
        ],
    )
});
pub static SUBSCRIPTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nostr_subscription",
        "EOSE, native CLOSED, or local CLOSE receipt",
        vec![
            p(
                "subscription_id",
                "string",
                "Affected subscription identifier",
                true,
            ),
            p(
                "status",
                "string",
                "eose, closed, or local_close; EOSE remains live",
                true,
            ),
            p(
                "message",
                "string",
                "Native CLOSED reason; empty on EOSE/local close",
                true,
            ),
            p(
                "reason_prefix",
                "string|null",
                "Native CLOSED reason prefix",
                true,
            ),
        ],
    )
});
pub static NOTICE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nostr_notice",
        "Native NOTICE or explicit unsupported extension receipt",
        vec![
            p(
                "message",
                "string",
                "Native bounded NOTICE, or fixed unsupported-extension text",
                true,
            ),
            p(
                "message_type",
                "string",
                "NOTICE, AUTH, COUNT, or unknown; no challenge echoed",
                true,
            ),
            p(
                "supported",
                "boolean",
                "False for extension messages this client cannot perform",
                true,
            ),
        ],
    )
});
pub static INFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("nostr_relay_information", "Selected optional NIP-11 metadata without fabricated capabilities",vec![p("information","object","Optional name/description/contact/images/keys/software/version/supported_nips and selected typed limitation fields. Unknown fields ignored, absent fields remain absent; no negotiated policy claim.",true)])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nostr_request_error",
        "Local selected-action or NIP-11 transport/schema failure; no raw payload diagnostic",
        vec![
            p(
                "category",
                "string",
                "action, relay_info, or relay_schema",
                true,
            ),
            p(
                "error",
                "string",
                "Bounded fixed validation/transport diagnostic",
                true,
            ),
        ],
    )
});
impl Protocol for NostrClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Nostr"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WS>NOSTR"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nostr", "nip-01"]
    }
    fn description(&self) -> &'static str {
        "Selected signed Nostr publishing and subscriptions"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn example_prompt(&self) -> &'static str {
        "Subscribe to live film notes at ws://localhost:7777"
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
            EVENT_EVENT.clone(),
            RESULT_EVENT.clone(),
            SUBSCRIPTION_EVENT.clone(),
            NOTICE_EVENT.clone(),
            INFO_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition{name:"secret_key".into(),type_hint:"string".into(),description:"Optional64 hex secp256k1 private signing key; generated identity by default. Never offered to handlers, events or incidental diagnostics. No key helper/file.".into(),required:false,example:json!("<64 hex characters>"),default:None},
            ParameterDefinition{name:"request_timeout_secs".into(),type_hint:"integer".into(),description:"Whole connect/upgrade, individual write/NIP-11 and publish-OK deadline1..30 seconds; no idle subscription deadline".into(),required:false,example:json!(10),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))},
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Native NIP-01 EVENT/REQ/CLOSE and validated EVENT/OK/EOSE/CLOSED/NOTICE; selected NIP-11 metadata").llm_control("Typed public event content and filters, common memory/event handlers/injection, private signing outside model").e2e_testing("tests/client/nostr: independent nak relay/CLI, existing independent relay-server SDK evidence, NetGet pair and mocked model; bounded schemas, queues, correlations and owned cancellation").notes("No event archive or domain database. Native WS/WSS verifies certificates; browser WS only. Messages128KiB, content64KiB, tags2000x32, filter lists500, filters10, subscriptions20, pending publishes16, queues8, handler followups4; JSON depth8/nodes25000/retained2MiB. One owned NIP-11 request. Publish deadline does not infer rejection. EOSE remains live; CLOSE has no acknowledgement. Already-selected frames after close are ignored; after replacement current-filter match is informational. NIP-11 fields optional, unknown extensions ignored. No AUTH/COUNT, relay pool, private-key actions, custom trust/client certificates, URL credentials/query, proxies/redirects, automatic reconnect/replay/retry, local replacement/expiration/storage policy, encrypted messages or conformance claim. Existing relay NIP-42/45 refusals preserved.").max_inbound_bytes(crate::server::nostr::wire::MAX_MESSAGE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","base_stack":"nostr","protocol":"nostr","remote_addr":"ws://127.0.0.1:7777","instruction":"Subscribe to live film notes and explain relay notices"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"nostr_connected","handler":{"type":"static","actions":[{"type":"nostr_subscribe","subscription_id":"film","filters":[{"kinds":[1],"#t":["film"],"limit":0}]}]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\njson.dump({'actions':[{'type':'nostr_subscribe','subscription_id':'film','filters':[{'kinds':[1],'#t':['film'],'limit':0}]}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for NostrClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        if !super::api::within_budget(&value) {
            crate::utils::json_budget::drop_iteratively(value);
            bail!("Nostr action depth/node/retained-content limit");
        }
        match super::api::action(&value)? {
            super::api::Action::Disconnect => Ok(ClientActionResult::Disconnect),
            _ => Ok(ClientActionResult::Custom {
                name: "nostr".into(),
                data: value,
            }),
        }
    }
}
