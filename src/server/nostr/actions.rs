//! Nostr relay actions: what the model is told, and how its answers become relay messages.
//!
//! The model decides two things — whether a published event is taken, and which events answer a
//! subscription — and supplies the content of those events. It never writes a relay message, an
//! id or a signature: NetGet renders every frame, and signs the model's events with the relay's
//! own key (see [`super::wire::RelayKey`] for why).

use super::subscriptions::ConnShared;
use super::wire::{self, RelayKey};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};

/// What `relay_name` defaults to.
pub const DEFAULT_RELAY_NAME: &str = "NetGet relay";
/// What `relay_description` defaults to.
pub const DEFAULT_RELAY_DESCRIPTION: &str = "A Nostr relay whose answers are written by a model";
/// What `supported_nips` defaults to: the two this relay implements.
pub const DEFAULT_SUPPORTED_NIPS: &[u64] = &[1, 11];

/// Content longer than this reaches the model cut, with `content_truncated` set.
pub const MAX_CONTENT_FOR_MODEL: usize = 4096;
/// Tags past this many reach the model as a count only.
pub const MAX_TAGS_FOR_MODEL: usize = 50;

/// The connection a protocol instance answers for.
#[derive(Clone)]
struct Binding {
    key: Arc<RelayKey>,
    conn: Arc<ConnShared>,
}

pub struct NostrProtocol {
    binding: Option<Binding>,
}

impl NostrProtocol {
    /// The registry's instance: validates actions but has no connection to answer on.
    pub fn new() -> Self {
        Self { binding: None }
    }

    /// The instance one connection's events are answered through.
    pub fn for_connection(key: Arc<RelayKey>, conn: Arc<ConnShared>) -> Self {
        Self {
            binding: Some(Binding { key, conn }),
        }
    }
}

impl Default for NostrProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for NostrProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "relay_name".to_string(),
                type_hint: "string".to_string(),
                description: "The relay's name in its NIP-11 information document".to_string(),
                required: false,
                example: json!("Film club relay"),
                default: Some(json!(DEFAULT_RELAY_NAME)),
            },
            ParameterDefinition {
                name: "relay_description".to_string(),
                type_hint: "string".to_string(),
                description: "The relay's description in its NIP-11 information document"
                    .to_string(),
                required: false,
                example: json!("Notes about films, one a day"),
                default: Some(json!(DEFAULT_RELAY_DESCRIPTION)),
            },
            ParameterDefinition {
                name: "supported_nips".to_string(),
                type_hint: "array".to_string(),
                description: "NIP numbers listed in the NIP-11 document. The relay implements \
                              NIP-01 and NIP-11; listing more claims more than it does."
                    .to_string(),
                required: false,
                example: json!([1, 11]),
                default: Some(json!(DEFAULT_SUPPORTED_NIPS)),
            },
            ParameterDefinition {
                name: "relay_secret_key".to_string(),
                type_hint: "string".to_string(),
                description: "64 hex characters: the secp256k1 secret key the relay signs the \
                              events it serves with, so its pubkey stays the same across \
                              restarts. Without it a fresh key is generated at startup. Shown \
                              redacted wherever startup parameters are printed."
                    .to_string(),
                required: false,
                example: json!("<64 hex characters>"),
                default: None,
            },
            ParameterDefinition {
                name: "handshake_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer has to send its HTTP request (the \
                              WebSocket upgrade or the NIP-11 GET)."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::HANDSHAKE_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an open WebSocket may go without a single frame from the \
                              client. The relay pings at half of it and every client answers \
                              by itself, so only a peer that stopped reading or vanished is \
                              closed; a subscription left open is not idleness. Never fires \
                              while a message is being answered."
                    .to_string(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_nostr_event_action(),
            reject_nostr_event_action(),
            send_nostr_events_action(),
            close_nostr_subscription_action(),
            send_nostr_notice_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Nostr"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![NOSTR_EVENT_EVENT.clone(), NOSTR_REQ_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WS>NOSTR"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nostr", "relay", "nip-01", "nip01", "nostr relay"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        // No well-known port: NIP-01 relays are ws:// / wss:// URLs on HTTP's ports, and the
        // relay implementations disagree on a default (strfry.conf `port = 7777`,
        // nostr-rs-relay config.toml `port = 8080`). See NO_WELL_KNOWN_PORT in
        // tests/well_known_port_declaration_test.rs.
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written HTTP head and RFC 6455 upgrade, tokio-tungstenite framing; NIP-01 \
                 messages parsed with serde_json; event ids recomputed with sha2 and BIP-340 \
                 signatures verified and made with secp256k1 0.29 (the one bitcoin links)",
            )
            .llm_control(
                "Whether each published event is accepted (and the rejection reason), which \
                 events answer each subscription (kind, content, tags, created_at - NetGet \
                 signs them), closing subscriptions, and notices",
            )
            .e2e_testing(
                "tests/server/nostr/real_client_test.rs drives nak (fiatjaf's Go Nostr client, \
                 go-nostr underneath): nak event publishes a signed event and reports the OK, \
                 nak req receives the model's events and verifies their signatures itself, nak \
                 relay reads the NIP-11 document. A second client, rust-nostr's Python \
                 bindings (pip nostr-sdk), publishes and subscribes through its own NIP-01 \
                 implementation. Both fail, never skip, when absent. The pcap oracle reads a \
                 recorded nak session as http then websocket in both directions.",
            )
            .notes(
                "NIP-01 (EVENT, REQ, CLOSE in; EVENT, OK, EOSE, CLOSED, NOTICE out) and NIP-11 \
                 on a GET with Accept: application/nostr+json. Refused by NetGet without the \
                 model: an event whose id is not the hash of its content or whose signature \
                 does not verify (OK false invalid:), malformed messages (NOTICE), bad \
                 subscription ids, too many filters or subscriptions (CLOSED). The relay stores \
                 nothing: an accepted event is delivered to the matching subscriptions open at \
                 that moment and then forgotten; a REQ is answered with events the model \
                 supplies, signed by the relay's own key rather than by their nominal author, \
                 and filtered against the REQ's own filters. No NIP-42 AUTH, no COUNT, no \
                 replaceable- or ephemeral-kind semantics. On backend failure a published event \
                 gets OK false error:/rate-limited: and a subscription gets CLOSED.",
            )
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Nostr relay (NIP-01 over WebSocket) - the model decides which notes it takes and serves"
    }
    fn example_prompt(&self) -> &'static str {
        "Nostr relay - accept notes tagged #film, and answer subscriptions with three film reviews"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 7777,
                "base_stack": "nostr",
                "instruction": "A film club relay: accept short notes (kind 1) about films and \
                                refuse everything else; answer subscriptions with two recent \
                                film reviews"
            }),
            json!({
                "type": "open_server",
                "port": 7777,
                "base_stack": "nostr",
                "startup_params": {"relay_name": "Film club relay"},
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\ni = json.load(sys.stdin)\ne = i['event']\nif i['event_type_id'] == 'nostr_event':\n    if e.get('kind') == 1 and 'film' in e.get('content', '').lower():\n        a = [{'type': 'accept_nostr_event'}]\n    else:\n        a = [{'type': 'reject_nostr_event', 'reason': 'blocked: only notes about films'}]\nelse:\n    a = [{'type': 'send_nostr_events', 'events': [{'kind': 1, 'content': 'Review: Stalker (1979), five stars', 'tags': [['t', 'film']]}]}]\nprint(json.dumps({'actions': a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 7777,
                "base_stack": "nostr",
                "event_handlers": [
                    {
                        "event_pattern": "nostr_event",
                        "handler": {"type": "static", "actions": [{"type": "accept_nostr_event"}]}
                    },
                    {
                        "event_pattern": "nostr_req",
                        "handler": {"type": "static", "actions": [{
                            "type": "send_nostr_events",
                            "events": [{"kind": 1, "content": "Welcome to this relay"}]
                        }]}
                    }
                ]
            }),
        )
    }
}

impl Server for NostrProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let string = |name: &str| -> anyhow::Result<Option<String>> {
                Ok(params
                    .map(|p| p.get_optional_string(name))
                    .transpose()?
                    .flatten())
            };
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(params
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let supported_nips = match params.map(|p| p.get_optional_array("supported_nips")) {
                Some(result) => match result? {
                    Some(items) => items
                        .iter()
                        .map(|v| {
                            v.as_u64()
                                .ok_or_else(|| anyhow!("supported_nips must be NIP numbers"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                    None => DEFAULT_SUPPORTED_NIPS.to_vec(),
                },
                None => DEFAULT_SUPPORTED_NIPS.to_vec(),
            };
            let key = match string("relay_secret_key")? {
                Some(hex_key) => RelayKey::from_hex(&hex_key).map_err(|e| anyhow!(e))?,
                None => RelayKey::generate(),
            };
            let config = super::RelayConfig {
                info: super::http::RelayInfo {
                    name: string("relay_name")?.unwrap_or_else(|| DEFAULT_RELAY_NAME.to_string()),
                    description: string("relay_description")?
                        .unwrap_or_else(|| DEFAULT_RELAY_DESCRIPTION.to_string()),
                    supported_nips,
                    relay_pubkey: key.pubkey_hex().to_string(),
                },
                handshake_timeout: secs("handshake_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::HANDSHAKE_TIMEOUT),
                idle_timeout: secs("idle_timeout_secs")?
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(super::IDLE_TIMEOUT),
            };

            super::NostrServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                Arc::new(key),
                config,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "accept_nostr_event" => Ok(ActionResult::Custom {
                name: "accept_nostr_event".to_string(),
                data: json!({}),
            }),
            "reject_nostr_event" => {
                let reason = action.get("reason").and_then(Value::as_str).unwrap_or("");
                Ok(ActionResult::Custom {
                    name: "reject_nostr_event".to_string(),
                    data: json!({"reason": wire::with_prefix(reason, "blocked")}),
                })
            }
            "send_nostr_events" => {
                let supplied =
                    wire::parse_supplied_events(action.get("events")).map_err(|e| anyhow!(e))?;
                let Some(binding) = &self.binding else {
                    return Ok(ActionResult::Custom {
                        name: "send_nostr_events".to_string(),
                        data: json!({"events": supplied.len()}),
                    });
                };
                let named = action.get("subscription_id").and_then(Value::as_str);
                let (subscription_id, filters, apply_limit) =
                    binding.conn.target(named).map_err(|e| anyhow!(e))?;
                let now = wire::now_secs();
                let events: Vec<wire::Event> = supplied
                    .into_iter()
                    .map(|s| {
                        binding
                            .key
                            .sign(s.created_at.unwrap_or(now), s.kind, s.tags, s.content)
                    })
                    .collect();
                let chosen = wire::select_events(&filters, &events, apply_limit);
                if chosen.len() < events.len() {
                    tracing::info!(
                        "Nostr {}: {} of {} supplied events match the subscription's filters; \
                         the rest are not sent",
                        subscription_id,
                        chosen.len(),
                        events.len()
                    );
                }
                Ok(ActionResult::Multiple(
                    chosen
                        .into_iter()
                        .map(|i| {
                            ActionResult::Output(
                                wire::event_message(&subscription_id, &events[i]).into_bytes(),
                            )
                        })
                        .collect(),
                ))
            }
            "close_nostr_subscription" => {
                let reason = action.get("reason").and_then(Value::as_str).unwrap_or("");
                let reason = wire::with_prefix(reason, "restricted");
                let named = action
                    .get("subscription_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let subscription_id = match &self.binding {
                    Some(binding) => {
                        let (id, _, _) = binding.conn.target(named).map_err(|e| anyhow!(e))?;
                        binding.conn.close(&id);
                        id
                    }
                    None => named
                        .context(
                            "close_nostr_subscription can only run while answering a nostr_req, \
                             or with a subscription_id",
                        )?
                        .to_string(),
                };
                Ok(ActionResult::Output(
                    wire::closed_message(&subscription_id, &reason).into_bytes(),
                ))
            }
            "send_nostr_notice" => {
                let message = action
                    .get("message")
                    .and_then(Value::as_str)
                    .filter(|m| !m.trim().is_empty())
                    .context("send_nostr_notice needs 'message'")?;
                Ok(ActionResult::Output(
                    wire::notice_message(message).into_bytes(),
                ))
            }
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown Nostr action: {}", action_type)),
        }
    }
}

fn accept_nostr_event_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_nostr_event".to_string(),
        description: "Accept the event a client just published (answers a nostr_event). The \
                      client is told OK true, and the event goes to every subscription open at \
                      that moment whose filters it matches. The relay does not store it."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "accept_nostr_event"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Nostr OK true")
                .with_debug("Nostr accept_nostr_event"),
        ),
    }
}

fn reject_nostr_event_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_nostr_event".to_string(),
        description: "Refuse the event a client just published (answers a nostr_event). The \
                      client is told OK false with the reason."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why, starting with one of NIP-01's prefixes: blocked:, \
                          rate-limited:, invalid:, restricted:, pow:, duplicate: or error:. \
                          Without one, blocked: is added."
                .to_string(),
            required: true,
        }],
        example: json!({"type": "reject_nostr_event", "reason": "blocked: <why>"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Nostr OK false {reason}")
                .with_debug("Nostr reject_nostr_event: {reason}"),
        ),
    }
}

fn send_nostr_events_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nostr_events".to_string(),
        description: "Answer a subscription (nostr_req) with events. Give each event's kind, \
                      content and tags - the words your instructions give them, the \
                      example's are placeholders - and NetGet fills in pubkey, id and sig by \
                      signing with the relay's own key, sends the ones the subscription's \
                      filters allow, then EOSE. events: [] when there is nothing to serve."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "events".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {kind, content, tags?, created_at?}. kind is a number \
                              (1 = short text note, 0 = profile metadata whose content is a \
                              JSON object, 7 = reaction); tags is an array of string arrays \
                              like [[\"t\", \"topic\"]]; created_at is a unix time in seconds, \
                              now when omitted."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "subscription_id".to_string(),
                type_hint: "string".to_string(),
                description: "Only when sending outside the answer to a REQ: which open \
                              subscription receives the events. The REQ being answered by \
                              default."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nostr_events",
            "events": [
                {"kind": 1, "content": "<the note's text>", "tags": [["t", "<topic>"]]}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Nostr events")
                .with_debug("Nostr send_nostr_events"),
        ),
    }
}

fn close_nostr_subscription_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_nostr_subscription".to_string(),
        description: "Refuse or end a subscription: sends CLOSED with the reason and forgets \
                      the subscription. Answering a nostr_req with this instead of \
                      send_nostr_events refuses the query."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Why, starting with one of NIP-01's prefixes (restricted:, \
                              blocked:, rate-limited:, invalid:, error:). Without one, \
                              restricted: is added."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "subscription_id".to_string(),
                type_hint: "string".to_string(),
                description: "Which subscription; the REQ being answered by default".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "close_nostr_subscription",
            "reason": "restricted: <why>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Nostr CLOSED {reason}")
                .with_debug("Nostr close_nostr_subscription: {reason}"),
        ),
    }
}

fn send_nostr_notice_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nostr_notice".to_string(),
        description: "Send the client a human-readable NOTICE. Not an answer: a published \
                      event still needs accept or reject, a subscription still needs events."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The notice text".to_string(),
            required: true,
        }],
        example: json!({"type": "send_nostr_notice", "message": "<notice text>"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Nostr NOTICE {message}")
                .with_debug("Nostr send_nostr_notice: {message}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the WebSocket (after the answer to this message is sent)".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Nostr connection closed")
                .with_debug("Nostr close_connection"),
        ),
    }
}

/// The `answer_with` of `nostr_event`.
pub fn event_answer_with(kind: u64) -> String {
    format!(
        "a client published a kind {kind} event; NetGet has already checked its id and \
         signature. Decide from your instructions whether the relay takes it, with exactly one \
         action: {{\"type\": \"accept_nostr_event\"}}, or {{\"type\": \"reject_nostr_event\", \
         \"reason\": \"blocked: ...\"}} (the reason starts with blocked:, restricted:, \
         invalid:, rate-limited:, pow:, duplicate: or error:)"
    )
}

/// The `answer_with` of `nostr_req`: what the filters ask for, and which answers fit.
pub fn req_answer_with(
    subscription_id: &str,
    filters: &[wire::Filter],
    relay_pubkey: &str,
) -> String {
    let mut asks: Vec<String> = Vec::new();
    let mut unsatisfiable: Vec<&str> = Vec::new();
    for filter in filters {
        let mut parts: Vec<String> = Vec::new();
        if let Some(kinds) = &filter.kinds {
            parts.push(format!(
                "kind {}",
                kinds
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
        for (letter, values) in &filter.tags {
            parts.push(format!(
                "a \"{letter}\" tag of {}",
                values
                    .iter()
                    .map(|v| format!("\"{}\"", crate::utils::truncate_for_log(v, 64)))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
        if let Some(since) = filter.since {
            parts.push(format!("created_at at or after {since}"));
        }
        if let Some(until) = filter.until {
            parts.push(format!("created_at at or before {until}"));
        }
        if let Some(limit) = filter.limit {
            parts.push(format!("at most {limit}"));
        }
        if filter
            .authors
            .as_ref()
            .is_some_and(|a| !a.iter().any(|k| k == relay_pubkey))
        {
            unsatisfiable.push("authors");
        }
        if filter.ids.is_some() {
            unsatisfiable.push("ids");
        }
        asks.push(if parts.is_empty() {
            "any event".to_string()
        } else {
            parts.join(", ")
        });
    }
    let mut text = format!(
        "a client opened subscription \"{}\" asking for {}. Answer with one \
         send_nostr_events whose events are the ones your instructions give that fit, each \
         with only kind, content and tags (and created_at if a time is given); events: [] if \
         none fit. NetGet signs them with the relay's key, drops any the filters exclude and \
         sends EOSE after them. To refuse the subscription instead, close_nostr_subscription \
         with a reason",
        crate::utils::truncate_for_log(subscription_id, 64),
        asks.join("; or ")
    );
    if !unsatisfiable.is_empty() {
        unsatisfiable.dedup();
        text.push_str(&format!(
            ". Note: this subscription filters on {}, and every event you supply is published \
             under the relay's key {relay_pubkey} with an id NetGet computes, so none of yours \
             can match that part; events: [] is the honest answer to it",
            unsatisfiable.join(" and ")
        ));
    }
    text
}

/// A client published an event (`["EVENT", <event>]`) whose id and signature verified.
pub static NOSTR_EVENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nostr_event",
        "A client published an event. Its id and signature are already verified. Answer \
         with exactly one decision: accept_nostr_event or reject_nostr_event.",
        json!({"type": "accept_nostr_event"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "id".to_string(),
            type_hint: "string".to_string(),
            description: "The event id (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "pubkey".to_string(),
            type_hint: "string".to_string(),
            description: "The author's public key (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "kind".to_string(),
            type_hint: "number".to_string(),
            description: "1 = short text note, 0 = profile metadata, 3 = follow list, 7 = \
                          reaction, and so on"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "created_at".to_string(),
            type_hint: "number".to_string(),
            description: "Unix time in seconds, as the author claims it".to_string(),
            required: true,
        },
        Parameter {
            name: "tags".to_string(),
            type_hint: "array".to_string(),
            description: format!(
                "The event's tags, arrays of strings (the first {MAX_TAGS_FOR_MODEL}; \
                 tag_count has the total)"
            ),
            required: true,
        },
        Parameter {
            name: "tag_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many tags the event has".to_string(),
            required: true,
        },
        Parameter {
            name: "content".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "The event's content (the first {MAX_CONTENT_FOR_MODEL} bytes; \
                 content_truncated says whether there was more)"
            ),
            required: true,
        },
        Parameter {
            name: "content_truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether content was cut".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "The two answers this event takes".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Nostr EVENT kind {kind}")
            .with_debug("Nostr nostr_event: id={id} kind={kind}"),
    )
    .with_actions(vec![
        accept_nostr_event_action(),
        reject_nostr_event_action(),
        send_nostr_notice_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "reject_nostr_event",
        "reason": "blocked: <why>"
    }))
});

/// A client opened a subscription (`["REQ", <id>, <filter>...]`).
pub static NOSTR_REQ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nostr_req",
        "A client opened a subscription. Answer with the events that fit it \
         (send_nostr_events; NetGet signs and filters them and sends EOSE), or refuse it \
         (close_nostr_subscription).",
        json!({
            "type": "send_nostr_events",
            "events": [{"kind": 1, "content": "<the note's text>"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "subscription_id".to_string(),
            type_hint: "string".to_string(),
            description: "The client's name for this subscription".to_string(),
            required: true,
        },
        Parameter {
            name: "filters".to_string(),
            type_hint: "array".to_string(),
            description: "The NIP-01 filters, as sent: kinds, authors, ids, since, until, \
                          limit, #<letter> tag filters. An event is sent when it matches any \
                          one filter"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "relay_pubkey".to_string(),
            type_hint: "string".to_string(),
            description: "The key the relay signs your events with; they appear as authored \
                          by it"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "What the filters ask for, in words, and which answers fit".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Nostr REQ {subscription_id}")
            .with_debug("Nostr nostr_req: {subscription_id}"),
    )
    .with_actions(vec![
        send_nostr_events_action(),
        close_nostr_subscription_action(),
        send_nostr_notice_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_nostr_events",
        "events": []
    }))
});
