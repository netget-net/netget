//! SEP-3415 at b08e4f9: polling and stdio streams. No webhook endpoints.

use crate::events::journal::{EventJournal, ACCESS_RECORDED, INTERCEPT_PENDING, LLM_PENDING};
use rmcp::model::{CustomNotification, CustomResult, ErrorCode, RequestId};
use rmcp::service::{Peer, RequestContext, RoleServer};
use rmcp::ErrorData;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const EXTENSION: &str = "io.modelcontextprotocol/events";
pub const MODERN_VERSION: &str = "2026-07-28";
pub const HEARTBEAT: Duration = Duration::from_secs(30);
const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
const MAX_STREAMS: usize = 64;

/// Per transport connection, never shared between HTTP sessions.
#[derive(Default)]
pub struct SessionEvents {
    pub stop: CancellationToken,
    streams: AtomicUsize,
    channels_started: AtomicBool,
}
impl SessionEvents {
    pub fn start_channels(&self, journal: Arc<EventJournal>, peer: Peer<RoleServer>) {
        if !self.channels_started.swap(true, Ordering::SeqCst) {
            start_channels(journal, self.stop.clone(), peer);
        }
    }
}
impl Drop for SessionEvents {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
struct StreamSlot<'a>(&'a AtomicUsize);
impl Drop for StreamSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Map<String, Value>,
    pub cursor: Option<String>,
    pub max_age_ms: Option<u64>,
    pub max_events: Option<usize>,
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
}

pub fn error(code: i32, message: &str, data: Value) -> ErrorData {
    ErrorData::new(ErrorCode(code), message.to_owned(), Some(data))
}

pub fn descriptors(push: bool) -> Value {
    let definitions = [
        (LLM_PENDING, "A model request needs an agent answer. Use get_next_llm_request to claim work, then answer_llm_request. Reading an event does not claim it.", "request_id"),
        (INTERCEPT_PENDING, "A manual-handler request needs an answer. Use list_intercepts, then answer_intercept or fail_intercept.", "intercept_id"),
        (ACCESS_RECORDED, "A server or client access-log entry was recorded. Use get_access_log to inspect the request and produced actions; this is not proof of wire delivery.", "access_log_id"),
    ];
    let events: Vec<Value> = definitions.into_iter().map(|(name, description, id)| {
        let mut fields = Map::new();
        for key in ["server_id", "client_id", "connection_id", id] {
            fields.insert(key.into(), json!({"type":"integer","minimum":0}));
        }
        // Protocol is unavailable for manual intercepts, which instead carry event_type.
        for key in ["protocol", "event_type"] {
            if name != INTERCEPT_PENDING || key != "protocol" {
                fields.insert(key.into(), json!({"type":"string"}));
            }
        }
        let mut payload = fields.clone();
        for key in ["server_id", "client_id", "connection_id"] {
            payload.insert(key.into(), json!({"type":["integer","null"]}));
        }
        if name != ACCESS_RECORDED {
            payload.insert("deadline_unix_ms".into(), json!({"type":["integer","null"]}));
        }
        json!({"name":name,"description":description,
            "delivery":if push {json!(["poll","push"])} else {json!(["poll"])},
            "inputSchema":{"type":"object","properties":fields,"additionalProperties":false},
            "payloadSchema":{"type":"object","properties":payload,"required":[id],"additionalProperties":false}})
    }).collect();
    json!({"resultType":"complete","events":events})
}

fn validate(params: &EventParams, stream: bool) -> Result<(), ErrorData> {
    let descriptions = descriptors(true);
    let descriptor = descriptions["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == params.name)
        .ok_or_else(|| error(-32023, "NotFound", json!({"kind":"event"})))?;
    let fields = descriptor["inputSchema"]["properties"].as_object().unwrap();
    for (key, value) in &params.arguments {
        let valid = fields
            .get(key)
            .is_some_and(|schema| match schema["type"].as_str() {
                Some("integer") => value.as_u64().is_some(),
                Some("string") => value.is_string(),
                _ => false,
            });
        if !valid {
            return Err(ErrorData::invalid_params(
                format!("invalid event argument: {key}"),
                None,
            ));
        }
    }
    if params.max_events == Some(0) || (stream && params.max_events.is_some()) {
        return Err(ErrorData::invalid_params(
            "maxEvents must be positive and is only valid for events/poll",
            None,
        ));
    }
    Ok(())
}

pub fn poll(journal: &EventJournal, params: &EventParams) -> Result<CustomResult, ErrorData> {
    validate(params, false)?;
    let batch = journal
        .read(
            &params.name,
            &params.arguments,
            params.cursor.as_deref(),
            params.max_age_ms,
            params.max_events.unwrap_or(100).min(1000),
        )
        .map_err(|e| ErrorData::invalid_params(e, None))?;
    let events: Vec<Value> = batch
        .events
        .into_iter()
        .map(|mut e| {
            e.as_object_mut().unwrap().remove("cursor");
            e
        })
        .collect();
    Ok(CustomResult(
        json!({"resultType":"complete","events":events,"cursor":batch.cursor,
        "truncated":batch.truncated,"hasMore":batch.has_more,"nextPollMs":1000}),
    ))
}

async fn notify(
    peer: &Peer<RoleServer>,
    method: &str,
    mut params: Value,
    id: &RequestId,
) -> Result<(), ErrorData> {
    params["_meta"] = json!({SUBSCRIPTION_ID:id});
    peer.send_notification(CustomNotification::new(method, Some(params)).into())
        .await
        .map_err(|_| ErrorData::internal_error("event transport closed", None))
}

pub async fn stream(
    journal: &EventJournal,
    session: &SessionEvents,
    params: EventParams,
    context: RequestContext<RoleServer>,
) -> Result<CustomResult, ErrorData> {
    validate(&params, true)?;
    if session.streams.fetch_add(1, Ordering::SeqCst) >= MAX_STREAMS {
        session.streams.fetch_sub(1, Ordering::SeqCst);
        return Err(error(
            -32025,
            "ResourceExhausted",
            json!({"limit":"subscriptions","max":MAX_STREAMS}),
        ));
    }
    let _slot = StreamSlot(&session.streams);
    let mut changed = journal.subscribe();
    let mut cursor = params.cursor;
    let mut first = true;
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    loop {
        changed.borrow_and_update();
        let batch = journal
            .read(
                &params.name,
                &params.arguments,
                cursor.as_deref(),
                params.max_age_ms,
                100,
            )
            .map_err(|e| ErrorData::invalid_params(e, None))?;
        if first || batch.truncated {
            notify(
                &context.peer,
                "notifications/events/active",
                json!({"cursor":batch.start_cursor,"truncated":batch.truncated}),
                &context.id,
            )
            .await?;
            first = false;
        }
        for event in batch.events {
            if context.ct.is_cancelled() || session.stop.is_cancelled() {
                return Ok(CustomResult(
                    json!({"resultType":"complete","_meta":{SUBSCRIPTION_ID:context.id}}),
                ));
            }
            notify(
                &context.peer,
                "notifications/events/event",
                event,
                &context.id,
            )
            .await?;
        }
        cursor = Some(batch.cursor);
        if batch.has_more {
            continue;
        }
        tokio::select! {
            biased;
            _ = context.ct.cancelled() => break,
            _ = session.stop.cancelled() => break,
            result = changed.changed() => { if result.is_err() { break; } },
            _ = heartbeat.tick() => { notify(&context.peer, "notifications/events/heartbeat", json!({"cursor":cursor}), &context.id).await?; }
        }
    }
    Ok(CustomResult(
        json!({"resultType":"complete","_meta":{SUBSCRIPTION_ID:context.id}}),
    ))
}

/// Channels use the same event IDs/history. Legacy clients gate these locally.
pub fn start_channels(journal: Arc<EventJournal>, stop: CancellationToken, peer: Peer<RoleServer>) {
    let changed = journal.subscribe();
    let cursor = journal.current_cursor();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = stop.cancelled() => {},
            _ = channel_loop(&journal, &peer, None, cursor, changed) => {},
        }
    });
}

/// Modern clients request a scoped channel stream rather than unsolicited delivery.
pub async fn channel_stream(
    journal: &EventJournal,
    session: &SessionEvents,
    params: Value,
    context: RequestContext<RoleServer>,
) -> Result<CustomResult, ErrorData> {
    if !params.get("notifications").is_some_and(Value::is_object) {
        return Err(ErrorData::invalid_params(
            "subscriptions/listen requires a notifications object",
            None,
        ));
    }
    if session.streams.fetch_add(1, Ordering::SeqCst) >= MAX_STREAMS {
        session.streams.fetch_sub(1, Ordering::SeqCst);
        return Err(error(
            -32025,
            "ResourceExhausted",
            json!({"limit":"subscriptions","max":MAX_STREAMS}),
        ));
    }
    let _slot = StreamSlot(&session.streams);
    let changed = journal.subscribe();
    let cursor = journal.current_cursor();
    notify(
        &context.peer,
        "notifications/subscriptions/acknowledged",
        json!({"notifications":{}}),
        &context.id,
    )
    .await?;
    let enabled = context
        .meta
        .get("io.modelcontextprotocol/clientCapabilities")
        .and_then(|v| v.get("experimental"))
        .and_then(|v| v.get("claude/channel"))
        .is_some_and(Value::is_object);
    if enabled {
        tokio::select! {
            biased;
            _ = context.ct.cancelled() => {},
            _ = session.stop.cancelled() => {},
            result = channel_loop(journal, &context.peer, Some(&context.id), cursor, changed) => { result?; },
        }
    }
    Ok(CustomResult(
        json!({"resultType":"complete","_meta":{SUBSCRIPTION_ID:context.id}}),
    ))
}

async fn channel_loop(
    journal: &EventJournal,
    peer: &Peer<RoleServer>,
    subscription: Option<&RequestId>,
    mut cursor: String,
    mut changed: tokio::sync::watch::Receiver<u64>,
) -> Result<(), ErrorData> {
    loop {
        changed.borrow_and_update();
        let batch = journal
            .read("*", &Map::new(), Some(&cursor), None, 1000)
            .map_err(|e| ErrorData::internal_error(e, None))?;
        let mut deliver = batch.events;
        if batch.truncated {
            deliver.insert(0,json!({"name":"events.gap","eventId":format!("gap:{}",batch.start_cursor),"truncated":true,"cursor":batch.start_cursor}));
        }
        for event in deliver {
            let name = event["name"].as_str().unwrap_or("");
            if matches!(name, LLM_PENDING | INTERCEPT_PENDING | "events.gap") {
                let params = json!({"content":serde_json::to_string(&event).unwrap(),
                    "meta":{"event":name,"event_id":event["eventId"].as_str().unwrap_or("")}});
                if let Some(id) = subscription {
                    notify(peer, "notifications/claude/channel", params, id).await?;
                } else {
                    peer.send_notification(
                        CustomNotification::new("notifications/claude/channel", Some(params))
                            .into(),
                    )
                    .await
                    .map_err(|_| ErrorData::internal_error("channel transport closed", None))?;
                }
            }
        }
        cursor = batch.cursor;
        if batch.has_more {
            continue;
        }
        if changed.changed().await.is_err() {
            return Ok(());
        }
    }
}
