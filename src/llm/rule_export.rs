//! Record with the model, replay without it: turn the access log's model-authored answers
//! into `event_handlers`.
//!
//! Every event the shared model path answers is recorded in the access log with
//! `answered_by: "model"` (or `"cache"` for a memoised replay of a model answer). Grouped by
//! event type, those answers are usually a function of a few event fields — an HTTP server's
//! of the method and path, a DNS server's of the name and type — plus per-request ids the
//! answer echoes. [`derive_rules`] finds that function where the recording shows one and
//! writes it as static rules with `match` conditions:
//!
//! 1. Per-request fields ([`crate::llm::answer_reuse::PER_REQUEST_FIELDS`]) echoed in an
//!    answer become `{{event.<field>}}` references, so a replay carries the new request's id.
//! 2. The fewest fields that explain why answers differ are chosen greedily: the recorded
//!    events are split by a field's value while that reduces the number of events whose group
//!    still holds two different answers. A group the model answered identically (after step 1,
//!    or after echoing a field whose varying value the answers carried) becomes one rule.
//! 3. Each rule's `match` holds those fields plus every other field that was constant in its
//!    group and that the recording never showed to be irrelevant. A field is shown irrelevant
//!    when it varied inside a group the model answered identically, or when every recorded
//!    event carried a different value (a request id or timestamp by another name). Unknown
//!    relevance is treated as relevant: a narrower rule falls through to the fallback, a
//!    broader one would answer a request the model never saw with someone else's answer.
//! 4. Every rule is validated as `start_server` would validate it, then replayed against each
//!    recorded event it covers; a rule that does not reproduce the recorded answer exactly is
//!    dropped and reported.
//!
//! A group whose recorded answers differ with nothing to tell them apart is reported as
//! undetermined and left to the fallback rather than guessed at. So are answers that did more
//! than reply (memory, tasks, logs, instance management), failed, carried credentials, or
//! answered a batch of events at once.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::llm::answer_reuse::{
    is_addressable_key, is_peer_address_field, is_per_request_field, per_request_fields_of,
    replayable_actions, template_fields, EchoEvidence,
};
use crate::scripting::event_handler::{interpolate_actions, match_field, EventPattern};
use crate::scripting::EventHandlerType;
use crate::state::app_state::{answered_by, AccessLogEntry, AppState};
use crate::state::AccessLogOwner;

/// The most fields one rule's derivation may split on.
const MAX_KEY_FIELDS: usize = 8;
/// How deep into the event data a `match` condition may reach.
const MAX_CONDITION_DEPTH: usize = 4;
/// A field whose value serialises larger than this is never a condition.
const MAX_CONDITION_VALUE_BYTES: usize = 4096;

/// What follows the exported rules in the table `export_rules` builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    /// The instance's own fallback rule (`*` with no `match`), if it has one; none otherwise.
    #[default]
    Keep,
    /// No fallback rule: anything no rule matches goes to the model.
    Llm,
    /// `*` → manual: anything no rule matches waits for a person at the dashboard.
    Manual,
}

impl Fallback {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "keep" => Ok(Fallback::Keep),
            "llm" | "model" => Ok(Fallback::Llm),
            "manual" => Ok(Fallback::Manual),
            other => anyhow::bail!(
                "unknown fallback '{other}': use \"keep\" (the instance's own), \"llm\" or \"manual\""
            ),
        }
    }
}

/// Recorded answers left out of the rules, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub event_type: String,
    pub entries: usize,
    pub reason: String,
}

/// Recorded events no deterministic rule could be written for. They stay with the fallback.
#[derive(Debug, Clone, Serialize)]
pub struct Undetermined {
    pub event_type: String,
    /// The fields the events had in common when the derivation gave up on them.
    #[serde(rename = "match")]
    pub conditions: Map<String, Value>,
    pub entries: usize,
    pub distinct_answers: usize,
    pub reason: String,
}

/// What [`derive_rules`] found in a recording.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DerivedRules {
    /// Model-authored answers read (model and memoised replays of the model).
    pub recorded_answers: usize,
    /// The rules, as `event_handlers` entries, most specific event types first in the order
    /// they were first seen.
    pub rules: Vec<Value>,
    pub skipped: Vec<Skipped>,
    pub undetermined: Vec<Undetermined>,
}

/// An export: the derived rules and the whole table to apply.
#[derive(Debug, Clone, Serialize)]
pub struct RuleExport {
    /// `"server #3"` / `"client #2"`.
    pub instance: String,
    pub protocol: String,
    #[serde(flatten)]
    pub derived: DerivedRules,
    /// The derived rules, then the instance's existing rules (less any the derivation
    /// reproduced), then the fallback.
    pub event_handlers: Vec<Value>,
    pub fallback: Fallback,
}

struct Sample {
    request: Value,
    response: Vec<Value>,
    /// `response` with echoed per-request fields replaced by references.
    templated: Vec<Value>,
}

/// Derive deterministic rules from access-log entries, oldest first. Only entries answered by
/// the model (or a memoised model answer) are read; everything else is ignored.
pub fn derive_rules(entries: &[AccessLogEntry]) -> DerivedRules {
    let mut out = DerivedRules::default();
    let mut skipped: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<Sample>> = BTreeMap::new();

    for entry in entries {
        let by = entry.answered_by.as_deref();
        if by != Some(answered_by::MODEL) && by != Some(answered_by::CACHE) {
            continue;
        }
        out.recorded_answers += 1;
        if let Some(reason) = skip_reason(entry) {
            *skipped
                .entry((entry.event_type.clone(), reason.to_string()))
                .or_default() += 1;
            continue;
        }
        if !groups.contains_key(&entry.event_type) {
            order.push(entry.event_type.clone());
        }
        let templated = template_fields(
            &entry.request,
            &entry.response,
            &per_request_fields_of(&entry.request),
            EchoEvidence::SingleAnswer,
        );
        groups
            .entry(entry.event_type.clone())
            .or_default()
            .push(Sample {
                request: entry.request.clone(),
                response: entry.response.clone(),
                templated,
            });
    }

    for event_type in order {
        let samples = &groups[&event_type];
        derive_for_event(&event_type, samples, &mut out);
    }
    out.skipped = skipped
        .into_iter()
        .map(|((event_type, reason), entries)| Skipped {
            event_type,
            entries,
            reason,
        })
        .collect();
    out
}

fn skip_reason(entry: &AccessLogEntry) -> Option<&'static str> {
    let types: Vec<&str> = entry
        .response
        .iter()
        .map(|a| a.get("type").and_then(Value::as_str).unwrap_or(""))
        .collect();
    if types.contains(&crate::state::exchange_history::ANSWERED_WITH_NEXT) {
        return Some(
            "answered together with a later event in one model call (batching), so it has no \
             answer of its own",
        );
    }
    if types
        .iter()
        .any(|t| t.starts_with(crate::llm::actions::executor::FAILED_ACTION_TYPE_PREFIX))
    {
        return Some("the answer failed to execute");
    }
    if types.contains(&"private_handler_result")
        || crate::utils::redact::contains_credentials(&entry.request)
        || contains_redacted(&entry.response)
    {
        return Some("it carried credentials, which are never written into a rule");
    }
    if !replayable_actions(&entry.response) {
        return Some(
            "the answer did more than reply (memory, tasks, logs or instance management); a \
             rule would replay only part of it",
        );
    }
    None
}

fn contains_redacted(actions: &[Value]) -> bool {
    let mut pending: Vec<&Value> = actions.iter().collect();
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) if text == crate::utils::redact::REDACTED => return true,
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => pending.extend(map.values()),
            _ => {}
        }
    }
    false
}

/// Every field path a condition could name: scalar leaves (and arrays and empty objects,
/// whole) up to [`MAX_CONDITION_DEPTH`], never a top-level per-request field, never a value
/// larger than [`MAX_CONDITION_VALUE_BYTES`]. Shallow paths first.
fn candidate_paths(samples: &[Sample]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    let mut too_large = BTreeSet::new();
    fn walk(
        value: &Value,
        prefix: &str,
        depth: usize,
        paths: &mut BTreeSet<String>,
        too_large: &mut BTreeSet<String>,
    ) {
        match value {
            Value::Object(map) if !map.is_empty() && depth < MAX_CONDITION_DEPTH => {
                for (key, child) in map {
                    if !is_addressable_key(key) || (depth == 0 && is_per_request_field(key)) {
                        continue;
                    }
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(child, &path, depth + 1, paths, too_large);
                }
            }
            _ if prefix.is_empty() => {}
            _ => {
                if serde_json::to_string(value).map_or(usize::MAX, |s| s.len())
                    > MAX_CONDITION_VALUE_BYTES
                {
                    too_large.insert(prefix.to_string());
                } else {
                    paths.insert(prefix.to_string());
                }
            }
        }
    }
    for sample in samples {
        walk(&sample.request, "", 0, &mut paths, &mut too_large);
    }
    let mut out: Vec<String> = paths.difference(&too_large).cloned().collect();
    out.sort_by_key(|path| (path.split('.').count(), path.clone()));
    out
}

fn value_at<'a>(sample: &'a Sample, path: &str) -> &'a Value {
    match_field(Some(&sample.request), path)
}

/// Split sample indices by their values at `key`, groups in first-seen order.
fn partition(samples: &[Sample], indices: &[usize], key: &[String]) -> Vec<Vec<usize>> {
    let mut parts: Vec<(Vec<&Value>, Vec<usize>)> = Vec::new();
    for &i in indices {
        let values: Vec<&Value> = key.iter().map(|p| value_at(&samples[i], p)).collect();
        match parts.iter_mut().find(|(v, _)| *v == values) {
            Some((_, members)) => members.push(i),
            None => parts.push((values, vec![i])),
        }
    }
    parts.into_iter().map(|(_, members)| members).collect()
}

/// The one answer a group of samples shares, if it shares one: identical after per-request
/// echoes, or identical once the top-level fields that varied within the group are echoed too
/// (an echo server answering each message with itself).
fn shared_answer(samples: &[Sample], part: &[usize]) -> Option<Vec<Value>> {
    let first = &samples[part[0]].templated;
    if part.iter().all(|&i| samples[i].templated == *first) {
        return Some(first.clone());
    }
    let request = samples[part[0]].request.as_object()?;
    let varied: Vec<String> = request
        .keys()
        .filter(|key| !is_per_request_field(key) && is_addressable_key(key))
        .filter(|key| {
            let first = value_at(&samples[part[0]], key);
            part.iter().any(|&i| value_at(&samples[i], key) != first)
        })
        .cloned()
        .collect();
    if varied.is_empty() {
        return None;
    }
    let rendered: Vec<Vec<Value>> = part
        .iter()
        .map(|&i| {
            template_fields(
                &samples[i].request,
                &samples[i].templated,
                &varied,
                EchoEvidence::Corroborated,
            )
        })
        .collect();
    rendered
        .iter()
        .all(|r| *r == rendered[0])
        .then(|| rendered[0].clone())
}

/// How many samples sit in a group whose answers disagree.
fn disagreeing(samples: &[Sample], parts: &[Vec<usize>]) -> usize {
    parts
        .iter()
        .filter(|part| shared_answer(samples, part).is_none())
        .map(|part| part.len())
        .sum()
}

fn derive_for_event(event_type: &str, samples: &[Sample], out: &mut DerivedRules) {
    let all: Vec<usize> = (0..samples.len()).collect();
    let candidates = candidate_paths(samples);

    // 2. The fewest fields that explain why the answers differ.
    let mut key: Vec<String> = Vec::new();
    loop {
        let parts = partition(samples, &all, &key);
        let bad = disagreeing(samples, &parts);
        if bad == 0 || key.len() >= MAX_KEY_FIELDS {
            break;
        }
        let mut best: Option<(usize, usize, usize)> = None;
        for (index, candidate) in candidates.iter().enumerate() {
            if key.contains(candidate) {
                continue;
            }
            let mut trial = key.clone();
            trial.push(candidate.clone());
            let trial_parts = partition(samples, &all, &trial);
            let trial_bad = disagreeing(samples, &trial_parts);
            if trial_bad < bad {
                let score = (trial_bad, trial_parts.len(), index);
                if best.is_none_or(|b| score < b) {
                    best = Some(score);
                }
            }
        }
        match best {
            Some((_, _, index)) => key.push(candidates[index].clone()),
            None => break,
        }
    }
    let parts = partition(samples, &all, &key);

    // 3. Which of the remaining fields the recording shows do not matter.
    let mut irrelevant: HashSet<&str> = HashSet::new();
    for part in &parts {
        if part.len() < 2 || shared_answer(samples, part).is_none() {
            continue;
        }
        for candidate in &candidates {
            let first = value_at(&samples[part[0]], candidate);
            if part
                .iter()
                .any(|&i| value_at(&samples[i], candidate) != first)
            {
                irrelevant.insert(candidate);
            }
        }
    }
    if samples.len() >= 2 {
        for candidate in &candidates {
            if key.contains(candidate) {
                continue;
            }
            let distinct: HashSet<String> = samples
                .iter()
                .map(|s| value_at(s, candidate).to_string())
                .collect();
            if distinct.len() == samples.len() {
                irrelevant.insert(candidate);
            }
        }
    }

    for part in &parts {
        let mut conditions = Map::new();
        for path in &key {
            conditions.insert(path.clone(), value_at(&samples[part[0]], path).clone());
        }
        let Some(actions) = shared_answer(samples, part) else {
            let distinct: HashSet<String> = part
                .iter()
                .map(|&i| Value::Array(samples[i].templated.clone()).to_string())
                .collect();
            out.undetermined.push(Undetermined {
                event_type: event_type.to_string(),
                conditions,
                entries: part.len(),
                distinct_answers: distinct.len(),
                reason: format!(
                    "the model answered these {} events {} different ways and no recorded field \
                     explains the difference; they stay with the fallback",
                    part.len(),
                    distinct.len()
                ),
            });
            continue;
        };
        for candidate in &candidates {
            if key.contains(candidate) || irrelevant.contains(candidate.as_str()) {
                continue;
            }
            let top = candidate.split('.').next().unwrap_or_default();
            if is_peer_address_field(top) {
                continue;
            }
            let first = value_at(&samples[part[0]], candidate);
            if part
                .iter()
                .all(|&i| value_at(&samples[i], candidate) == first)
            {
                conditions.insert(candidate.clone(), first.clone());
            }
        }
        let mut rule = json!({
            "event_pattern": event_type,
            "handler": {"type": "static", "actions": actions},
        });
        if !conditions.is_empty() {
            rule["match"] = Value::Object(conditions.clone());
        }

        // 4. Validate as start_server would, then replay every recorded event it covers.
        if let Err(e) =
            crate::events::handler::EventHandler::parse_event_handlers(vec![rule.clone()])
        {
            out.undetermined.push(Undetermined {
                event_type: event_type.to_string(),
                conditions,
                entries: part.len(),
                distinct_answers: 1,
                reason: format!("the derived rule did not validate: {e}"),
            });
            continue;
        }
        let reproduces = part.iter().all(|&i| {
            let sample = &samples[i];
            let pattern = EventPattern::specific(event_type);
            let handler = crate::scripting::EventHandler::new(
                pattern,
                EventHandlerType::static_response(actions.clone()),
            )
            .with_match(conditions.clone());
            handler.matches_event(event_type, Some(&sample.request))
                && interpolate_actions(&actions, Some(&sample.request))
                    .is_ok_and(|rendered| rendered == sample.response)
        });
        if !reproduces {
            out.undetermined.push(Undetermined {
                event_type: event_type.to_string(),
                conditions,
                entries: part.len(),
                distinct_answers: 1,
                reason: "the derived rule did not reproduce every recorded answer it covers"
                    .to_string(),
            });
            continue;
        }
        out.rules.push(rule);
    }
}

/// Derive rules from an instance's access log and build the table to apply: the derived
/// rules, the instance's other existing rules, then `fallback`.
pub async fn export_rules(
    state: &AppState,
    owner: AccessLogOwner,
    fallback: Fallback,
) -> anyhow::Result<RuleExport> {
    let (instance, protocol, existing) = match owner {
        AccessLogOwner::Server(id) => {
            let server = state
                .get_server(crate::state::ServerId::new(id))
                .await
                .ok_or_else(|| anyhow::anyhow!("Server #{id} not found"))?;
            (
                format!("server #{id}"),
                server.protocol_name.clone(),
                server.event_handler_config,
            )
        }
        AccessLogOwner::Client(id) => {
            let client = state
                .get_client(crate::state::ClientId::new(id))
                .await
                .ok_or_else(|| anyhow::anyhow!("Client #{id} not found"))?;
            (
                format!("client #{id}"),
                client.protocol_name.clone(),
                client.event_handler_config,
            )
        }
    };
    let mut entries = state.list_access_logs_for(Some(owner), None).await;
    entries.reverse();
    let derived = derive_rules(&entries);

    let mut table = derived.rules.clone();
    let mut own_fallback: Option<Value> = None;
    for handler in existing.map(|c| c.handlers).unwrap_or_default() {
        let value = serde_json::to_value(&handler)?;
        if matches!(handler.event_pattern, EventPattern::Wildcard) && handler.data_match.is_none() {
            own_fallback.get_or_insert(value);
        } else if !table.contains(&value) {
            table.push(value);
        }
    }
    match fallback {
        Fallback::Keep => table.extend(own_fallback),
        Fallback::Llm => {}
        Fallback::Manual => table.push(json!({
            "event_pattern": "*",
            "handler": {"type": "manual"},
        })),
    }

    Ok(RuleExport {
        instance,
        protocol,
        derived,
        event_handlers: table,
        fallback,
    })
}

/// Apply an export's table to the running instance, in place (connections preserved).
pub async fn apply_export(
    state: &AppState,
    owner: AccessLogOwner,
    export: &RuleExport,
    llm_client: crate::llm::OllamaClient,
) -> anyhow::Result<crate::cli::management::UpdateOutcome> {
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    match owner {
        AccessLogOwner::Server(id) => {
            crate::cli::management::update_server(
                state,
                crate::state::ServerId::new(id),
                crate::cli::management::ServerForm {
                    event_handlers: Some(export.event_handlers.clone()),
                    ..Default::default()
                },
                status_tx,
            )
            .await
        }
        AccessLogOwner::Client(id) => {
            crate::cli::management::update_client(
                state,
                crate::state::ClientId::new(id),
                crate::cli::management::ClientForm {
                    event_handlers: Some(export.event_handlers.clone()),
                    ..Default::default()
                },
                llm_client,
                status_tx,
            )
            .await
        }
    }
}

/// A plain-text account of an export, for the MCP tool and the dashboard.
pub fn describe_export(export: &RuleExport) -> String {
    let derived = &export.derived;
    let mut out = format!(
        "{} ({}): {} model-authored answer(s) recorded; {} rule(s) derived.\n",
        export.instance,
        export.protocol,
        derived.recorded_answers,
        derived.rules.len()
    );
    for rule in &derived.rules {
        let handler: Option<crate::scripting::EventHandler> =
            serde_json::from_value(rule.clone()).ok();
        let names: Vec<&str> = rule["handler"]["actions"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x["type"].as_str()).collect())
            .unwrap_or_default();
        out.push_str(&format!(
            "  - {} → {}\n",
            handler.map(|h| h.describe()).unwrap_or_default(),
            if names.is_empty() {
                "answer with nothing".to_string()
            } else {
                names.join(", ")
            }
        ));
    }
    if !derived.undetermined.is_empty() {
        out.push_str("Left to the fallback (no deterministic rule):\n");
        for u in &derived.undetermined {
            out.push_str(&format!(
                "  - {} {}: {} event(s): {}\n",
                u.event_type,
                Value::Object(u.conditions.clone()),
                u.entries,
                u.reason
            ));
        }
    }
    if !derived.skipped.is_empty() {
        out.push_str("Recorded answers not used:\n");
        for s in &derived.skipped {
            out.push_str(&format!(
                "  - {}: {} answer(s): {}\n",
                s.event_type, s.entries, s.reason
            ));
        }
    }
    out.push_str(&format!(
        "Fallback: {}.\n",
        match export.fallback {
            Fallback::Keep => "the instance's own",
            Fallback::Llm => "the model",
            Fallback::Manual => "manual (a person answers at the dashboard)",
        }
    ));
    out
}
