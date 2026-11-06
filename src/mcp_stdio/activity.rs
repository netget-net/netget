//! What `client_status` / `server_status` say about an instance's behaviour: the event
//! handlers it runs, how many events it has handled and who answered them, and its most
//! recent access-log entries.
//!
//! All of it is read from state other tools already expose — the handler table
//! (`update_client` / `update_server` set it) and the access log (`list_access_logs`,
//! `get_access_log`) — so status and the log cannot disagree about what happened.

use crate::scripting::{EventHandlerConfig, EventHandlerType};
use crate::state::app_state::{AccessLogEntry, AccessLogOwner, AppState};

use super::tools::{summarize_request, summarize_response};

/// How many recent events a status shows.
pub const RECENT_EVENTS_IN_STATUS: usize = 5;

/// Wall-clock now, in Unix milliseconds (the access log's clock).
pub fn now_unix_ms() -> u64 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One access-log entry as a list line: id, age, owner (when `with_owner`), event type,
/// request summary, the actions it was answered with, and what answered it.
pub fn access_log_line(entry: &AccessLogEntry, now_ms: u64, with_owner: bool) -> String {
    let age = now_ms.saturating_sub(entry.unix_ms) / 1000;
    let owner = if with_owner {
        let who = match (entry.server_id, entry.client_id) {
            (Some(id), _) => format!("server #{id}"),
            (None, Some(id)) => format!("client #{id}"),
            (None, None) => "unknown".to_string(),
        };
        format!(" {} ({}) —", who, entry.protocol)
    } else {
        String::new()
    };
    format!(
        "- **#{}** [{}s ago]{} {} — {} → {}{}\n",
        entry.id,
        age,
        owner,
        entry.event_type,
        summarize_request(&entry.request),
        summarize_response(&entry.response),
        entry
            .answered_by
            .as_deref()
            .map(|by| format!(" (answered by {by})"))
            .unwrap_or_default(),
    )
}

/// One handler as an operator reads it: `pattern → kind: detail`.
fn describe_handler_type(handler: &EventHandlerType) -> String {
    match handler {
        EventHandlerType::Llm { instruction } => {
            if instruction.trim().is_empty() {
                "model".to_string()
            } else {
                format!(
                    "model: \"{}\"",
                    crate::utils::truncate_with_suffix(instruction.trim(), 80, "…")
                )
            }
        }
        EventHandlerType::Script {
            language, resident, ..
        } => format!(
            "script ({language}{})",
            if *resident { ", resident" } else { "" }
        ),
        EventHandlerType::Static { actions } => {
            let names: Vec<&str> = actions
                .iter()
                .filter_map(|a| a.get("type").and_then(|t| t.as_str()))
                .collect();
            if names.is_empty() {
                "static: answer with nothing".to_string()
            } else {
                format!("static: {}", names.join(", "))
            }
        }
        EventHandlerType::Manual { timeout_secs } => {
            format!("manual (you answer via answer_intercept; fails closed after {timeout_secs}s)")
        }
    }
}

/// The `### Event handlers` section: each rule in match order, first match wins.
pub fn handlers_section(config: Option<&EventHandlerConfig>) -> String {
    let handlers = config.map(|c| c.handlers.as_slice()).unwrap_or_default();
    if handlers.is_empty() {
        return "- **Event handlers**: none — every event goes to the model\n".to_string();
    }
    let mut out = String::from("\n### Event handlers (first match wins)\n\n");
    for (index, handler) in handlers.iter().enumerate() {
        out.push_str(&format!(
            "{}. `{}` → {}\n",
            index + 1,
            handler.describe(),
            describe_handler_type(&handler.handler)
        ));
    }
    if !handlers
        .iter()
        .any(|h| matches!(h.event_pattern, crate::scripting::EventPattern::Wildcard))
    {
        out.push_str("Events no rule matches go to the model.\n");
    }
    out
}

/// The `### Activity` and `### Recent events` sections for one instance.
///
/// `llm_calls` is a client's `(used, limit)` model-call budget, where it has one.
pub async fn activity_section(
    state: &AppState,
    owner: AccessLogOwner,
    llm_calls: Option<(u32, u32)>,
) -> String {
    let activity = state.access_activity(owner).await;
    let recent = state
        .list_access_logs_for(Some(owner), Some(RECENT_EVENTS_IN_STATUS))
        .await;
    let now_ms = now_unix_ms();
    let (kind, id) = match owner {
        AccessLogOwner::Server(id) => ("server", id),
        AccessLogOwner::Client(id) => ("client", id),
    };

    let mut out = String::from("\n### Activity\n\n");
    let breakdown: Vec<String> = activity
        .answered_by
        .iter()
        .map(|(by, n)| format!("{by} {n}"))
        .collect();
    out.push_str(&format!(
        "- **Events handled**: {}{}\n",
        activity.events,
        if breakdown.is_empty() {
            String::new()
        } else {
            format!(" (answered by: {})", breakdown.join(", "))
        }
    ));
    out.push_str(&format!(
        "- **Actions answered with**: {}{}\n",
        activity.actions,
        if matches!(owner, AccessLogOwner::Client(_)) {
            " (as produced; the client's own loop executes them)"
        } else {
            ""
        }
    ));
    out.push_str(&format!(
        "- **Actions sent by hand**: {}\n",
        activity.injected
    ));
    if let Some(last) = activity.last_unix_ms {
        out.push_str(&format!(
            "- **Last event**: {}s ago\n",
            now_ms.saturating_sub(last) / 1000
        ));
    }
    if let Some((used, limit)) = llm_calls {
        if limit == 0 {
            out.push_str(&format!("- **Model calls**: {used} (no limit)\n"));
        } else {
            out.push_str(&format!("- **Model calls**: {used} of {limit}\n"));
        }
    }

    if recent.is_empty() {
        out.push_str(
            "\nNo events recorded yet. An event is recorded once it has been answered; one \
             whose model call failed leaves no entry.\n",
        );
        return out;
    }
    out.push_str(&format!(
        "\n### Recent events (newest first)\n\n\
         More with `list_access_logs {{\"{kind}_id\": {id}}}`; one in full with \
         `get_access_log {{\"id\": …}}`.\n\n"
    ));
    for entry in &recent {
        out.push_str(&access_log_line(entry, now_ms, false));
    }
    out
}
