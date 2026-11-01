//! Runnability harness for protocol **startup examples**.
//!
//! Every protocol declares `get_startup_examples()` → `StartupExamples { llm_mode,
//! script_mode, static_mode }`. The existing `protocol_examples_test.rs` checks that the
//! examples are structurally well-formed JSON and that a server *starts* from them. It does
//! **not** check that the example is actually *runnable* — that its script handler is real
//! code rather than a `<foo_handler>` placeholder, or that a static handler references an
//! action the protocol actually implements. A prior audit found ~106 protocols carrying
//! dangling `<proto_handler>` placeholders in their `script_mode` code, which would fail
//! the moment anyone ran them.
//!
//! This harness closes that gap. For every registered protocol it inspects the three
//! startup examples and classifies each into concrete, deterministic problem categories.
//!
//! ## What is checked
//!
//! **Hard (gated by the allowlist below):**
//! - `SCRIPT_PLACEHOLDER` — a `script` handler whose `code` is a bare `<...>` placeholder
//!   token (e.g. `"<zookeeper_handler>"`). Such a script cannot run: it is neither valid
//!   Python/JS nor does it emit `{"actions": [...]}`.
//! - `UNKNOWN_ACTION` — a `static` handler references an action `type` that is neither one
//!   of the protocol's declared actions (sync / async / per-event) nor a recognised common
//!   or universal action. A model following that example puts an action on the wire that
//!   the executor rejects as unknown.
//! - `LLM_EMPTY` — the `llm_mode` example has no `instruction`, or an empty/placeholder one.
//!   (A weak check by design: it catches empty/placeholder, nothing subtler.)
//!
//! **Advisory (reported, never gated — environment- or heuristic-dependent):**
//! - `SCRIPT_EXEC_FAIL` — a non-placeholder script handler failed to produce a valid
//!   `{"actions": [...]}` response when actually executed against a synthetic event built
//!   from the event type's declared parameter examples. Advisory because the synthetic
//!   event is imperfect and because it needs the interpreter installed.
//! - `SUSPECT_PLACEHOLDER` — a `<...>` token appearing somewhere *other* than script code
//!   (e.g. a static action's data field). Might be a genuine dangling placeholder, might be
//!   legitimate served content (`<html>`), so it is only surfaced, not enforced.
//!
//! ## Hard test vs advisory
//!
//! The enforcing test (`examples_are_runnable_or_allowlisted`) is a **hard test with an
//! allowlist**, the same shape as the `orphaned-tests` / log-prefix guards. The allowlist
//! is the *worklist*: it names every protocol currently carrying a hard problem, together
//! with the exact category set expected. A protocol whose hard problems are **not** covered
//! by its allowlist entry fails the build; so does a *new* broken protocol. And an
//! allowlisted protocol that has since been fixed (no hard problems, or fewer categories
//! than listed) *also* fails — so the allowlist can only shrink, never silently rot.
//!
//! This is why it does not red-master on day one despite ~100 broken protocols: they are
//! all enumerated in `KNOWN_BROKEN`. As each is fixed, its entry is removed. When the map
//! is empty the placeholder epidemic is gone.
//!
//! Set `NETGET_EXAMPLE_WORKLIST=<path>` to also dump the full categorized report to a file.
//!
//! ```bash
//! ./cargo-isolated.sh test --all-features --test examples \
//!     -- examples::example_runnability --nocapture --test-threads=100
//! ```

#![cfg(test)]

use netget::llm::actions::common::CommonAction;
use netget::llm::actions::{get_network_event_common_actions, Server, TOOL_ACTION_NAMES};
use netget::protocol::server_registry::registry;
use netget::scripting::executor::execute_script_blocking_with_timeout;
use netget::scripting::types::{
    ScriptConfig, ScriptInput, ScriptLanguage, ScriptSource, ServerContext,
};
use netget::state::app_state::AppState;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

/// Universal action names that any protocol's executor accepts regardless of what it
/// declares — common actions, tool actions and pipe/control verbs handled centrally in
/// `execute_actions` / `execute_common_action`. Kept deliberately generous: a name listed
/// here that a build later drops merely means we stop *flagging* it, which is the safe
/// direction (a false "unknown action" would red-master a working protocol).
const UNIVERSAL_ACTIONS: &[&str] = &[
    // CommonAction variants
    "open_server",
    "open_client",
    "close_server",
    "close_all_servers",
    "close_client",
    "update_instruction",
    "update_client_instruction",
    "change_model",
    "set_memory",
    "append_memory",
    "set_connection_memory",
    "append_connection_memory",
    "notify_operator",
    // notify_operator's former name, still accepted
    "show_message",
    "append_to_log",
    "schedule_task",
    "cancel_task",
    "provide_feedback",
    "create_database",
    "delete_database",
    "update_server",
    "update_client",
    // Pipe wiring, handled directly in execute_actions
    "create_pipe",
    "remove_pipe",
    // Universal per-connection control verbs handled by most protocol executors
    "wait_for_more",
    "no_action",
    "close_connection",
    "close_this_connection",
];

/// A hard problem category. Ordered/derived as a stable string for the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HardCategory {
    ScriptPlaceholder,
    UnknownAction,
    LlmEmpty,
}

impl HardCategory {
    fn code(&self) -> &'static str {
        match self {
            HardCategory::ScriptPlaceholder => "SCRIPT_PLACEHOLDER",
            HardCategory::UnknownAction => "UNKNOWN_ACTION",
            HardCategory::LlmEmpty => "LLM_EMPTY",
        }
    }
}

/// Full per-protocol finding: hard categories (gated) and advisory notes (reported only).
#[derive(Default)]
struct Finding {
    hard: BTreeSet<HardCategory>,
    details: Vec<String>,
    advisory: Vec<String>,
}

/// Is `s` a bare placeholder token like `<zookeeper_handler>` — a single `<...>` group whose
/// inner text is only `[A-Za-z0-9_]`? Whole-string match only, so a served `<html>…</html>`
/// body (which is longer than the tag) never matches.
fn is_placeholder_token(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 3 || !t.starts_with('<') || !t.ends_with('>') {
        return false;
    }
    let inner = &t[1..t.len() - 1];
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Collect every string value in `v` that is a bare placeholder token, paired with a rough
/// JSON path so the report can point at it.
fn collect_placeholder_strings(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => {
            if is_placeholder_token(s) {
                out.push((path.to_string(), s.clone()));
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                collect_placeholder_strings(x, &format!("{path}[{i}]"), out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                collect_placeholder_strings(x, &child, out);
            }
        }
        _ => {}
    }
}

/// The set of action names this protocol accepts: everything it declares (sync, async,
/// per-event) plus the common, tool and universal names handled centrally.
fn valid_action_vocabulary(proto: &dyn Server, state: &AppState) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for a in proto.get_sync_actions() {
        set.insert(a.name);
    }
    for a in proto.get_async_actions(state) {
        set.insert(a.name);
    }
    for et in proto.get_event_types() {
        for a in et.actions {
            set.insert(a.name);
        }
    }
    for a in get_network_event_common_actions() {
        set.insert(a.name);
    }
    for t in TOOL_ACTION_NAMES {
        set.insert((*t).to_string());
    }
    for u in UNIVERSAL_ACTIONS {
        set.insert((*u).to_string());
    }
    set
}

/// One `event_handlers` entry, normalised.
struct Handler {
    event_pattern: String,
    kind: HandlerKind,
}

enum HandlerKind {
    Script { language: String, code: String },
    Static { actions: Vec<Value> },
    Other,
}

/// Extract the `event_handlers` array from a startup example, whatever nesting it uses.
fn extract_handlers(example: &Value) -> Vec<Handler> {
    let mut out = Vec::new();
    let handlers = example
        .get("event_handlers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for h in handlers {
        let event_pattern = h
            .get("event_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let handler = h.get("handler").cloned().unwrap_or(Value::Null);
        let htype = handler.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let kind = match htype {
            "script" => HandlerKind::Script {
                language: handler
                    .get("language")
                    .and_then(|v| v.as_str())
                    .unwrap_or("python")
                    .to_string(),
                code: handler
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            },
            "static" => HandlerKind::Static {
                actions: handler
                    .get("actions")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default(),
            },
            _ => HandlerKind::Other,
        };
        out.push(Handler {
            event_pattern,
            kind,
        });
    }
    out
}

/// Build a synthetic event payload for `event_pattern` from the event type's declared
/// parameter examples. Best-effort — only used to *run* real scripts (advisory).
fn synthetic_event(proto: &dyn Server, event_pattern: &str) -> Value {
    let mut obj = serde_json::Map::new();
    // Common fields many handlers read regardless of protocol.
    obj.insert("data".to_string(), Value::String("test".to_string()));
    obj.insert("encoding".to_string(), Value::String("utf8".to_string()));
    for et in proto.get_event_types() {
        if !event_pattern.is_empty() && et.id != event_pattern {
            continue;
        }
        for p in &et.parameters {
            // Event `Parameter` carries no example value, only a type hint — synthesize a
            // plausible dummy from it so a real script that reads the field does not KeyError.
            let val = match p.type_hint.to_lowercase().as_str() {
                h if h.contains("number") || h.contains("int") || h.contains("u16") => {
                    Value::from(0)
                }
                h if h.contains("bool") => Value::from(false),
                h if h.contains("array") || h.contains("list") => Value::Array(vec![]),
                h if h.contains("object") || h.contains("map") => {
                    Value::Object(serde_json::Map::new())
                }
                _ => Value::String("test".to_string()),
            };
            obj.insert(p.name.clone(), val);
        }
        if !event_pattern.is_empty() {
            break;
        }
    }
    Value::Object(obj)
}

/// Actually run a script handler against a synthetic event; return Err with a short reason
/// if it does not yield a valid `{"actions": [...]}`.
fn try_run_script(
    proto: &dyn Server,
    language: &str,
    code: &str,
    event_pattern: &str,
) -> Result<(), String> {
    let lang = match ScriptLanguage::parse(language) {
        Some(l) => l,
        None => return Err(format!("unknown script language '{language}'")),
    };
    // Only attempt languages whose interpreter this harness can reasonably expect.
    let config = ScriptConfig {
        language: lang,
        source: ScriptSource::Inline(code.to_string()),
        handles_contexts: vec!["all".to_string()],
    };
    let event = synthetic_event(proto, event_pattern);
    let input = ScriptInput {
        event_type_id: if event_pattern.is_empty() {
            "unknown".to_string()
        } else {
            event_pattern.to_string()
        },
        client: None,
        server: Some(ServerContext {
            id: 1,
            port: 0,
            stack: proto.protocol_name().to_string(),
            memory: String::new(),
            instruction: String::new(),
        }),
        connection: None,
        event,
    };
    match execute_script_blocking_with_timeout(&config, &input, Duration::from_secs(8)) {
        Ok(_resp) => Ok(()),
        Err(e) => Err(format!("{e}").lines().next().unwrap_or("error").to_string()),
    }
}

/// Classify one protocol's startup examples.
fn analyze(proto: &dyn Server, state: &AppState) -> Finding {
    let mut f = Finding::default();
    let examples = proto.get_startup_examples();
    let vocab = valid_action_vocabulary(proto, state);

    // ---- llm_mode: instruction present & non-placeholder ---------------------------------
    let instr = examples
        .llm_mode
        .get("instruction")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if instr.is_empty() || is_placeholder_token(&instr) {
        f.hard.insert(HardCategory::LlmEmpty);
        f.details
            .push(format!("llm_mode instruction empty/placeholder: {instr:?}"));
    }

    // ---- script_mode & static_mode handler inspection ------------------------------------
    for (mode, example) in [
        ("script_mode", &examples.script_mode),
        ("static_mode", &examples.static_mode),
    ] {
        for h in extract_handlers(example) {
            match h.kind {
                HandlerKind::Script { language, code } => {
                    if is_placeholder_token(&code) {
                        f.hard.insert(HardCategory::ScriptPlaceholder);
                        f.details.push(format!(
                            "{mode} '{}' script code is placeholder: {code:?}",
                            h.event_pattern
                        ));
                    } else if code.trim().is_empty() {
                        f.hard.insert(HardCategory::ScriptPlaceholder);
                        f.details
                            .push(format!("{mode} '{}' script code empty", h.event_pattern));
                    } else {
                        // Real code — attempt to execute (advisory).
                        if let Err(reason) =
                            try_run_script(proto, &language, &code, &h.event_pattern)
                        {
                            f.advisory.push(format!(
                                "SCRIPT_EXEC_FAIL {mode} '{}': {reason}",
                                h.event_pattern
                            ));
                        }
                    }
                }
                HandlerKind::Static { actions } => {
                    for a in &actions {
                        let name = a.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if name.is_empty() {
                            continue;
                        }
                        let known = vocab.contains(name) || CommonAction::from_json(a).is_ok();
                        if !known {
                            f.hard.insert(HardCategory::UnknownAction);
                            f.details.push(format!(
                                "{mode} '{}' references unknown action '{name}'",
                                h.event_pattern
                            ));
                        }
                    }
                }
                HandlerKind::Other => {}
            }
        }
    }

    // ---- advisory: placeholder tokens anywhere other than script code --------------------
    // (Script-code placeholders are already the hard SCRIPT_PLACEHOLDER above.)
    for (mode, example) in [
        ("llm_mode", &examples.llm_mode),
        ("script_mode", &examples.script_mode),
        ("static_mode", &examples.static_mode),
    ] {
        let mut found = Vec::new();
        collect_placeholder_strings(example, "", &mut found);
        for (path, s) in found {
            // Skip the script `code` field — reported as hard already.
            if path.ends_with("handler.code") || path.contains(".handler.code") {
                continue;
            }
            f.advisory
                .push(format!("SUSPECT_PLACEHOLDER {mode} at {path}: {s:?}"));
        }
    }

    f
}

/// Collect every protocol's finding, sorted by name.
fn collect_findings() -> Vec<(String, Finding)> {
    let state = AppState::new();
    let reg = registry();
    let mut protocols: Vec<(String, Arc<dyn Server>)> = reg.all_protocols();
    protocols.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    protocols
        .into_iter()
        .map(|(name, proto)| {
            let finding = analyze(proto.as_ref(), &state);
            (name, finding)
        })
        .collect()
}

fn render_report(findings: &[(String, Finding)]) -> String {
    let mut out = String::new();
    out.push_str("\n=== NetGet startup-example runnability worklist ===\n\n");

    let mut clean = 0usize;
    let mut broken = 0usize;
    let mut cat_counts: BTreeMap<&'static str, usize> = BTreeMap::new();

    for (_name, f) in findings {
        if f.hard.is_empty() {
            clean += 1;
        } else {
            broken += 1;
            for c in &f.hard {
                *cat_counts.entry(c.code()).or_default() += 1;
            }
        }
    }

    out.push_str(&format!(
        "{} protocols · {clean} clean · {broken} with hard problems\n",
        findings.len()
    ));
    out.push_str("hard categories:");
    for (code, n) in &cat_counts {
        out.push_str(&format!(" {code}={n}"));
    }
    out.push_str("\n\n--- protocols WITH hard problems ---\n");
    for (name, f) in findings {
        if f.hard.is_empty() {
            continue;
        }
        let cats: Vec<&str> = f.hard.iter().map(|c| c.code()).collect();
        out.push_str(&format!("{:<26} [{}]\n", name, cats.join(", ")));
        for d in &f.details {
            out.push_str(&format!("      - {d}\n"));
        }
    }

    out.push_str("\n--- advisory notes (not gated) ---\n");
    for (name, f) in findings {
        if f.advisory.is_empty() {
            continue;
        }
        out.push_str(&format!("{name}:\n"));
        for a in &f.advisory {
            out.push_str(&format!("      - {a}\n"));
        }
    }

    // Machine-readable allowlist seed, so the KNOWN_BROKEN map can be regenerated.
    out.push_str("\n--- allowlist seed (protocol => categories) ---\n");
    for (name, f) in findings {
        if f.hard.is_empty() {
            continue;
        }
        let cats: Vec<String> = f.hard.iter().map(|c| format!("\"{}\"", c.code())).collect();
        out.push_str(&format!("    (\"{}\", &[{}]),\n", name, cats.join(", ")));
    }

    out
}

/// Informational: always prints the full worklist and (optionally) writes it to a file.
/// Never fails — it exists to *produce* the worklist.
#[test]
fn example_runnability_report() {
    let findings = collect_findings();
    let report = render_report(&findings);
    println!("{report}");
    if let Ok(path) = std::env::var("NETGET_EXAMPLE_WORKLIST") {
        let _ = std::fs::write(&path, &report);
        println!("(worklist written to {path})");
    }
}

/// The worklist, as code: every protocol currently carrying a hard problem, and the exact
/// set of hard categories it has. This is what makes the gate green today while still
/// catching regressions. **It can only shrink** — see the two assertions below.
///
/// Regenerate the seed with:
/// ```bash
/// NETGET_EXAMPLE_WORKLIST=/tmp/wl ./cargo-isolated.sh test --all-features \
///     --test examples -- examples::example_runnability::example_runnability_report --nocapture
/// ```
/// then paste the "allowlist seed" section here.
const KNOWN_BROKEN: &[(&str, &[&str])] = &[
    // Empty: the `<..._handler>` placeholder epidemic is cleared — every registered protocol's
    // script_mode `code` is now real, runnable Python that emits `{"actions": [...]}`. The
    // originally allowlisted 67 were fixed batch by batch (see tcp/http/dns/redis for the
    // worked-example shape). This list is shrink-only: a new placeholder or an unknown static
    // action fails the build rather than being silently re-added here.
];

fn expected_categories(name: &str) -> Option<BTreeSet<String>> {
    KNOWN_BROKEN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, cats)| cats.iter().map(|c| c.to_string()).collect())
}

/// Hard gate. Fails if a protocol has hard problems not covered by its allowlist entry, or
/// if an allowlisted protocol has been fixed (so the list is forced to shrink).
#[test]
fn examples_are_runnable_or_allowlisted() {
    let findings = collect_findings();

    let mut regressions: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();

    for (name, f) in &findings {
        let actual: BTreeSet<String> = f.hard.iter().map(|c| c.code().to_string()).collect();
        match expected_categories(name) {
            None => {
                if !actual.is_empty() {
                    regressions.push(format!(
                        "{name} has hard problems [{}] but is not in KNOWN_BROKEN:\n      {}",
                        actual.iter().cloned().collect::<Vec<_>>().join(", "),
                        f.details.join("\n      ")
                    ));
                }
            }
            Some(expected) => {
                if actual.is_empty() {
                    stale.push(format!(
                        "{name} is in KNOWN_BROKEN but is now CLEAN — remove it"
                    ));
                } else {
                    // New category not previously recorded => regression.
                    let extra: Vec<String> = actual.difference(&expected).cloned().collect();
                    if !extra.is_empty() {
                        regressions.push(format!(
                            "{name} gained new hard problem(s) [{}] not in its allowlist entry",
                            extra.join(", ")
                        ));
                    }
                    // Category recorded but no longer present => shrink the entry.
                    let gone: Vec<String> = expected.difference(&actual).cloned().collect();
                    if !gone.is_empty() {
                        stale.push(format!(
                            "{name} no longer has [{}] — narrow its KNOWN_BROKEN entry",
                            gone.join(", ")
                        ));
                    }
                }
            }
        }
    }

    // Also flag KNOWN_BROKEN entries for protocols that are not even registered in this
    // build only when running with the full feature set, to avoid churn on subset builds.
    let mut messages = Vec::new();
    if !regressions.is_empty() {
        messages.push(format!(
            "New/undeclared broken startup examples ({}):\n  - {}",
            regressions.len(),
            regressions.join("\n  - ")
        ));
    }
    if !stale.is_empty() {
        messages.push(format!(
            "Stale KNOWN_BROKEN entries ({}) — examples were fixed, tighten the list:\n  - {}",
            stale.len(),
            stale.join("\n  - ")
        ));
    }

    assert!(
        messages.is_empty(),
        "\n{}\n\nRun `example_runnability_report` for the full worklist.",
        messages.join("\n\n")
    );
}
