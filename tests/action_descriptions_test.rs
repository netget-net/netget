//! The model picks an action from its description and nothing else.
//!
//! `tests/executable_examples_test.rs` asks whether an action's own example is one its
//! executor accepts — whether the shape the model copies works. This asks the question one
//! step earlier: whether what the model is *told* about an action and its parameters is enough
//! to choose it correctly, and whether what it is told is true.
//!
//! Two defects motivated it, and neither is visible to any structural check:
//!
//! * `send_first`'s description read "not typically needed for this protocol". A person reads
//!   that as "leave it alone". A model reads it as *you may set this and it will work* — and
//!   for a protocol that does not declare the parameter, setting it is a startup error. A
//!   description that describes frequency instead of effect is worse than a short one.
//! * Four ZooKeeper examples showed `"xid": "{{event.xid}}"`. That placeholder is real in a
//!   **static handler**, where the handler engine substitutes it. In a `response_example` —
//!   which is the template for the *model's own reply* — nothing substitutes anything, so the
//!   model sends the literal string `{{event.xid}}` and the protocol reads it as a malformed
//!   transaction id.
//!
//! # What is checked
//!
//! | Rule | Applies to |
//! |---|---|
//! | `log_template` is declared | every action |
//! | description is at least a sentence | every action, every parameter, every startup parameter |
//! | `type_hint` parses as a known type | every parameter, every startup parameter |
//! | `example` is present | every startup parameter |
//! | the example is an object whose `type` is the action's own name | every action |
//! | every **required** parameter appears in the action's example | every action |
//! | no `{{…}}` handler placeholder | every event `response_example` |
//! | an event field named in a response example exists on the event | every event |
//!
//! Each rule carries a shrink-only baseline of the sites that violate it today, so the rule
//! fails the build for anything new without demanding the whole tree be fixed in one pass.
//! **A baseline entry is a defect that is still there**, not an exemption — the entries are
//! what the next pass works through.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features all-protocols \
//!       --test action_descriptions_test -- --test-threads=100 --nocapture

use std::collections::BTreeSet;

use netget::llm::actions::{ActionDefinition, Parameter, ParameterDefinition};
use netget::protocol::client_registry::CLIENT_REGISTRY;
use netget::protocol::event_type::EventType;
use netget::protocol::server_registry::registry;
use netget::state::app_state::AppState;

/// The shortest thing that can be called a sentence.
///
/// Deliberately crude: a length bound, not a grammar. The point is to catch `""`, `"port"` and
/// `"the value"`, not to referee prose. Anything that clears it and is still useless is a
/// review problem, and the real-model eval (`PROTOCOL_QUALITY.md` Tier 4) is what measures it.
const MIN_DESCRIPTION_CHARS: usize = 15;

/// The type names a `type_hint` may be built from.
///
/// `integer` and `number` are both here because the tree uses both and they mean different
/// things to a model deciding whether `1.5` is allowed.
const BASE_TYPES: &[&str] = &[
    "string", "number", "integer", "boolean", "object", "array", "any", "null",
];

/// Does `hint` parse as a type the model can act on?
///
/// Four forms are accepted, and the third and fourth are why this is a parser rather than a
/// set membership test:
///
/// * a base type — `string`
/// * a union of base types — `number | string`, `string|null`
/// * `array of <base>s` — more informative than a bare `array`, and the tree uses it
/// * a **quoted alternation**, which is how a closed set of values is declared:
///   `"utf8" | "hex"`. `Parameter::with_choices` writes this form and `Parameter::choices`
///   reads it back, so it is a contract rather than a convention.
fn type_hint_is_known(hint: &str) -> bool {
    let hint = hint.trim();
    if hint.is_empty() {
        return false;
    }

    // Quoted alternation: every alternative is a quoted literal.
    let alternatives: Vec<&str> = hint.split('|').map(str::trim).collect();
    if alternatives
        .iter()
        .all(|a| a.len() >= 2 && a.starts_with('"') && a.ends_with('"'))
    {
        return true;
    }

    alternatives.iter().all(|alternative| {
        let a = alternative.trim();
        if BASE_TYPES.contains(&a) {
            return true;
        }
        // `array of strings`, `array of objects`, `array of integers`
        if let Some(inner) = a.strip_prefix("array of ") {
            let singular = inner.strip_suffix('s').unwrap_or(inner);
            return BASE_TYPES.contains(&singular);
        }
        false
    })
}

/// Every `{{…}}` placeholder in `value`, in source order.
///
/// These are the handler engine's substitution syntax. They belong in a static or script
/// handler, where something substitutes them; in a `response_example` the model copies the
/// braces onto the wire.
fn handler_placeholders(value: &serde_json::Value) -> Vec<String> {
    let text = value.to_string();
    let mut found = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                found.push(format!("{{{{{}}}}}", &after[..end]));
                rest = &after[end + 2..];
            }
            None => break,
        }
    }
    found
}

/// One violation, keyed so it can sit in a shrink-only baseline.
///
/// The key names the site, never the wording — a baseline keyed on the offending text would
/// have to be edited every time someone improves a description by one word, which trains
/// people to edit the baseline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    key: String,
    detail: String,
}

fn check_parameter(scope: &str, param: &Parameter, out: &mut Vec<Violation>) {
    if param.description.trim().chars().count() < MIN_DESCRIPTION_CHARS {
        out.push(Violation {
            key: format!("desc/param/{scope}/{}", param.name),
            detail: format!(
                "parameter description is {:?} — the model chooses from this alone",
                param.description
            ),
        });
    }
    if !type_hint_is_known(&param.type_hint) {
        out.push(Violation {
            key: format!("hint/param/{scope}/{}", param.name),
            detail: format!(
                "type_hint {:?} is not a base type, a `|` union of them, `array of <type>s`, \
                 or a quoted alternation",
                param.type_hint
            ),
        });
    }
}

fn check_startup_parameter(scope: &str, param: &ParameterDefinition, out: &mut Vec<Violation>) {
    if param.description.trim().chars().count() < MIN_DESCRIPTION_CHARS {
        out.push(Violation {
            key: format!("desc/startup/{scope}/{}", param.name),
            detail: format!("startup parameter description is {:?}", param.description),
        });
    }
    if !type_hint_is_known(&param.type_hint) {
        out.push(Violation {
            key: format!("hint/startup/{scope}/{}", param.name),
            detail: format!(
                "startup parameter type_hint {:?} is unknown",
                param.type_hint
            ),
        });
    }
    if param.example.is_null() {
        out.push(Violation {
            key: format!("example/startup/{scope}/{}", param.name),
            detail: "startup parameter has no example value".to_string(),
        });
    }
}

fn check_action(scope: &str, action: &ActionDefinition, out: &mut Vec<Violation>) {
    let site = format!("{scope}/{}", action.name);

    if action.log_template.is_none() {
        out.push(Violation {
            key: format!("log_template/{site}"),
            detail: "action declares no log_template, so its execution is logged generically \
                     and an operator cannot tell one call from another"
                .to_string(),
        });
    }

    if action.description.trim().chars().count() < MIN_DESCRIPTION_CHARS {
        out.push(Violation {
            key: format!("desc/action/{site}"),
            detail: format!("action description is {:?}", action.description),
        });
    }

    match action.example.as_object() {
        None => out.push(Violation {
            key: format!("example/shape/{site}"),
            detail: "action example is not a JSON object the model could send".to_string(),
        }),
        Some(obj) => {
            match obj.get("type").and_then(|t| t.as_str()) {
                Some(t) if t == action.name => {}
                Some(t) => out.push(Violation {
                    key: format!("example/type/{site}"),
                    detail: format!(
                        "action example says \"type\": {t:?} but the action is named {:?} — the \
                         model copies the example, so it would send an action nobody executes",
                        action.name
                    ),
                }),
                None => out.push(Violation {
                    key: format!("example/type/{site}"),
                    detail: "action example has no \"type\" field".to_string(),
                }),
            }
            for param in action.parameters.iter().filter(|p| p.required) {
                if !obj.contains_key(&param.name) {
                    out.push(Violation {
                        key: format!("example/missing/{site}/{}", param.name),
                        detail: format!(
                            "required parameter {:?} is absent from the action's own example, \
                             so the shape the model copies is one the executor rejects",
                            param.name
                        ),
                    });
                }
            }
        }
    }

    for param in &action.parameters {
        check_parameter(&site, param, out);
    }
}

fn check_event(scope: &str, event: &EventType, out: &mut Vec<Violation>) {
    let site = format!("{scope}/{}", event.id);

    for placeholder in handler_placeholders(&event.response_example) {
        out.push(Violation {
            key: format!("placeholder/{site}"),
            detail: format!(
                "response_example contains {placeholder}. That is handler-substitution syntax: \
                 real in a static or script handler, meaningless in the model's own reply, \
                 which is what a response_example is a template for. Show a literal value."
            ),
        });
    }

    // A response example that names an event field must name one the event carries. The model
    // is being told "echo this back", and an event that does not carry it cannot be echoed.
    let declared: BTreeSet<&str> = event.parameters.iter().map(|p| p.name.as_str()).collect();
    for placeholder in handler_placeholders(&event.response_example) {
        let inner = placeholder.trim_matches(|c| c == '{' || c == '}');
        if let Some(field) = inner.strip_prefix("event.") {
            if !declared.contains(field) {
                out.push(Violation {
                    key: format!("placeholder_field/{site}/{field}"),
                    detail: format!(
                        "response_example echoes event field {field:?}, which the event does \
                         not declare in its parameters (it declares {declared:?})"
                    ),
                });
            }
        }
    }

    for param in &event.parameters {
        check_parameter(&format!("{site}/event_data"), param, out);
    }
    for action in &event.actions {
        check_action(&format!("{site}/action"), action, out);
    }
}

/// Every violation this build can see, sorted and de-duplicated.
fn collect_violations() -> Vec<Violation> {
    let state = AppState::new();
    let mut out: Vec<Violation> = Vec::new();

    let mut servers = registry().all_protocols();
    servers.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, protocol) in servers {
        let scope = format!("server:{name}");
        for action in protocol.get_async_actions(&state) {
            check_action(&scope, &action, &mut out);
        }
        for action in protocol.get_sync_actions() {
            check_action(&scope, &action, &mut out);
        }
        for param in protocol.get_startup_parameters() {
            check_startup_parameter(&scope, &param, &mut out);
        }
        for event in protocol.get_event_types() {
            check_event(&scope, &event, &mut out);
        }
    }

    for client in CLIENT_REGISTRY.get_all() {
        let scope = format!("client:{}", client.protocol_name());
        for action in client.get_async_actions(&state) {
            check_action(&scope, &action, &mut out);
        }
        for action in client.get_sync_actions() {
            check_action(&scope, &action, &mut out);
        }
        for param in client.get_startup_parameters() {
            check_startup_parameter(&scope, &param, &mut out);
        }
        for event in client.get_event_types() {
            check_event(&scope, &event, &mut out);
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Sites that violate a rule above today, measured at `--features all-protocols`.
///
/// **Every entry is a defect, not an exemption.** They are listed so the rule can fail the
/// build for anything *new* without demanding 1113 declarations be rewritten in one pass, and
/// the list is the work queue for the next one. It may only shrink;
/// `the_baseline_has_no_stale_entries` fails if an entry outlives the defect it names.
///
/// Kept as a data file rather than a `&[&str]` literal: a thousand-line array buried in a test
/// is unreadable, and a one-key-per-line file diffs as what it is — a queue getting shorter.
const BASELINE_FILE: &str = include_str!("action_descriptions_baseline.txt");

fn baseline() -> BTreeSet<&'static str> {
    BASELINE_FILE
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn no_new_action_or_parameter_is_undescribed() {
    let violations = collect_violations();
    let baseline = baseline();

    let mut new: Vec<&Violation> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for v in &violations {
        seen.insert(v.key.as_str());
        if !baseline.contains(v.key.as_str()) {
            new.push(v);
        }
    }

    println!("\n=== action/parameter description audit ===");
    println!("violations in this build: {}", violations.len());
    println!("baseline entries:         {}", baseline.len());
    println!("baseline entries this build can see: {}", seen.len());

    assert!(
        new.is_empty(),
        "{} action/parameter description problem(s) not in the baseline.\n\n\
         The model chooses an action from its description, its type hints and its example, and \
         nothing else. Fix the declaration; add to the baseline only for something this rule \
         genuinely cannot express, and say why in the same commit.\n\n{}",
        new.len(),
        new.iter()
            .map(|v| format!("  {}\n      {}", v.key, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The baseline may only shrink, so an entry nothing produces any more must go.
///
/// Feature-gated: at a narrow feature set most of the baseline names protocols this build did
/// not compile, and they would all read as stale. Only run the check where the build can see
/// everything the baseline was measured against.
#[test]
#[ignore = "the baseline is measured at --features all-protocols; a narrower build cannot \
              tell a fixed entry from an uncompiled one"]
fn the_baseline_has_no_stale_entries() {
    let violations = collect_violations();
    let live: BTreeSet<&str> = violations.iter().map(|v| v.key.as_str()).collect();

    let stale: Vec<&str> = baseline()
        .into_iter()
        .filter(|k| !live.contains(k))
        .collect();

    assert!(
        stale.is_empty(),
        "{} baseline entr(ies) name a site that no longer violates the rule. A baseline that \
         does not shrink when the code does is read by the next person as permission that is \
         still needed — delete these:\n{}",
        stale.len(),
        stale.join("\n")
    );
}

#[test]
fn the_type_hint_grammar_accepts_what_the_tree_uses_and_refuses_what_it_should() {
    for good in [
        "string",
        "number",
        "integer",
        "boolean",
        "object",
        "array",
        "any",
        "string|null",
        "number | string",
        "array | object",
        "array of strings",
        "array of objects",
        "array of integers",
        "\"utf8\" | \"hex\"",
    ] {
        assert!(type_hint_is_known(good), "{good:?} should be accepted");
    }
    for bad in ["", "bool", "str", "string or number", "a port", "list"] {
        assert!(!type_hint_is_known(bad), "{bad:?} should be refused");
    }
}

#[test]
fn a_handler_placeholder_is_found_wherever_it_hides() {
    // The ZooKeeper shape: nested inside an array, inside an object.
    let example = serde_json::json!([{"type": "send_zk_response", "xid": "{{event.xid}}"}]);
    assert_eq!(handler_placeholders(&example), vec!["{{event.xid}}"]);
    assert!(handler_placeholders(&serde_json::json!({"xid": 1})).is_empty());
}
