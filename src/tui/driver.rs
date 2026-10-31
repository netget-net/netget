//! Who answers an instance's events, in one word.
//!
//! An instance's handler table can hold any number of rules, but the one
//! that decides its character is the wildcard: what happens to an event no
//! specific rule claims. That is the **driver**, and it is what the list badge
//! shows and what `[ driver: … ]` / `m` cycles. Cycling rewrites only the
//! wildcard rule; every specific rule survives.

use serde_json::{json, Value};

use crate::scripting::event_handler::EventPattern;
use crate::scripting::{EventHandlerConfig, EventHandlerType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    /// `*` → manual: every unmatched event parks for the human.
    Manual,
    /// No wildcard rule (or `*` → LLM): the model answers, from the instance
    /// instruction.
    Llm,
    /// `*` → static with no actions: acknowledge, never reply.
    Silent,
    /// `*` → a script or a static list with actions: something custom.
    Rules,
}

impl Driver {
    /// Badge text.
    pub fn label(&self) -> &'static str {
        match self {
            Driver::Manual => "MANUAL",
            Driver::Llm => "LLM",
            Driver::Silent => "SILENT",
            Driver::Rules => "RULES",
        }
    }

    /// One phrase for the overview.
    pub fn describe(&self) -> &'static str {
        match self {
            Driver::Manual => "you answer each event here",
            Driver::Llm => "the model answers, from the instruction",
            Driver::Silent => "events are acknowledged and never answered",
            Driver::Rules => "a wildcard rule answers (script or fixed actions)",
        }
    }

    /// The driver `m` moves to. `Rules` is not a target — it is whatever the
    /// user built — so from it the cycle restarts at MANUAL.
    pub fn next(&self) -> Driver {
        match self {
            Driver::Manual => Driver::Llm,
            Driver::Llm => Driver::Silent,
            Driver::Silent | Driver::Rules => Driver::Manual,
        }
    }
}

/// Read the driver off a handler table.
pub fn driver_of(routing: Option<&EventHandlerConfig>) -> Driver {
    let Some(config) = routing else {
        return Driver::Llm;
    };
    let wildcard = config.handlers.iter().find(|h| is_fallback(h));
    match wildcard.map(|h| &h.handler) {
        None => Driver::Llm,
        Some(EventHandlerType::Manual { .. }) => Driver::Manual,
        Some(EventHandlerType::Llm { .. }) => Driver::Llm,
        Some(EventHandlerType::Static { actions }) if actions.is_empty() => Driver::Silent,
        Some(EventHandlerType::Static { .. }) | Some(EventHandlerType::Script { .. }) => {
            Driver::Rules
        }
    }
}

/// Whether a rule is the table's fallback: `*` with no `match` conditions. A `*` rule with
/// conditions answers only some events, so it is a specific rule like any other.
fn is_fallback(handler: &crate::scripting::event_handler::EventHandler) -> bool {
    matches!(handler.event_pattern, EventPattern::Wildcard) && handler.data_match.is_none()
}

/// How many specific (non-wildcard) rules the table holds.
pub fn specific_rule_count(routing: Option<&EventHandlerConfig>) -> usize {
    routing
        .map(|c| c.handlers.iter().filter(|h| !is_fallback(h)).count())
        .unwrap_or(0)
}

/// Rebuild the table as JSON with the wildcard rule replaced for `driver`.
///
/// Specific rules are kept in order; the wildcard goes last, where
/// first-match-wins semantics need it. `Llm` means *no* wildcard, which is
/// how the instance instruction becomes the fallback. `Rules` cannot be
/// expressed (it is not a single rule) and is treated as `Manual`.
pub fn handlers_with_driver(routing: Option<&EventHandlerConfig>, driver: Driver) -> Vec<Value> {
    let mut out: Vec<Value> = routing
        .map(|c| {
            c.handlers
                .iter()
                .filter(|h| !is_fallback(h))
                .filter_map(|h| serde_json::to_value(h).ok())
                .collect()
        })
        .unwrap_or_default();
    match driver {
        Driver::Llm => {}
        Driver::Silent => out.push(json!({
            "event_pattern": "*",
            "handler": {"type": "static", "actions": []}
        })),
        Driver::Manual | Driver::Rules => out.push(json!({
            "event_pattern": "*",
            "handler": {"type": "manual"}
        })),
    }
    out
}
