//! The `answer_with` hint `otlp_export` carries, and examples that are placeholders.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- otlp::answer_with --test-threads=100

use netget::server::otlp::actions::{answer_with, OTLP_EXPORT_EVENT};
use netget::server::otlp::codec::Signal;

#[test]
fn the_hint_names_the_three_verdicts_and_the_items_for_each_signal() {
    let hint = answer_with(Signal::Metrics, 7);
    assert!(hint.starts_with("exactly one action"), "{hint}");
    for needle in [
        "accept_otlp",
        "accept_otlp_partially",
        "reject_otlp",
        "7 data points",
        "403",
        "429/503",
    ] {
        assert!(hint.contains(needle), "missing {needle}: {hint}");
    }
    assert!(answer_with(Signal::Traces, 1).contains("1 spans"));
    assert!(answer_with(Signal::Logs, 2).contains("2 log records"));
}

#[test]
fn the_event_carries_answer_with_and_placeholder_examples() {
    let event = &*OTLP_EXPORT_EVENT;
    assert!(event.parameters.iter().any(|p| p.name == "answer_with"));
    for action in &event.actions {
        let text = action.example.to_string();
        if text.contains("message") {
            assert!(text.contains("<why>"), "{text}");
        }
    }
}
