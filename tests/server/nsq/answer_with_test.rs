//! The `answer_with` hints each NSQ event carries, and examples that are placeholders.
//!
//! The eval-fix round found small models copying an action's example content verbatim when it
//! was close enough to the instruction to pass for it (beanstalkd's job body, gemini's page).
//! NSQ starts with placeholder examples, and every request names the one answer it takes and
//! where a delivered body comes from.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::answer_with --test-threads=100


use netget::server::nsq::actions::{
    deliver_answer_with, publish_answer_with, requeue_answer_with, subscribe_answer_with,
    NSQ_FINISH_EVENT, NSQ_PUBLISH_EVENT, NSQ_READY_EVENT, NSQ_REQUEUE_EVENT, NSQ_SUBSCRIBE_EVENT,
};

#[test]
fn a_publish_names_its_refusal_code_and_one_action() {
    let hint = publish_answer_with("MPUB", "orders", 3);
    assert!(
        hint.starts_with("exactly one action: send_nsq_ok"),
        "{hint}"
    );
    assert!(
        hint.contains("3 message(s)") && hint.contains("'orders'"),
        "{hint}"
    );
    assert!(hint.contains("E_MPUB_FAILED"), "{hint}");
    assert!(publish_answer_with("PUB", "t", 1).contains("E_PUB_FAILED"));
    assert!(publish_answer_with("DPUB", "t", 1).contains("E_DPUB_FAILED"));
}

#[test]
fn a_subscription_says_no_messages_yet() {
    let hint = subscribe_answer_with("orders", "workers");
    assert!(
        hint.contains("'orders'") && hint.contains("'workers'"),
        "{hint}"
    );
    assert!(hint.contains("has not sent RDY"), "{hint}");
}

#[test]
fn a_delivery_names_its_room_and_where_bodies_come_from() {
    let hint = deliver_answer_with("orders", 2, 0);
    assert!(
        hint.starts_with("deliver_nsq_messages with at most 2"),
        "{hint}"
    );
    assert!(hint.contains("word for word"), "{hint}");
    assert!(hint.contains("not delivered before"), "{hint}");
    assert!(hint.contains("no action at all"), "{hint}");
    assert!(deliver_answer_with("orders", 2, 5).contains("5 message(s) you gave earlier"));
    assert!(requeue_answer_with(1).contains("attempts 2"));
}

/// Every example a model reads is a placeholder, not a plausible message.
#[test]
fn the_examples_are_placeholders() {
    for event in [
        &*NSQ_PUBLISH_EVENT,
        &*NSQ_SUBSCRIBE_EVENT,
        &*NSQ_READY_EVENT,
        &*NSQ_FINISH_EVENT,
        &*NSQ_REQUEUE_EVENT,
    ] {
        assert!(
            event.parameters.iter().any(|p| p.name == "answer_with"),
            "{} carries answer_with",
            event.id
        );
        let mut texts: Vec<String> = event
            .actions
            .iter()
            .map(|a| a.example.to_string())
            .collect();
        texts.push(event.effective_response_example().to_string());
        for text in texts {
            if text.contains("\"body\"") {
                assert!(text.contains("<message body>"), "{text}");
            }
            if text.contains("\"message\"") {
                assert!(text.contains("<why>"), "{text}");
            }
        }
    }
}
