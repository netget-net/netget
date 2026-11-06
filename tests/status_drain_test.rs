//! A status flood is dropped and counted where the channel is drained, never left queued.
//!
//! Every server reports through an unbounded `status_tx`, at a rate the network sets (an HTTP
//! request logs a line per header). A drain that takes at most 500 lines per frame and leaves
//! the rest queued lets a peer sending faster than ~5 000 lines a second grow the queue for as
//! long as it keeps sending. `logging::status_drain::drain_queued` takes everything queued,
//! keeps a fixed number and counts the rest.

use netget::logging::status_drain::{drain_queued, UPDATE_UI};

#[tokio::test]
async fn a_flood_is_taken_off_the_channel_in_one_drain_and_counted() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    for n in 0..10_000 {
        tx.send(format!("[INFO] line {n}")).unwrap();
    }

    let batch = drain_queued(&mut rx, None, 500);

    assert_eq!(batch.lines.len(), 500);
    assert_eq!(
        batch.lines[0], "[INFO] line 0",
        "the oldest lines are the ones kept"
    );
    assert_eq!(batch.dropped, 9_500);
    assert!(
        rx.try_recv().is_err(),
        "nothing may be left queued: what is not shown is dropped, not deferred"
    );
    let notice = batch.dropped_notice().expect("a drop is announced");
    assert!(notice.starts_with("[WARN] 9500 status line(s) dropped"));
}

#[tokio::test]
async fn a_dropped_update_request_still_reaches_the_dashboard() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    for n in 0..10 {
        tx.send(format!("[INFO] line {n}")).unwrap();
    }
    tx.send(UPDATE_UI.to_string()).unwrap();

    let batch = drain_queued(&mut rx, None, 5);
    assert!(batch.update_ui_dropped);
    assert_eq!(
        batch.dropped, 5,
        "a control line is not counted as a dropped line"
    );
}

#[tokio::test]
async fn a_quiet_channel_drops_nothing() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tx.send("[INFO] one".to_string()).unwrap();

    let batch = drain_queued(&mut rx, Some("[INFO] first".to_string()), 500);
    assert_eq!(batch.lines, vec!["[INFO] first", "[INFO] one"]);
    assert_eq!(batch.dropped, 0);
    assert!(batch.dropped_notice().is_none());
}
