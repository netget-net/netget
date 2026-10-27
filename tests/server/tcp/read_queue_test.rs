//! `netget::server::read_queue::ReadQueue`, the state machine `tcp`, `tls`, `socket_file` and
//! `bitcoin` share, driven directly.
//!
//! The wire tests (`read_order_test.rs` in each of those protocols' suites) show replies leave in
//! order under load; these pin the individual decisions they rest on, each of which was once
//! made across two lock acquisitions in some server here. Each is one call, so with the
//! connection's lock held around it nothing can come in between.

use netget::server::read_queue::{Admitted, Held, ReadQueue, ReadState};

#[test]
fn the_first_read_starts_an_answer_and_later_ones_queue_behind_it() {
    let mut reads = ReadQueue::idle();
    assert_eq!(reads.admit(b"a", false), Admitted::Start(b"a".to_vec()));
    assert_eq!(reads.state(), ReadState::Processing);
    // A second read while the first is answered must queue, never start a second answer.
    assert_eq!(reads.admit(b"bb", false), Admitted::Queued(2));
    assert_eq!(reads.admit(b"ccc", false), Admitted::Queued(5));
    assert_eq!(reads.state(), ReadState::Processing);
}

#[test]
fn the_answer_takes_reads_oldest_first_and_goes_idle_only_on_an_empty_queue() {
    let mut reads = ReadQueue::idle();
    let _ = reads.admit(b"a", false);
    let _ = reads.admit(b"bb", false);
    let _ = reads.admit(b"ccc", false);
    // Batching off: one read per answer, in arrival order, and still Processing between them.
    assert_eq!(reads.next_or_idle(false), Some(b"bb".to_vec()));
    assert_eq!(reads.state(), ReadState::Processing);
    assert_eq!(reads.next_or_idle(false), Some(b"ccc".to_vec()));
    assert_eq!(reads.state(), ReadState::Processing);
    // Empty: Idle in the same call, so a read cannot be queued in between and stranded.
    assert_eq!(reads.next_or_idle(false), None);
    assert_eq!(reads.state(), ReadState::Idle);
    // And the next read starts an answer again.
    assert_eq!(reads.admit(b"d", false), Admitted::Start(b"d".to_vec()));
}

#[test]
fn batching_takes_everything_waiting_as_one_payload() {
    let mut reads = ReadQueue::idle();
    let _ = reads.admit(b"a", true);
    let _ = reads.admit(b"bb", true);
    let _ = reads.admit(b"ccc", true);
    assert_eq!(reads.next_or_idle(true), Some(b"bbccc".to_vec()));
    assert_eq!(reads.next_or_idle(true), None);
    assert_eq!(reads.state(), ReadState::Idle);
}

#[test]
fn a_connect_event_holds_reads_until_its_handler_takes_them() {
    let mut reads = ReadQueue::answering();
    assert_eq!(reads.admit(b"early", false), Admitted::Queued(5));
    assert_eq!(reads.next_or_idle(false), Some(b"early".to_vec()));
    assert_eq!(reads.next_or_idle(false), None);
    assert_eq!(reads.state(), ReadState::Idle);
}

#[test]
fn wait_for_more_with_nothing_queued_parks_the_fragment_for_the_next_read() {
    let mut reads = ReadQueue::idle();
    let _ = reads.admit(b"GET /", false);
    assert_eq!(reads.hold_for_more(b"GET /"), Held::Waiting(5));
    assert_eq!(reads.state(), ReadState::Accumulating);
    // The held fragment and the read that completes it are one payload, even with batching
    // off: they are one message.
    assert_eq!(
        reads.admit(b" HTTP/1.0\r\n", false),
        Admitted::Start(b"GET / HTTP/1.0\r\n".to_vec())
    );
}

#[test]
fn wait_for_more_with_bytes_already_queued_resumes_without_leaving_processing() {
    let mut reads = ReadQueue::idle();
    let _ = reads.admit(b"GET /", false);
    // These arrived while the model was deciding the fragment was incomplete.
    let _ = reads.admit(b" HTTP/1.0", false);
    let _ = reads.admit(b"\r\n", false);
    assert_eq!(
        reads.hold_for_more(b"GET /"),
        Held::Resume(b"GET / HTTP/1.0\r\n".to_vec())
    );
    // Still Processing: a read now must queue, not start a second answer alongside the one
    // going round again with the joined payload.
    assert_eq!(reads.state(), ReadState::Processing);
    assert_eq!(reads.admit(b"next", false), Admitted::Queued(4));
}
