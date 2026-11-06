//! Draining a status channel so that a flood is dropped and counted rather than queued.
//!
//! Every server and client reports to the operator through an unbounded `status_tx`, and what
//! goes onto it is paced by the network: a protocol logs per request, and an HTTP request with
//! many headers is one line per header. The channel stays unbounded on the sending side, because
//! a protocol task must never wait on the UI, so the bound is applied where it is drained:
//! whatever is queued is taken in one go, a fixed number of lines are kept, and the rest are
//! dropped and counted. The queue therefore never holds more than one drain interval of lines,
//! however fast they arrive. Nothing is lost for good: every line the channel carries is also
//! written to `netget.log` by the logging layer that sent it.

use tokio::sync::mpsc::UnboundedReceiver;

/// The control line asking the dashboard to rebuild its snapshot.
pub const UPDATE_UI: &str = "__UPDATE_UI__";

/// The most lines one drain takes off the channel, kept or dropped. A producer outrunning
/// `try_recv` could otherwise keep a drain going forever; whatever is left waits for the next.
const MAX_LINES_PER_DRAIN: usize = 200_000;

/// What one drain took off the channel.
#[derive(Debug, Default)]
pub struct StatusBatch {
    /// The lines kept, oldest first; control lines included.
    pub lines: Vec<String>,
    /// Lines taken and discarded because more than the cap were queued.
    pub dropped: usize,
    /// Whether an [`UPDATE_UI`] was among the dropped lines (it is never counted as dropped).
    pub update_ui_dropped: bool,
}

impl StatusBatch {
    /// The notice to show in place of the dropped lines, if any were dropped.
    pub fn dropped_notice(&self) -> Option<String> {
        (self.dropped > 0).then(|| {
            format!(
                "[WARN] {} status line(s) dropped: they arrived faster than they could be shown \
                 (netget.log has every one)",
                self.dropped
            )
        })
    }
}

/// Take everything queued on `rx` now, keeping at most `keep` lines (`first`, if given, counts
/// as one) and dropping the rest. Never waits.
pub fn drain_queued(
    rx: &mut UnboundedReceiver<String>,
    first: Option<String>,
    keep: usize,
) -> StatusBatch {
    let mut batch = StatusBatch::default();
    let mut taken = 0usize;
    let mut take = |line: String, batch: &mut StatusBatch| {
        if batch.lines.len() < keep {
            batch.lines.push(line);
        } else if line == UPDATE_UI {
            batch.update_ui_dropped = true;
        } else {
            batch.dropped += 1;
        }
    };
    if let Some(line) = first {
        take(line, &mut batch);
        taken += 1;
    }
    while taken < MAX_LINES_PER_DRAIN {
        match rx.try_recv() {
            Ok(line) => {
                take(line, &mut batch);
                taken += 1;
            }
            Err(_) => break,
        }
    }
    batch
}
