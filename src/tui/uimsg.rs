//! Results of work that must not run on the event loop.
//!
//! Creating a server, connecting a client and sending through one all perform
//! network I/O. Awaiting them inline in the key handler blocks the whole UI —
//! a connect to a blackholed address parks the dashboard for the kernel's full
//! SYN-retry window, which reads as a freeze. So those actions are spawned and
//! report back through this channel, which the event loop selects on alongside
//! input and ticks.

/// The identity of one spawned action, so its result reaches the modal that
/// started it and no other.
///
/// A form or routing editor that submits takes a fresh ticket and holds it
/// while the work is in flight; the result carries the same ticket back, and
/// [`crate::tui::keymap::handle_ui_msg`] routes it to the modal holding it,
/// wherever that modal sits in the stack. An action started with no modal —
/// `c` connecting a client, a protocol picked and started on defaults — holds
/// a ticket no modal has, and so does one whose modal was closed meanwhile:
/// those results go to the stream, never into whatever form is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionTicket(u64);

impl ActionTicket {
    /// A ticket no other action in this process has been given.
    pub fn next() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug)]
pub enum UiMsg {
    /// A page API needs input before creating an instance. Show the same form as the
    /// dashboard button, so credentials can be supplied with the normal field editor.
    OpenForm(Box<crate::tui::modal::form::FormModel>),
    /// A spawned action finished. On success the modal holding `ticket`
    /// closes and the summary goes to the stream; on failure that modal stays
    /// open and shows the error. With no modal holding it, both go to the
    /// stream.
    ActionDone {
        ticket: ActionTicket,
        result: Result<String, String>,
    },
    /// Text from background work that is purely informational — it goes to
    /// chat and must never close whatever modal happens to be open.
    Chat(String),
}
