//! Answering a request yourself.
//!
//! A `manual` routing rule parks each matched event as a pending question
//! (`crate::state::intercepts`); this modal is where the human answers it. It
//! shows what arrived and offers exactly three things to do:
//!
//! - **Compose answer…** opens the same composer the `[ send ]` rows use —
//!   pick one of the event's own answers from a list, fill its parameters as
//!   fields (booleans toggle), and send. Raw JSON is one button away for the
//!   rare shape the fields cannot express, never the starting point.
//! - **Answer with nothing** delivers zero actions: acknowledge, say nothing.
//!   That is a real answer — the same as an empty static handler, and what a
//!   lifecycle event like connection-opened usually deserves — so it is
//!   delivered (Ok) and distinct from a timeout (Err).
//! - **Fail closed** refuses: the waiting dispatcher errors immediately and
//!   the peer gets the protocol's category error, exactly as if the model had
//!   failed. Refusing is honest; inventing nothing is the fail-closed rule.

use crate::llm::actions::ActionDefinition;
use crate::tui::app::UiKey;
use crate::tui::hit::ModalAction;

#[derive(Debug, Clone)]
pub struct InterceptModel {
    /// The pending intercept being answered.
    pub id: u64,
    pub owner: UiKey,
    pub protocol: String,
    pub event_type: String,
    pub description: String,
    pub event_data: Option<serde_json::Value>,
    /// The actions this event may be answered with — what the composer offers
    /// (`crate::state::intercepts::server_answer_actions` / `client_answer_actions`).
    pub vocabulary: Vec<ActionDefinition>,
    /// Unix ms at which the waiting dispatcher fails the event closed if
    /// nobody answers (`InterceptView::created_unix_ms` + `timeout_secs`).
    pub deadline_unix_ms: Option<u64>,
    pub error: Option<String>,
    /// Index into [`Self::buttons`].
    pub focused: usize,
    /// First row of the scrolled body in view (↑/↓, PageUp/PageDown, the
    /// wheel); the renderer clamps it to the body.
    pub scroll: u16,
}

impl InterceptModel {
    pub fn buttons(&self) -> Vec<ModalAction> {
        vec![
            ModalAction::InterceptCompose,
            ModalAction::InterceptSend,
            ModalAction::InterceptDismiss,
        ]
    }

    pub fn focused_action(&self) -> Option<ModalAction> {
        self.buttons().get(self.focused).copied()
    }

    pub fn cycle_focus(&mut self, backward: bool) {
        let total = self.buttons().len();
        self.focused = if backward {
            (self.focused + total - 1) % total
        } else {
            (self.focused + 1) % total
        };
    }
}
