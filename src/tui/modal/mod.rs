//! Overlay modals: the dashboard's drill-in and editing surfaces.
//!
//! Modals form a stack (`DashboardApp::modals`) so nesting — server → routing
//! → handler → script editor — unwinds naturally with Esc. The topmost modal
//! owns all input while it is open.

pub mod composer;
pub mod confirm;
pub mod form;
pub mod help;
pub mod intercept;
pub mod protocol_picker;
pub mod request_detail;
pub mod routing;
pub mod text_editor;

use crate::state::app_state::{AccessLogEntry, WebApprovalResponse};
use crate::tui::app::{Section, UiKey};

use composer::ComposerModel;
use form::{FieldTarget, FormModel};
use protocol_picker::ProtocolEntry;
use text_editor::TextEditorModel;

/// A modal's preferred size: percentages of the screen, each capped by what
/// the content needs so a short modal stays short on a big terminal.
#[derive(Debug, Clone, Copy)]
pub struct ModalSize {
    pub percent_x: u16,
    pub percent_y: u16,
    pub max_cols: u16,
    pub max_rows: u16,
}

impl ModalSize {
    pub fn new(percent_x: u16, percent_y: u16, max_cols: u16, max_rows: u16) -> Self {
        Self {
            percent_x,
            percent_y,
            max_cols,
            max_rows,
        }
    }
}

/// Rows the handler editor's body needs for the kind being edited.
fn draft_rows(model: &routing::RoutingModel, draft: &routing::HandlerDraft) -> u16 {
    use routing::{DraftFocus, HandlerKind};
    // Kind control + its blurb (2 rows) + the pattern row + a blank.
    let mut rows = 5u16;
    // The pattern chooser lists the protocol's events while it has focus.
    if draft.focus == DraftFocus::Pattern && draft.editing.is_none() {
        rows += (model.event_ids.len() as u16 + 1).min(12);
    }
    rows += match draft.kind {
        HandlerKind::Static => 1 + draft.actions.len() as u16,
        HandlerKind::Script => 3 + draft.code.lines().count().min(6) as u16,
        HandlerKind::Llm => 1,
        // The timeout row plus its two-line explanation.
        HandlerKind::Manual => 3,
    };
    if draft.error.is_some() {
        rows += 2;
    }
    rows
}

/// An action deferred behind a confirmation. Closure-free so `Modal` stays a
/// plain data enum that can be inspected and tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingAction {
    StopServer(crate::state::ServerId),
    StopClient(crate::state::ClientId),
    StopAll,
    Quit,
}

pub enum Modal {
    /// Keybinding reference.
    Help { scroll: u16 },
    /// Full request/response JSON for one access-log entry.
    RequestDetail {
        entry: Box<AccessLogEntry>,
        scroll: u16,
    },
    /// Yes/no confirmation carrying the action to run on confirm.
    Confirm {
        message: String,
        action: PendingAction,
    },
    /// Web-search approval (ASK mode), answering the oneshot the LLM waits on.
    WebApproval {
        url: String,
        response_tx: tokio::sync::oneshot::Sender<WebApprovalResponse>,
    },
    /// Read-only detail of a band's full config.
    BandDetail { key: UiKey, scroll: u16 },
    /// The Wireshark / tshark command and filters that capture one instance's
    /// traffic — reachable from a running instance's row and from the
    /// create/edit form, so the capture can start before the instance does.
    Wireshark {
        plan: Box<crate::tui::wireshark::CapturePlan>,
        scroll: u16,
    },
    /// Choose a protocol — and with it the kind — for a new instance.
    ProtocolPicker {
        entries: Vec<ProtocolEntry>,
        filter: String,
        selected: usize,
        /// When set, the created client is aimed at this address (the
        /// `[+ client]` affordance on a running server).
        prefill_remote: Option<String>,
    },
    /// Create/edit form for an instance.
    Form(Box<FormModel>),
    /// Multi-line editor for one form field.
    TextEditor {
        editor: Box<TextEditorModel>,
        target: FieldTarget,
    },
    /// Compose and send an action through a running client.
    Composer(Box<ComposerModel>),
    /// Edit the instance's handler table (static / script / LLM / manual).
    Routing(Box<routing::RoutingModel>),
    /// Answer a request a `manual` rule parked for you.
    Intercept(Box<intercept::InterceptModel>),
}

impl Modal {
    /// Title shown in the modal's border.
    pub fn title(&self) -> String {
        match self {
            Modal::Help { .. } => "Keys".to_string(),
            Modal::RequestDetail { entry, .. } => format!("Request #{}", entry.id),
            Modal::Confirm { .. } => "Confirm".to_string(),
            Modal::WebApproval { .. } => "Web search approval".to_string(),
            Modal::BandDetail { key, .. } => match key {
                UiKey::Server(id) => format!("Server #{}", id.as_u32()),
                UiKey::Client(id) => format!("Client #{}", id.as_u32()),
            },
            Modal::Wireshark { plan, .. } => {
                format!("View in Wireshark — {}", plan.target.protocol)
            }
            Modal::ProtocolPicker { .. } => "New server or client — pick a protocol".to_string(),
            Modal::Form(form) => match &form.mode {
                form::FormMode::Create(Section::Servers) => {
                    format!("New {} server", form.protocol)
                }
                form::FormMode::Create(Section::Clients) => {
                    format!("New {} client", form.protocol)
                }
                form::FormMode::Edit(UiKey::Server(id)) => {
                    format!("Edit server #{}", id.as_u32())
                }
                form::FormMode::Edit(UiKey::Client(id)) => {
                    format!("Edit client #{}", id.as_u32())
                }
            },
            Modal::TextEditor { editor, .. } => format!("Edit {}", editor.label),
            Modal::Composer(composer) => match composer.target {
                composer::ComposerTarget::Client(id) => {
                    format!("Send a request — client #{}", id.as_u32())
                }
                composer::ComposerTarget::Peer { server, connection } => format!(
                    "Message peer — connection #{connection} of server #{}",
                    server.as_u32()
                ),
                composer::ComposerTarget::Intercept { id, .. } => {
                    format!("Answer request #{id} — pick what to send")
                }
            },
            Modal::Routing(model) => match model.key {
                UiKey::Server(id) => format!("Routing — server #{}", id.as_u32()),
                UiKey::Client(id) => format!("Auto-reply rules — client #{}", id.as_u32()),
            },
            Modal::Intercept(model) => match model.owner {
                UiKey::Server(id) => {
                    format!("Answer this request — server #{}", id.as_u32())
                }
                UiKey::Client(id) => {
                    format!("Answer this reply — client #{}", id.as_u32())
                }
            },
        }
    }

    /// Footer hint line for the modal.
    pub fn hint(&self) -> &'static str {
        match self {
            Modal::Help { .. } => "↑/↓ scroll · Esc close",
            Modal::RequestDetail { .. } | Modal::BandDetail { .. } => "↑/↓ scroll · Esc close",
            Modal::Wireshark { .. } => "Ctrl-T frees the mouse to copy · ↑/↓ scroll · Esc close",
            Modal::Confirm { .. } => "y confirm · n/Esc cancel",
            Modal::WebApproval { .. } => "y allow once · a always · n/Esc deny",
            Modal::ProtocolPicker { .. } => {
                "type to filter · ↑/↓ select · Enter choose · Esc cancel"
            }
            Modal::Form(form) => {
                if form.busy() {
                    "working… (network call in flight)"
                } else if form.editing.is_some() {
                    "type to edit · Enter accept · Esc cancel field"
                } else {
                    "↑/↓ field · Enter edit · Tab → buttons · Esc cancel"
                }
            }
            Modal::TextEditor { editor, .. } => {
                if editor.focused_button.is_some() {
                    "Tab next button · Enter press · type to go back to the text"
                } else {
                    "Tab → buttons · Esc cancel"
                }
            }
            Modal::Composer(composer) => {
                if composer.busy {
                    "sending…"
                } else if composer.editing.is_some() {
                    "type to edit · Enter accept · Esc cancel field"
                } else if composer.chosen.is_some() {
                    "↑/↓ field · Enter edit · Tab → buttons · Esc back"
                } else {
                    "↑/↓ action · Enter choose · Esc cancel"
                }
            }
            Modal::Routing(model) => {
                if model.busy() {
                    "applying…"
                } else if model.draft.is_some() {
                    "Tab next · ←/→ change a choice · Enter act · Esc back"
                } else {
                    "Tab moves through everything · Enter act · Esc close"
                }
            }
            Modal::Intercept(_) => "↑/↓ scroll · Tab buttons · Enter act · Esc keeps it waiting",
        }
    }

    /// How big this modal wants to be.
    ///
    /// Everything used to be 85% x 85%, so a two-line confirmation and a
    /// four-field form both opened as a near-fullscreen box of whitespace.
    /// Each modal now caps itself at what its content actually needs; the
    /// percentages only bound it on a small terminal.
    pub fn size(&self) -> ModalSize {
        // Border top + bottom, plus the button row where there is one.
        const CHROME: u16 = 4;
        // Scrolling modals want the screen; content-sized ones do not.
        const TALL: u16 = 500;

        match self {
            Modal::Confirm { .. } => ModalSize::new(50, 40, 72, 5),
            Modal::WebApproval { .. } => ModalSize::new(60, 40, 88, 8),
            Modal::Help { .. } => ModalSize::new(72, 88, 92, TALL),
            Modal::RequestDetail { .. } | Modal::BandDetail { .. } => {
                ModalSize::new(80, 85, 140, TALL)
            }
            // A copyable command line plus its explanation: wide, and tall
            // enough to scroll rather than sized to the content.
            Modal::Wireshark { .. } => ModalSize::new(80, 75, 132, TALL),
            Modal::ProtocolPicker { .. } => ModalSize::new(78, 80, 128, TALL),
            Modal::TextEditor { .. } => ModalSize::new(76, 70, 120, TALL),
            Modal::Form(form) => {
                // One row per field, the help under the selected one (which
                // wraps), and the error above the buttons. A box too short for
                // all of it scrolls to the selected field and keeps the error.
                let error = if form.error.is_some() { 3 } else { 0 };
                let rows = form.fields.len() as u16 + 3 + error;
                ModalSize::new(70, 70, 104, rows + CHROME)
            }
            Modal::Composer(composer) => {
                let rows = match composer.chosen {
                    // Parameter form: a row per field, the help line under the
                    // selected one (which can wrap to three), the heading (which
                    // wraps too for long descriptions), or the raw JSON text.
                    Some(_) => match &composer.raw_json {
                        Some(raw) => raw.lines().count() as u16 + 5,
                        None => composer.fields.len() as u16 + 9,
                    },
                    // Action list: one row each, plus the heading.
                    None => composer.actions.len() as u16 + 3,
                };
                // The validation line ("'code' is required") lives below the
                // fields; without room for it the popup clipped it and a send
                // with an empty required field looked like nothing happened.
                let error = if composer.error.is_some() { 2 } else { 0 };
                ModalSize::new(70, 75, 112, rows + error + CHROME)
            }
            Modal::Intercept(model) => {
                let payload = model
                    .event_data
                    .as_ref()
                    .map(|data| {
                        serde_json::to_string_pretty(data)
                            .map(|text| text.lines().count() as u16)
                            .unwrap_or(1)
                            + 1
                    })
                    .unwrap_or(0);
                // 90% wide: at 80 columns 72% was 57 cells, and the three
                // buttons need 59, so `[ Fail closed ]` was never drawn while
                // Tab still moved the focus onto it. The deadline and error
                // rows add two. A payload taller than the screen scrolls.
                let extra =
                    u16::from(model.deadline_unix_ms.is_some()) + u16::from(model.error.is_some());
                ModalSize::new(90, 85, 120, payload + 7 + extra + CHROME)
            }
            Modal::Routing(model) => {
                let rows = match &model.draft {
                    Some(draft) => draft_rows(model, draft),
                    // Heading, a row per rule, the fallback note.
                    None => model.handlers.len().max(1) as u16 + 5,
                };
                ModalSize::new(74, 80, 124, rows + CHROME)
            }
        }
    }

    /// The scroll of a modal read by scrolling, `None` for one whose body
    /// follows its focus instead.
    fn scroll_slot(&mut self) -> Option<&mut u16> {
        match self {
            Modal::Help { scroll }
            | Modal::RequestDetail { scroll, .. }
            | Modal::BandDetail { scroll, .. }
            | Modal::Wireshark { scroll, .. } => Some(scroll),
            Modal::Intercept(model) => Some(&mut model.scroll),
            _ => None,
        }
    }

    pub fn scroll_by(&mut self, delta: i16) {
        let Some(slot) = self.scroll_slot() else {
            return;
        };
        *slot = if delta < 0 {
            slot.saturating_sub(delta.unsigned_abs())
        } else {
            slot.saturating_add(delta as u16)
        };
    }

    /// Store the scroll the renderer actually used, which is clamped to the
    /// body: scrolling past the last row and back up then moves at once
    /// instead of first unwinding rows that were never shown.
    pub fn settle_scroll(&mut self, used: u16) {
        if let Some(slot) = self.scroll_slot() {
            *slot = used;
        }
    }

    /// The row a scrolled modal's view starts on; 0 for a modal whose body
    /// follows its focus.
    pub fn scroll(&self) -> u16 {
        match self {
            Modal::Help { scroll }
            | Modal::RequestDetail { scroll, .. }
            | Modal::BandDetail { scroll, .. }
            | Modal::Wireshark { scroll, .. } => *scroll,
            Modal::Intercept(model) => model.scroll,
            _ => 0,
        }
    }
}
