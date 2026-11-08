//! Keyboard and mouse handling for the panes.
//!
//! Precedence: an open modal owns everything (`modal_keys`); then the global
//! toggles; then the focused column. In the management column the arrows do
//! all the moving — ↑/↓ over rows, ←/→ along a row's buttons — and Enter acts
//! on whatever the cursor is on. Everything funnels into `actions::run` with
//! an `InstanceAction`, so a letter, a button and a click do the same thing.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use tokio::sync::mpsc;

use crate::events::EventHandler;
use crate::state::app_state::AppState;
use crate::tui::actions;
use crate::tui::app::{DashboardApp, Focus, UiKey};
use crate::tui::cards::{Activate, InstanceAction, Row};
use crate::tui::hit::{HitTarget, SegmentId};
use crate::tui::modal::Modal;
use crate::tui::uimsg::UiMsg;

/// What the event loop should do after handling an event.
pub enum Outcome {
    Continue,
    Quit,
}

pub async fn handle_key(
    app: &mut DashboardApp,
    key: KeyEvent,
    state: &AppState,
    event_handler: &EventHandler,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Outcome {
    app.dirty = true;

    if app.modal().is_some() {
        return crate::tui::modal_keys::handle_modal_key(app, key, state).await;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    // Readline chords on text being typed come before the global toggles:
    // Ctrl-E and Ctrl-W mean "end of line" and "delete word" to anyone with
    // a line in the box, and only cycle scripting / web search once it is
    // empty.
    if app.focus == Focus::ChatInput && !app.input.text().is_empty() && readline_key(app, key) {
        let text = app.input.text();
        app.core.update_slash_suggestions(&text);
        return Outcome::Continue;
    }

    match key.code {
        KeyCode::Char('c') | KeyCode::Char('C') if ctrl => return Outcome::Quit,
        KeyCode::Char('l') | KeyCode::Char('L') if ctrl => {
            let level = app.core.log_level.cycle();
            app.core.set_log_level(level);
            app.push_system(format!("Log level: {}", level.as_str()));
            return Outcome::Continue;
        }
        KeyCode::Char('w') | KeyCode::Char('W') if ctrl => {
            let mode = state.cycle_web_search_mode().await;
            app.status.web_search = format!("{mode:?}").to_uppercase();
            app.push_system(format!("Web search: {mode:?}"));
            return Outcome::Continue;
        }
        KeyCode::Char('h') | KeyCode::Char('H') if ctrl => {
            let mode = state.cycle_event_handler_mode().await;
            app.status.handler_mode = format!("{mode:?}").to_uppercase();
            app.push_system(format!("Handler mode: {mode:?}"));
            return Outcome::Continue;
        }
        KeyCode::Char('e') | KeyCode::Char('E') if ctrl => {
            let (mode, switched) = state.cycle_scripting_mode().await;
            if switched {
                app.status.scripting = mode.as_str().to_string();
                app.push_system(format!("Scripting: {}", mode.as_str()));
            }
            return Outcome::Continue;
        }
        KeyCode::Char('t') | KeyCode::Char('T') if ctrl => {
            app.mouse_capture = !app.mouse_capture;
            app.push_system(if app.mouse_capture {
                "Mouse capture ON"
            } else {
                "Mouse capture OFF — native text selection works; Ctrl-T to re-enable"
            });
            return Outcome::Continue;
        }
        KeyCode::F(1) => {
            app.modals.push(Modal::Help { scroll: 0 });
            return Outcome::Continue;
        }
        KeyCode::Tab if !alt => {
            cycle_focus(app);
            return Outcome::Continue;
        }
        KeyCode::BackTab => {
            cycle_focus(app);
            return Outcome::Continue;
        }
        _ => {}
    }

    match app.focus {
        Focus::ChatInput => handle_chat_key(app, key, state, event_handler, status_tx).await,
        Focus::Cards => handle_cards_key(app, key, state).await,
        Focus::Stream => handle_stream_key(app, key, state).await,
    }
}

/// Two stops: the management column and the chat box.
fn cycle_focus(app: &mut DashboardApp) {
    app.focus = match app.focus {
        Focus::Cards => Focus::ChatInput,
        Focus::Stream | Focus::ChatInput => Focus::Cards,
    };
    app.activity.cursor = None;
    let rows = app.rows();
    app.clamp_cursor_to(&rows);
}

async fn handle_chat_key(
    app: &mut DashboardApp,
    key: KeyEvent,
    state: &AppState,
    event_handler: &EventHandler,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Outcome {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    match key.code {
        KeyCode::Enter if ctrl || alt => {
            app.input.insert_newline();
        }
        KeyCode::Char('n') | KeyCode::Char('N') if ctrl || alt => {
            app.input.insert_newline();
        }
        KeyCode::Enter => {
            let text = app.input.text();
            app.input.clear();
            app.core.slash_suggestions.clear();
            crate::tui::commands::submit(app, text, state, event_handler, status_tx).await;
        }
        KeyCode::PageUp => {
            app.focus = Focus::Stream;
            app.activity.scroll_up(10);
        }
        KeyCode::Up if app.input.is_on_first_line() => history_previous(app),
        KeyCode::Down if app.input.is_on_last_line() => history_next(app),
        KeyCode::Esc => {
            app.input.clear();
            app.core.slash_suggestions.clear();
        }
        _ => {
            if !readline_key(app, key) {
                app.input.handle_key(key.code, key.modifiers);
            }
        }
    }
    let text = app.input.text();
    app.core.update_slash_suggestions(&text);
    Outcome::Continue
}

/// The readline chords the legacy TUI's footer had. Returns whether `key`
/// was one.
fn readline_key(app: &mut DashboardApp, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('a') | KeyCode::Char('A') if ctrl => app.input.move_to_start_of_line(),
        KeyCode::Char('e') | KeyCode::Char('E') if ctrl => app.input.move_to_end_of_line(),
        KeyCode::Char('k') | KeyCode::Char('K') if ctrl => app.input.delete_to_end_of_line(),
        KeyCode::Char('u') | KeyCode::Char('U') if ctrl => app.input.delete_line(),
        KeyCode::Char('w') | KeyCode::Char('W') if ctrl => app.input.delete_word(),
        KeyCode::Backspace if alt => app.input.delete_word(),
        KeyCode::Delete if alt => app.input.delete_word_forward(),
        KeyCode::Left if alt => app.input.move_cursor_word_left(),
        KeyCode::Right if alt => app.input.move_cursor_word_right(),
        KeyCode::Char('b') if alt => app.input.move_cursor_word_left(),
        KeyCode::Char('f') if alt => app.input.move_cursor_word_right(),
        KeyCode::Char('d') if alt => app.input.delete_word_forward(),
        _ => return false,
    }
    true
}

/// Command-history navigation, mirroring the legacy TUI: entering history
/// stashes the in-progress input, leaving it restores it.
fn history_previous(app: &mut DashboardApp) {
    use crate::cli::input_state::InputState;
    if app.core.command_history.is_empty() {
        return;
    }
    match app.core.history_position {
        None => {
            let current = app.input.text();
            if !current.is_empty() {
                app.core.history_temp_input = Some(current);
            }
            let pos = app.core.command_history.len() - 1;
            app.core.history_position = Some(pos);
            app.input = InputState::from_lines(
                app.core.command_history[pos]
                    .lines()
                    .map(|s| s.to_string())
                    .collect(),
            );
            app.input.move_to_bottom();
            app.input.move_to_end_of_line();
        }
        Some(pos) if pos > 0 => {
            let new_pos = pos - 1;
            app.core.history_position = Some(new_pos);
            app.input = InputState::from_lines(
                app.core.command_history[new_pos]
                    .lines()
                    .map(|s| s.to_string())
                    .collect(),
            );
            app.input.move_to_bottom();
            app.input.move_to_end_of_line();
        }
        _ => {}
    }
}

fn history_next(app: &mut DashboardApp) {
    use crate::cli::input_state::InputState;
    match app.core.history_position {
        Some(pos) if pos + 1 < app.core.command_history.len() => {
            let new_pos = pos + 1;
            app.core.history_position = Some(new_pos);
            app.input = InputState::from_lines(
                app.core.command_history[new_pos]
                    .lines()
                    .map(|s| s.to_string())
                    .collect(),
            );
            app.input.move_to_bottom();
            app.input.move_to_end_of_line();
        }
        Some(_) => {
            app.core.history_position = None;
            let temp = app.core.history_temp_input.take().unwrap_or_default();
            app.input = InputState::from_lines(temp.lines().map(|s| s.to_string()).collect());
            app.input.move_to_bottom();
            app.input.move_to_end_of_line();
        }
        None => {}
    }
}

/// Move the cursor by `delta` stop rows (rows with something to land on).
fn move_cursor(app: &mut DashboardApp, rows: &[Row], delta: isize) {
    let stops: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.positions() > 0)
        .map(|(i, _)| i)
        .collect();
    if stops.is_empty() {
        return;
    }
    let current = stops
        .iter()
        .position(|s| *s == app.cards.row)
        .unwrap_or_else(|| {
            stops
                .partition_point(|s| *s < app.cards.row)
                .min(stops.len() - 1)
        });
    let next = (current as isize + delta).clamp(0, stops.len() as isize - 1) as usize;
    app.cards.row = stops[next];
    // Keep the column where it can: a button grid walks vertically.
    let positions = rows[app.cards.row].positions();
    if app.cards.col >= positions {
        app.cards.col = positions.saturating_sub(1);
    }
}

/// Letters that act on the card under the cursor.
async fn instance_letter(app: &mut DashboardApp, code: KeyCode, state: &AppState) -> bool {
    if matches!(code, KeyCode::Char('a') | KeyCode::Char('A')) {
        actions::open_protocol_picker(app, None, state).await;
        return true;
    }
    let Some(key) = app.cursor_key() else {
        return false;
    };
    let action = match (code, key) {
        (KeyCode::Char('x'), _) => InstanceAction::Stop,
        (KeyCode::Char('e'), _) => InstanceAction::Edit,
        (KeyCode::Char('r'), _) => InstanceAction::Rules,
        (KeyCode::Char('m'), _) => InstanceAction::CycleDriver,
        (KeyCode::Char('w'), _) => InstanceAction::Wireshark,
        (KeyCode::Char('d'), _) => InstanceAction::Docs,
        (KeyCode::Char('c'), UiKey::Server(_)) => InstanceAction::ConnectClient,
        (KeyCode::Char('n'), UiKey::Client(_)) => InstanceAction::Send,
        _ => return false,
    };
    actions::run(app, key, action, state).await;
    true
}

/// Enter on the cursor: press the button, or act on the label.
async fn activate(app: &mut DashboardApp, rows: &[Row], state: &AppState) {
    let Some(row) = rows.get(app.cards.row) else {
        return;
    };
    if let Some(button) = row.button_at(app.cards.col) {
        let button = button.clone();
        let Some(key) = row.key else {
            return;
        };
        if button.enabled {
            actions::run(app, key, button.action, state).await;
        } else {
            app.push_system(format!(
                "[ {} ]: {}",
                button.label,
                button.why_disabled.unwrap_or_default()
            ));
        }
        return;
    }
    match row.on_enter.clone() {
        Activate::None => {}
        Activate::Toggle(node) => app.cards.state.toggle(&node),
        Activate::ShowAll(node) => app.cards.state.show_all(&node),
        Activate::Action(action) => {
            if let Some(key) = row.key {
                actions::run(app, key, action, state).await;
            }
        }
        Activate::NewInstance => actions::open_protocol_picker(app, None, state).await,
    }
}

async fn handle_cards_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    let rows = app.rows();
    app.clamp_cursor_to(&rows);
    match key.code {
        KeyCode::Down => move_cursor(app, &rows, 1),
        KeyCode::Up => move_cursor(app, &rows, -1),
        KeyCode::PageDown => move_cursor(app, &rows, 10),
        KeyCode::PageUp => move_cursor(app, &rows, -10),
        KeyCode::Home => move_cursor(app, &rows, isize::MIN / 2),
        KeyCode::End => move_cursor(app, &rows, isize::MAX / 2),
        KeyCode::Right => {
            let positions = rows.get(app.cards.row).map(|r| r.positions()).unwrap_or(0);
            if app.cards.col + 1 < positions {
                app.cards.col += 1;
            } else if let Some(row) = rows.get(app.cards.row) {
                // → on a folded row unfolds it, like a tree.
                if row.expanded == Some(false) {
                    if let Activate::Toggle(node) = &row.on_enter {
                        app.cards.state.open(node);
                    }
                }
            }
        }
        KeyCode::Left => {
            if app.cards.col > 0 {
                app.cards.col -= 1;
            } else if let Some(row) = rows.get(app.cards.row) {
                // ← on an open row folds it; on a leaf, steps out to the
                // row above it that is shallower.
                if row.expanded == Some(true) {
                    if let Activate::Toggle(node) = &row.on_enter {
                        app.cards.state.close(node);
                    }
                } else if row.depth > 0 {
                    if let Some(parent) = rows[..app.cards.row]
                        .iter()
                        .rposition(|r| r.depth < row.depth && r.positions() > 0)
                    {
                        app.cards.row = parent;
                        app.cards.col = 0;
                    }
                }
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => activate(app, &rows, state).await,
        KeyCode::Esc => {
            app.focus = Focus::ChatInput;
        }
        code => {
            instance_letter(app, code, state).await;
        }
    }
    let rows = app.rows();
    app.clamp_cursor_to(&rows);
    Outcome::Continue
}

async fn handle_stream_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    let sequences: Vec<u64> = crate::tui::render::stream::visible_entries(app)
        .iter()
        .map(|entry| entry.seq)
        .collect();
    let visible = sequences.len();
    let current = app
        .activity
        .cursor
        .and_then(|seq| sequences.iter().position(|&entry| entry >= seq));
    match key.code {
        KeyCode::Esc | KeyCode::End => {
            app.activity.scroll_to_follow();
            app.focus = Focus::ChatInput;
        }
        KeyCode::Up => {
            let cursor = match current {
                None => visible.checked_sub(1),
                Some(c) => Some(c.saturating_sub(1)),
            };
            app.activity.cursor = cursor.and_then(|index| sequences.get(index).copied());
            if cursor.is_some() && app.activity.scroll == crate::tui::chat::ScrollPos::Follow {
                app.activity.scroll_up(0);
            }
        }
        // ↓ past the newest line walks on into the chat box.
        KeyCode::Down => match current {
            Some(c) if c + 1 < visible => app.activity.cursor = sequences.get(c + 1).copied(),
            _ => {
                app.activity.scroll_to_follow();
                app.focus = Focus::ChatInput;
            }
        },
        KeyCode::PageUp => {
            let cursor = current.unwrap_or(visible).saturating_sub(10);
            app.activity.cursor = sequences.get(cursor).copied();
            if app.activity.scroll == crate::tui::chat::ScrollPos::Follow {
                app.activity.scroll_up(0);
            }
        }
        KeyCode::PageDown => {
            if let Some(c) = current {
                if c + 10 < visible {
                    app.activity.cursor = sequences.get(c + 10).copied();
                } else {
                    app.activity.scroll_to_follow();
                    app.focus = Focus::ChatInput;
                }
            }
        }
        KeyCode::Home => {
            if visible > 0 {
                app.activity.cursor = sequences.first().copied();
                app.activity.scroll_up(0);
            }
        }
        KeyCode::Char('f') => {
            app.activity.only_selected = !app.activity.only_selected;
            app.activity.cursor = None;
        }
        KeyCode::Enter => {
            if let Some(cursor) = app.activity.cursor {
                let link = crate::tui::render::stream::visible_entries(app)
                    .into_iter()
                    .find(|entry| entry.seq == cursor)
                    .and_then(|e| e.event.link);
                follow_link(app, link, state).await;
            }
        }
        _ => {}
    }
    Outcome::Continue
}

async fn follow_link(
    app: &mut DashboardApp,
    link: Option<crate::tui::activity::Link>,
    state: &AppState,
) {
    use crate::tui::activity::Link;
    match link {
        Some(Link::Request(key, id)) => {
            actions::run(app, key, InstanceAction::OpenRequest(id), state).await;
        }
        Some(Link::Intercept(key, id)) => {
            actions::run(app, key, InstanceAction::Answer(id), state).await;
        }
        Some(Link::Instance(key)) => {
            if app.instance(key).is_some() {
                app.focus = Focus::Cards;
                app.focus_card(key);
                app.activity.scroll_to_follow();
            } else {
                app.push_system(format!("{} is gone", key.describe()));
            }
        }
        None => {}
    }
}

pub async fn handle_mouse(app: &mut DashboardApp, event: MouseEvent, state: &AppState) -> Outcome {
    let target = app.hits.hit(event.column, event.row).cloned();

    match event.kind {
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            let up = event.kind == MouseEventKind::ScrollUp;
            match target {
                Some(HitTarget::ChatInput)
                | Some(HitTarget::Stream)
                | Some(HitTarget::StreamRow(_)) => {
                    if up {
                        app.focus = Focus::Stream;
                        app.activity.scroll_up(3);
                    } else {
                        app.activity.scroll_down(3);
                        if app.activity.scroll == crate::tui::chat::ScrollPos::Follow
                            && app.focus == Focus::Stream
                        {
                            app.focus = Focus::ChatInput;
                        }
                    }
                }
                Some(HitTarget::ModalBody) | Some(HitTarget::ModalRow(_)) => {
                    if let Some(modal) = app.modal_mut() {
                        modal.scroll_by(if up { -3 } else { 3 });
                    }
                }
                Some(HitTarget::CardRow { .. }) | Some(HitTarget::Cards) => {
                    let rows = app.rows().len();
                    app.cards.scroll = if up {
                        app.cards.scroll.saturating_sub(3)
                    } else {
                        (app.cards.scroll + 3).min(rows.saturating_sub(1))
                    };
                }
                _ => {}
            }
            app.dirty = true;
            return Outcome::Continue;
        }
        MouseEventKind::Down(MouseButton::Left) => {}
        _ => return Outcome::Continue,
    }

    app.dirty = true;
    let Some(target) = target else {
        return Outcome::Continue;
    };

    // Buttons inside a modal are clickable; every other click in a modal is
    // swallowed so it cannot reach the panes beneath.
    if app.modal().is_some() {
        if let HitTarget::ModalActionButton(action) = target {
            return crate::tui::modal_keys::run_modal_action(app, action, state).await;
        }
        if let HitTarget::ModalRow(index) = target {
            crate::tui::modal_keys::select_modal_row(app, index);
        }
        return Outcome::Continue;
    }

    match target {
        HitTarget::ChatInput => app.focus = Focus::ChatInput,
        HitTarget::Stream => app.focus = Focus::Stream,
        HitTarget::StreamRow(seq) => {
            app.focus = Focus::Stream;
            if app.activity.cursor == Some(seq) {
                let link = crate::tui::render::stream::visible_entries(app)
                    .into_iter()
                    .find(|entry| entry.seq == seq)
                    .and_then(|e| e.event.link);
                follow_link(app, link, state).await;
            } else {
                app.activity.cursor = Some(seq);
                if app.activity.scroll == crate::tui::chat::ScrollPos::Follow {
                    app.activity.scroll_up(0);
                }
            }
        }
        HitTarget::Cards => app.focus = Focus::Cards,
        HitTarget::CardRow { row, col } => {
            let rows = app.rows();
            let Some(target_row) = rows.get(row) else {
                return Outcome::Continue;
            };
            app.focus = Focus::Cards;
            let was_here = app.cards.row == row && app.cards.col == col;
            app.cards.row = row;
            app.cards.col = col;
            // A button runs on the click. A label needs a second click, so
            // a mis-click on a peer cannot fold it or open its request.
            if target_row.button_at(col).is_some() || was_here {
                activate(app, &rows, state).await;
            }
        }
        HitTarget::StatusSegment(segment) => match segment {
            SegmentId::LogLevel => {
                let level = app.core.log_level.cycle();
                app.core.set_log_level(level);
                app.push_system(format!("Log level: {}", level.as_str()));
            }
            SegmentId::WebSearch => {
                let mode = state.cycle_web_search_mode().await;
                app.status.web_search = format!("{mode:?}").to_uppercase();
            }
            SegmentId::Handler => {
                let mode = state.cycle_event_handler_mode().await;
                app.status.handler_mode = format!("{mode:?}").to_uppercase();
            }
            SegmentId::Scripting => {
                let (mode, switched) = state.cycle_scripting_mode().await;
                if switched {
                    app.status.scripting = mode.as_str().to_string();
                }
            }
            SegmentId::Help => app.modals.push(Modal::Help { scroll: 0 }),
            SegmentId::Waiting => actions::answer_next_waiting(app, state),
            SegmentId::Instances => {
                app.focus = Focus::Cards;
            }
            SegmentId::Model => {
                let lines = crate::tui::command_exec::execute(
                    crate::events::UserCommand::ShowUsage,
                    state,
                    &dummy_channel(),
                )
                .await;
                let model = if app.status.model.is_empty() {
                    "No model — /model <name> picks one; manual, static and script rules need none."
                        .to_string()
                } else {
                    format!("Model: {} — /model lists alternatives.", app.status.model)
                };
                app.push_system(model);
                for line in lines {
                    app.push_system(line);
                }
            }
            SegmentId::Backend | SegmentId::Usage => {
                let lines = crate::tui::command_exec::execute(
                    crate::events::UserCommand::ShowUsage,
                    state,
                    &dummy_channel(),
                )
                .await;
                for line in lines {
                    app.push_system(line);
                }
            }
        },
        HitTarget::ModalBody
        | HitTarget::ModalRow(_)
        | HitTarget::ModalButton(_)
        | HitTarget::ModalActionButton(_) => {}
    }
    let rows = app.rows();
    app.clamp_cursor_to(&rows);
    Outcome::Continue
}

/// Fold the result of a spawned action back into the UI.
///
/// The result goes to the modal holding its ticket — wherever that modal is
/// in the stack, and only that one: on success it closes and the summary goes
/// to the stream; on failure it stays open showing the error, so the user can
/// fix and retry. When no modal holds the ticket (the action was started with
/// none, or its modal was closed meanwhile) both go to the stream. Matching on
/// the modal's *type* instead let a slow `c` connect close, or write its error
/// into, an unrelated form opened while it was in flight.
pub fn handle_ui_msg(app: &mut DashboardApp, msg: UiMsg) {
    app.dirty = true;
    let (ticket, result) = match msg {
        UiMsg::OpenForm(model) => {
            app.modals.push(Modal::Form(model));
            return;
        }
        UiMsg::Chat(text) => {
            app.push_system(text);
            return;
        }
        UiMsg::ActionDone { ticket, result } => (ticket, result),
    };

    let holder = app.modals.iter().position(|modal| match modal {
        Modal::Form(form) => form.pending == Some(ticket),
        Modal::Routing(model) => model.pending == Some(ticket),
        _ => false,
    });
    let Some(index) = holder else {
        match result {
            Ok(summary) => app.push_system(summary),
            Err(error) => app.push_error(error),
        }
        return;
    };

    match result {
        Ok(summary) => {
            app.modals.remove(index);
            // A text editor opened from it writes back into the modal beneath
            // itself, which is no longer the one that opened it.
            if matches!(app.modals.get(index), Some(Modal::TextEditor { .. })) {
                app.modals.remove(index);
            }
            app.push_system(summary);
        }
        Err(error) => {
            let unshown = match &mut app.modals[index] {
                Modal::Form(form) => {
                    form.pending = None;
                    form.error = Some(error);
                    None
                }
                Modal::Routing(model) => {
                    model.pending = None;
                    model.error = Some(error);
                    None
                }
                // Only a form or a routing editor holds a ticket.
                _ => Some(error),
            };
            if let Some(error) = unshown {
                app.push_error(error);
            }
        }
    }
}

/// A detached sender for command paths that only need the return value.
fn dummy_channel() -> mpsc::UnboundedSender<String> {
    let (tx, _rx) = mpsc::unbounded_channel();
    tx
}
