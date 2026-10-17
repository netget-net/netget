//! Input handling for every modal.
//!
//! The topmost modal owns all input while it is open. Each modal has its own
//! key handler here, plus `run_modal_action`, which is what a clicked or
//! focused button dispatches to — so a button and its keyboard path cannot
//! diverge.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::state::app_state::AppState;
use crate::tui::app::DashboardApp;
use crate::tui::keymap::Outcome;
use crate::tui::modal::{confirm, Modal, PendingAction};
use crate::tui::uimsg::{ActionOrigin, UiMsg};

pub(crate) async fn handle_modal_key(
    app: &mut DashboardApp,
    key: KeyEvent,
    state: &AppState,
) -> Outcome {
    let is_confirm = matches!(app.modal(), Some(Modal::Confirm { .. }));
    let is_approval = matches!(app.modal(), Some(Modal::WebApproval { .. }));

    if is_approval {
        use crate::state::app_state::WebApprovalResponse;
        let response = match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                Some(WebApprovalResponse::Allow)
            }
            KeyCode::Char('a') | KeyCode::Char('A') => Some(WebApprovalResponse::AlwaysAllow),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                Some(WebApprovalResponse::Deny)
            }
            KeyCode::Char('c') | KeyCode::Char('C')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                Some(WebApprovalResponse::Deny)
            }
            _ => None,
        };
        if let Some(response) = response {
            if let Some(Modal::WebApproval { response_tx, .. }) = app.modals.pop() {
                let _ = response_tx.send(response);
            }
        }
        return Outcome::Continue;
    }

    if is_confirm {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                if let Some(Modal::Confirm { action, .. }) = app.modals.pop() {
                    if action == PendingAction::Quit {
                        return Outcome::Quit;
                    }
                    let line = confirm::execute(&action, state).await;
                    app.push_system(line);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.modals.pop();
            }
            _ => {}
        }
        return Outcome::Continue;
    }

    match app.modal() {
        Some(Modal::ProtocolPicker { .. }) => return handle_picker_key(app, key, state).await,
        Some(Modal::Form(_)) => return handle_form_key(app, key, state).await,
        Some(Modal::TextEditor { .. }) => return handle_text_editor_key(app, key),
        Some(Modal::Composer(_)) => return handle_composer_key(app, key, state).await,
        Some(Modal::Routing(_)) => return handle_routing_key(app, key, state).await,
        Some(Modal::Intercept(_)) => return handle_intercept_key(app, key, state).await,
        _ => {}
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.modals.pop();
        }
        KeyCode::Up => app.modal_mut().map(|m| m.scroll_by(-1)).unwrap_or(()),
        KeyCode::Down => app.modal_mut().map(|m| m.scroll_by(1)).unwrap_or(()),
        KeyCode::PageUp => app.modal_mut().map(|m| m.scroll_by(-10)).unwrap_or(()),
        KeyCode::PageDown => app.modal_mut().map(|m| m.scroll_by(10)).unwrap_or(()),
        _ => {}
    }
    Outcome::Continue
}

async fn handle_picker_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    use crate::tui::modal::form::{FieldTarget, FormModel};
    use crate::tui::modal::protocol_picker;

    let Some(Modal::ProtocolPicker {
        entries,
        filter,
        selected,
        prefill_remote,
    }) = app.modals.last_mut()
    else {
        return Outcome::Continue;
    };

    match key.code {
        KeyCode::Esc => {
            app.modals.pop();
        }
        KeyCode::Up => *selected = selected.saturating_sub(1),
        KeyCode::Down => {
            let count = protocol_picker::filter(entries, filter).len();
            if *selected + 1 < count {
                *selected += 1;
            }
        }
        KeyCode::Backspace => {
            filter.pop();
            *selected = 0;
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            filter.push(c);
            *selected = 0;
        }
        KeyCode::Enter => {
            // Take everything needed out of the picker first, so the borrow on
            // `app.modals` is released before the instance is started.
            let matches = protocol_picker::filter(entries, filter);
            let Some(entry) = matches.get(*selected) else {
                return Outcome::Continue;
            };
            let section = entry.kind;
            let protocol = entry.name.clone();
            let remote = prefill_remote.clone();

            // Resolved again rather than taken from the entry: the picker was built when it
            // opened, and whether the well-known port is free is a question about now.
            let default_port = if section == crate::tui::app::Section::Servers {
                let caps = state.get_system_capabilities().await;
                crate::protocol::server_registry::registry()
                    .resolve(&protocol)
                    .ok()
                    .and_then(|p| {
                        crate::protocol::default_port::default_port_for_server(
                            p.as_ref(),
                            None,
                            &caps,
                        )
                    })
            } else {
                None
            };

            let mut model =
                FormModel::for_create(section, &protocol, default_port.as_ref().map(|d| d.port));
            if let Some(default) = &default_port {
                model.note_default_port(default);
            }
            if let Some(remote) = remote {
                model.set_field_value(&FieldTarget::RemoteAddr, remote);
            }
            let missing = model.missing_required();
            app.modals.pop();

            // Picking a protocol starts it immediately on defaults — the point
            // of the picker is "give me one of these", not "fill in a form".
            // Everything stays editable afterwards (`e` config, `r` routing).
            // The form only appears when something genuinely cannot be
            // defaulted, such as a client's remote address.
            if let Some(missing) = missing {
                model.focus_first_missing_required();
                model.error = Some(format!(
                    "{protocol} needs {missing} before it can start — fill it in and press [ Apply ]"
                ));
                app.modals.push(Modal::Form(Box::new(model)));
                return Outcome::Continue;
            }

            match &default_port {
                Some(default) => app.push_system(format!(
                    "Starting {protocol} on defaults ({})…",
                    default.describe()
                )),
                None => app.push_system(format!("Starting {protocol} on defaults…")),
            }
            let llm = app.llm_client.clone();
            let status_tx = app.status_tx.clone();
            let ui_tx = app.ui_tx.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let result = model
                    .apply(&state, llm, &status_tx)
                    .await
                    .map_err(|e| e.to_string());
                let _ = ui_tx.send(UiMsg::ActionDone {
                    origin: ActionOrigin::Form,
                    result,
                });
            });
        }
        _ => {}
    }
    Outcome::Continue
}

async fn handle_form_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    use crate::tui::modal::form::FieldTarget;
    use crate::tui::modal::text_editor::TextEditorModel;

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let Some(Modal::Form(form)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };

    // Inline editing of a single-line field.
    if let Some(buffer) = form.editing.as_mut() {
        match key.code {
            KeyCode::Enter => form.commit_edit(),
            KeyCode::Esc => form.cancel_edit(),
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Char(c) if !ctrl => buffer.push(c),
            _ => {}
        }
        return Outcome::Continue;
    }

    match key.code {
        KeyCode::Esc => {
            app.modals.pop();
        }
        KeyCode::Tab => form.cycle_focus(false),
        KeyCode::BackTab => form.cycle_focus(true),
        KeyCode::Up => {
            form.focused_button = None;
            form.move_selection(-1);
        }
        KeyCode::Down => {
            form.focused_button = None;
            form.move_selection(1);
        }
        KeyCode::Enter if form.focused_action().is_some() => {
            let action = form.focused_action().unwrap();
            return run_form_action(app, action, state).await;
        }
        KeyCode::Enter => {
            let Some(field) = form.selected_field().cloned() else {
                return Outcome::Continue;
            };
            if field.multiline {
                let json = matches!(field.target, FieldTarget::EventHandlersJson);
                let editor = TextEditorModel::new(&field.label, &field.help, &field.value, json);
                app.modals.push(Modal::TextEditor {
                    editor: Box::new(editor),
                    target: field.target,
                });
            } else if field.target.is_toggle() {
                let toggled = if field.value == "true" {
                    "false"
                } else {
                    "true"
                };
                let target = field.target.clone();
                form.set_field_value(&target, toggled.to_string());
            } else {
                form.begin_edit();
            }
        }
        // Typing on a selected field edits it, starting with the character
        // just typed. Requiring Enter first made every field a two-step, and
        // nothing else here wants bare letters.
        KeyCode::Char(c) if !ctrl && form.focused_button.is_none() => {
            if form
                .selected_field()
                .is_some_and(|field| !field.multiline && !field.target.is_toggle())
            {
                form.begin_edit();
                if let Some(buffer) = form.editing.as_mut() {
                    buffer.push(c);
                }
            }
        }
        KeyCode::Backspace if form.focused_button.is_none() => {
            // Same for backspace: start editing and delete, rather than
            // silently doing nothing until Enter is pressed.
            if form
                .selected_field()
                .is_some_and(|field| !field.multiline && !field.target.is_toggle())
            {
                form.begin_edit();
                if let Some(buffer) = form.editing.as_mut() {
                    buffer.pop();
                }
            }
        }
        _ => {}
    }
    Outcome::Continue
}

/// Run one instance-form button. Applying is spawned, never awaited on the
/// event loop: creating a server or connecting a client does network I/O, and
/// awaiting it here froze the whole dashboard until the kernel gave up.
async fn run_form_action(
    app: &mut DashboardApp,
    action: crate::tui::hit::ModalAction,
    state: &AppState,
) -> Outcome {
    use crate::tui::hit::ModalAction;

    let Some(Modal::Form(form)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };
    match action {
        ModalAction::FormCancel => {
            app.modals.pop();
        }
        ModalAction::FormWireshark => {
            // Stacked over the form, so Esc returns to it with nothing lost —
            // the point is to start the capture, then come back and Apply.
            let plan = crate::tui::wireshark::CapturePlan::build(
                form.capture_target(),
                crate::tui::wireshark::Platform::current(),
            );
            app.modals.push(Modal::Wireshark {
                plan: Box::new(plan),
                scroll: 0,
            });
        }
        ModalAction::FormApply => {
            if form.busy {
                return Outcome::Continue;
            }
            form.busy = true;
            form.error = None;
            let model = form.clone();
            let llm = app.llm_client.clone();
            let status_tx = app.status_tx.clone();
            let ui_tx = app.ui_tx.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let result = model
                    .apply(&state, llm, &status_tx)
                    .await
                    .map_err(|e| e.to_string());
                let _ = ui_tx.send(UiMsg::ActionDone {
                    origin: ActionOrigin::Form,
                    result,
                });
            });
        }
        _ => {}
    }
    Outcome::Continue
}

/// The text editor: Tab leaves the text for the `[ Accept ]` / `[ Cancel ]`
/// buttons (and cycles back), Enter presses the focused one, and typing
/// returns to the text. Tab used to insert a tab character here, which left
/// a chord as the only way to accept — the one thing the buttons exist to
/// avoid. Indentation inside the editor is the spacebar's job.
fn handle_text_editor_key(app: &mut DashboardApp, key: KeyEvent) -> Outcome {
    use crate::tui::hit::ModalAction;

    let Some(Modal::TextEditor { editor, .. }) = app.modals.last_mut() else {
        return Outcome::Continue;
    };

    match key.code {
        KeyCode::Esc => {
            app.modals.pop();
        }
        KeyCode::Tab => editor.cycle_focus(false),
        KeyCode::BackTab => editor.cycle_focus(true),
        KeyCode::Enter | KeyCode::Char(' ') if editor.focused_action().is_some() => {
            match editor.focused_action() {
                Some(ModalAction::EditorAccept) => text_editor_accept(app),
                Some(ModalAction::EditorCancel) => {
                    app.modals.pop();
                }
                _ => {}
            }
        }
        _ => {
            editor.focused_button = None;
            editor.textarea.input(tui_textarea::Input::from(key));
        }
    }
    Outcome::Continue
}

/// Accept the text editor's content into whatever opened it. Shared by the
/// focused and the clicked `[ Accept ]` button so the two cannot diverge.
fn text_editor_accept(app: &mut DashboardApp) {
    use crate::tui::modal::form::FieldTarget;

    let Some(Modal::TextEditor { editor, target }) = app.modals.last_mut() else {
        return;
    };
    let Some(text) = editor.accept() else {
        return; // Validation failed; the editor shows why.
    };
    let target = target.clone();
    app.modals.pop();
    match app.modals.last_mut() {
        Some(Modal::Form(form)) => form.set_field_value(&target, text),
        // Opened from a routing draft: the target says which half of the
        // handler body was being edited.
        Some(Modal::Routing(model)) => {
            if let Some(draft) = model.draft.as_mut() {
                match target {
                    FieldTarget::DraftActions | FieldTarget::EventHandlersJson => {
                        match serde_json::from_str::<serde_json::Value>(&text) {
                            Ok(serde_json::Value::Array(actions)) => {
                                draft.actions = actions;
                                draft.error = None;
                            }
                            Ok(_) => {
                                draft.error = Some("response actions must be a JSON array".into())
                            }
                            Err(e) => draft.error = Some(format!("invalid JSON: {e}")),
                        }
                    }
                    FieldTarget::DraftInstruction => draft.instruction = text,
                    _ => draft.code = text,
                }
            }
        }
        _ => {}
    }
}

async fn handle_composer_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let Some(Modal::Composer(composer)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };

    if let Some(buffer) = composer.editing.as_mut() {
        match key.code {
            KeyCode::Enter => composer.commit_edit(),
            KeyCode::Esc => composer.cancel_edit(),
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Char(c) if !ctrl => buffer.push(c),
            _ => {}
        }
        return Outcome::Continue;
    }

    match key.code {
        KeyCode::Esc => {
            if composer.chosen.is_some() {
                composer.back_to_actions();
            } else {
                app.modals.pop();
            }
        }
        KeyCode::Tab => composer.cycle_focus(false),
        KeyCode::BackTab => composer.cycle_focus(true),
        KeyCode::Up => {
            composer.focused_button = None;
            composer.move_selection(-1);
        }
        KeyCode::Down => {
            composer.focused_button = None;
            composer.move_selection(1);
        }
        KeyCode::Enter if composer.focused_action().is_some() => {
            let action = composer.focused_action().unwrap();
            return run_composer_action(app, action, state).await;
        }
        KeyCode::Enter => {
            if composer.chosen.is_some() {
                composer.begin_edit();
            } else {
                composer.choose();
            }
        }
        // Space flips a boolean field like a checkbox, and steps a choice
        // field to its next value — the same gesture Enter performs.
        KeyCode::Char(' ')
            if composer.chosen.is_some()
                && composer.raw_json.is_none()
                && composer.focused_button.is_none()
                && composer.selected_field().is_some_and(|f| {
                    matches!(
                        f.kind,
                        crate::tui::modal::composer::FieldKind::Bool
                            | crate::tui::modal::composer::FieldKind::Choice
                    )
                }) =>
        {
            composer.begin_edit();
        }
        // ←/→ cycle a choice field without leaving the row.
        KeyCode::Left | KeyCode::Right
            if composer.chosen.is_some()
                && composer.raw_json.is_none()
                && composer.focused_button.is_none()
                && composer
                    .selected_field()
                    .is_some_and(|f| f.kind == crate::tui::modal::composer::FieldKind::Choice) =>
        {
            let backward = key.code == KeyCode::Left;
            let selected = composer.selected;
            if let Some(field) = composer.fields.get_mut(selected) {
                field.cycle_choice(backward);
            }
        }
        // Typing on a parameter field edits it (see the form's note).
        KeyCode::Char(c)
            if !ctrl
                && composer.chosen.is_some()
                && composer.raw_json.is_none()
                && composer.focused_button.is_none()
                && composer
                    .selected_field()
                    .is_some_and(|f| f.kind == crate::tui::modal::composer::FieldKind::Text) =>
        {
            composer.begin_edit();
            if let Some(buffer) = composer.editing.as_mut() {
                buffer.push(c);
            }
        }
        KeyCode::Backspace
            if composer.chosen.is_some()
                && composer.raw_json.is_none()
                && composer.focused_button.is_none()
                && composer
                    .selected_field()
                    .is_some_and(|f| f.kind == crate::tui::modal::composer::FieldKind::Text) =>
        {
            composer.begin_edit();
            if let Some(buffer) = composer.editing.as_mut() {
                buffer.pop();
            }
        }
        // Backspace unsets an optional choice field (a required one has no
        // meaningful empty state to go back to).
        KeyCode::Backspace
            if composer.chosen.is_some()
                && composer.raw_json.is_none()
                && composer.focused_button.is_none()
                && composer.selected_field().is_some_and(|f| {
                    f.kind == crate::tui::modal::composer::FieldKind::Choice && !f.required
                }) =>
        {
            let selected = composer.selected;
            if let Some(field) = composer.fields.get_mut(selected) {
                field.value.clear();
            }
        }
        _ => {}
    }
    Outcome::Continue
}

/// Run one composer button. Sending is spawned (network I/O must not block
/// the event loop); the toggles act in place.
async fn run_composer_action(
    app: &mut DashboardApp,
    action: crate::tui::hit::ModalAction,
    state: &AppState,
) -> Outcome {
    use crate::tui::hit::ModalAction;

    let Some(Modal::Composer(composer)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };
    match action {
        ModalAction::ComposerBack => composer.back_to_actions(),
        ModalAction::ComposerRaw => composer.toggle_raw_json(),
        ModalAction::ComposerSend => {
            use crate::tui::modal::composer::{ComposerModel, ComposerTarget};

            // Answering a parked request: resolving is a channel send under a
            // short lock, so it happens inline, and both the composer and the
            // question it answered close together.
            if let ComposerTarget::Intercept { id, .. } = composer.target {
                let actions = match composer.build_answer() {
                    Ok(actions) => actions,
                    Err(e) => {
                        composer.error = Some(e.to_string());
                        return Outcome::Continue;
                    }
                };
                let names: Vec<String> = actions
                    .iter()
                    .map(|a| {
                        a.get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("(no type)")
                            .to_string()
                    })
                    .collect();
                match state.resolve_intercept(id, actions).await {
                    Ok(()) => {
                        app.modals.pop();
                        if matches!(app.modals.last(), Some(Modal::Intercept(m)) if m.id == id) {
                            app.modals.pop();
                        }
                        app.push_system(format!(
                            "answered request #{id} with {}",
                            names.join(", ")
                        ));
                    }
                    Err(e) => composer.error = Some(e),
                }
                return Outcome::Continue;
            }

            // Validate synchronously: a missing required field is the user's
            // to fix right here, so the composer stays open showing it.
            let action = match composer.build_action() {
                Ok(action) => action,
                Err(e) => {
                    composer.error = Some(e.to_string());
                    return Outcome::Continue;
                }
            };

            // Everything past this point is network work. Close the composer
            // and report asynchronously — it used to sit on "sending…" until
            // the outcome arrived, which for a client whose loop is parked on
            // a MANUAL question meant a frozen-looking modal and then a bare
            // timeout error.
            let target = composer.target;
            let name = action
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("action")
                .to_string();
            app.modals.pop();
            app.push_system(format!("{}: sending {name}…", target.describe()));

            let ui_tx = app.ui_tx.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let message = match ComposerModel::deliver(target, &state, action).await {
                    Ok(outcome) => format!(
                        "{}: {}",
                        target.describe(),
                        crate::tui::modal::composer::describe(&outcome)
                    ),
                    // No target prefix here: send_to_client / send_to_peer
                    // already name what failed, and prefixing produced
                    // "client #2: client #2 did not report…".
                    Err(e) => match ComposerModel::queue_hint(target, &state).await {
                        Some(hint) => format!("{e} — {hint}"),
                        None => e.to_string(),
                    },
                };
                let _ = ui_tx.send(UiMsg::Chat(message));
            });
        }
        _ => {}
    }
    Outcome::Continue
}

/// The intercept modal: three buttons, Tab between them, Enter acts.
async fn handle_intercept_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    let Some(Modal::Intercept(model)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };
    match key.code {
        // Esc keeps the request waiting — closing the window must not be the
        // thing that silently refuses a peer.
        KeyCode::Esc => {
            app.modals.pop();
        }
        KeyCode::Tab | KeyCode::Right | KeyCode::Down => model.cycle_focus(false),
        KeyCode::BackTab | KeyCode::Left | KeyCode::Up => model.cycle_focus(true),
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(action) = model.focused_action() {
                return run_intercept_action(app, action, state).await;
            }
        }
        _ => {}
    }
    Outcome::Continue
}

/// Run one intercept button: compose, send, or fail closed.
async fn run_intercept_action(
    app: &mut DashboardApp,
    action: crate::tui::hit::ModalAction,
    state: &AppState,
) -> Outcome {
    use crate::tui::hit::ModalAction;
    use crate::tui::modal::composer::ComposerModel;

    let Some(Modal::Intercept(model)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };
    match action {
        // The same composer as the `[ send ]` rows: an action list, then
        // fields. Its Send resolves the intercept (see `run_composer_action`).
        ModalAction::InterceptCompose => {
            if model.vocabulary.is_empty() {
                model.error = Some(format!(
                    "{} declares no actions to answer with — Answer with nothing or Fail closed",
                    model.protocol
                ));
                return Outcome::Continue;
            }
            let composer = ComposerModel::for_intercept(
                model.id,
                model.owner,
                &model.protocol,
                model.vocabulary.clone(),
            );
            app.modals.push(Modal::Composer(Box::new(composer)));
        }
        ModalAction::InterceptSend => {
            // Zero actions is a real answer — "acknowledge, say nothing" — the
            // same semantics as an empty static handler, and exactly what a
            // lifecycle event like connection-opened usually deserves. It is
            // delivered (Ok) and therefore distinct from a timeout (Err).
            let id = model.id;
            // Resolving is a channel send under a short lock — no network I/O,
            // safe to do inline (the waiting dispatcher does the wire work).
            match state.resolve_intercept(id, Vec::new()).await {
                Ok(()) => {
                    app.modals.pop();
                    app.push_system(format!(
                        "answered request #{id} with nothing (acknowledged, no reply sent)"
                    ));
                }
                Err(e) => model.error = Some(e),
            }
        }
        ModalAction::InterceptDismiss => {
            let id = model.id;
            if state.dismiss_intercept(id).await {
                app.modals.pop();
                app.push_system(format!(
                    "refused request #{id} — the peer got the fail-closed reply"
                ));
            } else {
                model.error = Some(format!("request #{id} is no longer waiting"));
            }
        }
        _ => {}
    }
    Outcome::Continue
}

async fn handle_routing_key(app: &mut DashboardApp, key: KeyEvent, state: &AppState) -> Outcome {
    use crate::tui::modal::routing::DraftFocus;
    use crate::tui::modal::text_editor::TextEditorModel;

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let Some(Modal::Routing(model)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };

    // Handler draft open. Tab walks kind → pattern → the kind's fields →
    // buttons; ←/→ changes whatever choice has focus; Enter acts on it.
    if let Some(draft) = model.draft.as_mut() {
        if let Some(buffer) = draft.editing.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    let text = buffer.clone();
                    draft.editing = None;
                    match draft.focus {
                        DraftFocus::Pattern => draft.pattern = text,
                        DraftFocus::Timeout => draft.timeout_secs = text,
                        _ => {}
                    }
                }
                KeyCode::Esc => draft.editing = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) if !ctrl => buffer.push(c),
                _ => {}
            }
            return Outcome::Continue;
        }

        let backward_left = key.code == KeyCode::Left;
        match key.code {
            KeyCode::Esc => model.draft = None,
            KeyCode::Tab => draft.cycle_focus(false),
            KeyCode::BackTab => draft.cycle_focus(true),
            KeyCode::Left | KeyCode::Right => match draft.focus {
                DraftFocus::Kind => {
                    let kind = if backward_left {
                        draft.kind.previous()
                    } else {
                        draft.kind.next()
                    };
                    draft.set_kind(kind);
                }
                DraftFocus::Pattern => {
                    let event_ids = model.event_ids.clone();
                    if let Some(draft) = model.draft.as_mut() {
                        draft.cycle_pattern(&event_ids, backward_left);
                    }
                }
                DraftFocus::Language => draft.cycle_language(backward_left),
                DraftFocus::Resident => draft.resident = !draft.resident,
                DraftFocus::Button(_) => draft.cycle_focus(backward_left),
                _ => {}
            },
            KeyCode::Up if draft.focus == DraftFocus::Actions => {
                draft.selected_action = draft.selected_action.saturating_sub(1);
            }
            KeyCode::Down if draft.focus == DraftFocus::Actions => {
                if draft.selected_action + 1 < draft.actions.len() {
                    draft.selected_action += 1;
                }
            }
            KeyCode::Char('d') if draft.focus == DraftFocus::Actions => {
                if draft.selected_action < draft.actions.len() {
                    draft.actions.remove(draft.selected_action);
                    draft.selected_action = draft.selected_action.saturating_sub(1);
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                use crate::tui::modal::form::FieldTarget;
                match draft.focus {
                    DraftFocus::Button(_) => match draft.focused_action() {
                        Some(crate::tui::hit::ModalAction::DraftSave) => {
                            match model.commit_draft() {
                                Ok(()) => model.error = None,
                                Err(e) => {
                                    if let Some(draft) = model.draft.as_mut() {
                                        draft.error = Some(e.to_string());
                                    }
                                }
                            }
                        }
                        Some(crate::tui::hit::ModalAction::DraftCancel) => model.draft = None,
                        _ => {}
                    },
                    DraftFocus::Kind => draft.set_kind(draft.kind.next()),
                    DraftFocus::Pattern => draft.editing = Some(draft.pattern.clone()),
                    DraftFocus::Language => draft.cycle_language(false),
                    DraftFocus::Resident => draft.resident = !draft.resident,
                    DraftFocus::Timeout => draft.editing = Some(draft.timeout_secs.clone()),
                    DraftFocus::Instruction => {
                        let editor = TextEditorModel::new(
                            "per-event instruction",
                            "What the model should do when this event arrives.",
                            &draft.instruction,
                            false,
                        );
                        app.modals.push(Modal::TextEditor {
                            editor: Box::new(editor),
                            target: FieldTarget::DraftInstruction,
                        });
                    }
                    DraftFocus::Code => {
                        let editor = TextEditorModel::new(
                            "script code",
                            "The script receives the event on stdin and writes {\"actions\": [...]}.",
                            &draft.code,
                            false,
                        );
                        app.modals.push(Modal::TextEditor {
                            editor: Box::new(editor),
                            target: FieldTarget::DraftCode,
                        });
                    }
                    DraftFocus::Actions => {
                        let initial = if draft.actions.is_empty() {
                            example_actions(model_actions(model))
                        } else {
                            serde_json::to_string_pretty(&draft.actions).unwrap_or_default()
                        };
                        let editor = TextEditorModel::new(
                            "response actions",
                            "A JSON array of actions. {{event.field}} interpolates from the event.",
                            &initial,
                            true,
                        );
                        app.modals.push(Modal::TextEditor {
                            editor: Box::new(editor),
                            target: FieldTarget::DraftActions,
                        });
                    }
                }
            }
            // Typing on the two free-text fields edits them in place.
            KeyCode::Char(c) if !ctrl => match draft.focus {
                DraftFocus::Pattern => {
                    draft.editing = Some(format!("{}{c}", draft.pattern));
                }
                DraftFocus::Timeout => {
                    draft.editing = Some(format!("{}{c}", draft.timeout_secs));
                }
                _ => {}
            },
            KeyCode::Backspace => match draft.focus {
                DraftFocus::Pattern => {
                    let mut text = draft.pattern.clone();
                    text.pop();
                    draft.editing = Some(text);
                }
                DraftFocus::Timeout => {
                    let mut text = draft.timeout_secs.clone();
                    text.pop();
                    draft.editing = Some(text);
                }
                _ => {}
            },
            _ => {}
        }
        return Outcome::Continue;
    }

    // Handler list and buttons. Tab moves between them; Enter activates what
    // has focus. The letter shortcuts still work, but nothing depends on them.
    use crate::tui::modal::routing::RoutingFocus;

    match key.code {
        KeyCode::Tab => model.cycle_focus(false),
        KeyCode::BackTab => model.cycle_focus(true),
        KeyCode::Esc => {
            app.modals.pop();
        }
        KeyCode::Up if model.focus == RoutingFocus::List => model.move_selection(-1),
        KeyCode::Down if model.focus == RoutingFocus::List => model.move_selection(1),
        KeyCode::Left | KeyCode::Right => model.cycle_focus(key.code == KeyCode::Left),
        KeyCode::Enter => match model.focused_button() {
            Some(action) => return run_routing_action(app, action, state).await,
            None => model.edit_selected(),
        },
        // Kept as accelerators for anyone who wants them.
        KeyCode::Char('a') => model.add(),
        KeyCode::Char('e') => model.edit_selected(),
        KeyCode::Char('d') => model.delete_selected(),
        KeyCode::Char('K') => model.reorder(-1),
        KeyCode::Char('J') => model.reorder(1),
        _ => {}
    }
    Outcome::Continue
}

/// Run one routing-editor button.
async fn run_routing_action(
    app: &mut DashboardApp,
    action: crate::tui::hit::ModalAction,
    state: &AppState,
) -> Outcome {
    use crate::tui::hit::ModalAction;

    let Some(Modal::Routing(model)) = app.modals.last_mut() else {
        return Outcome::Continue;
    };
    match action {
        ModalAction::RoutingAdd => model.add(),
        ModalAction::RoutingEdit => model.edit_selected(),
        ModalAction::RoutingDelete => model.delete_selected(),
        ModalAction::RoutingMoveUp => model.reorder(-1),
        ModalAction::RoutingMoveDown => model.reorder(1),
        ModalAction::RoutingCancel => {
            app.modals.pop();
        }
        ModalAction::RoutingSave => {
            if model.busy {
                return Outcome::Continue;
            }
            model.busy = true;
            model.error = None;
            let snapshot = model.clone();
            let llm = app.llm_client.clone();
            let status_tx = app.status_tx.clone();
            let ui_tx = app.ui_tx.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let result = snapshot
                    .apply(&state, llm, &status_tx)
                    .await
                    .map_err(|e| e.to_string());
                let _ = ui_tx.send(UiMsg::ActionDone {
                    origin: ActionOrigin::Routing,
                    result,
                });
            });
        }
        // Draft/form actions are handled by their own modals.
        _ => {}
    }
    Outcome::Continue
}

fn model_actions(
    model: &crate::tui::modal::routing::RoutingModel,
) -> &[crate::llm::actions::ActionDefinition] {
    &model.actions
}

/// A starter JSON array using the protocol's first action as a template, so
/// the editor opens with something valid rather than a blank page.
fn example_actions(actions: &[crate::llm::actions::ActionDefinition]) -> String {
    match actions.first() {
        Some(action) => {
            let mut example = action.example.clone();
            if example.get("type").is_none() {
                if let Some(obj) = example.as_object_mut() {
                    obj.insert(
                        "type".to_string(),
                        serde_json::Value::String(action.name.clone()),
                    );
                }
            }
            serde_json::to_string_pretty(&serde_json::Value::Array(vec![example]))
                .unwrap_or_else(|_| "[]".to_string())
        }
        None => "[]".to_string(),
    }
}

/// Point the open modal's selection at the row that was clicked.
///
/// Selection only — a click never *acts*, so a mis-click cannot send a
/// request or delete a handler. Enter (or the buttons) still does that.
pub(crate) fn select_modal_row(app: &mut DashboardApp, index: usize) {
    match app.modals.last_mut() {
        Some(Modal::Form(form)) => {
            if index < form.fields.len() {
                form.focused_button = None;
                form.selected = index;
            }
        }
        Some(Modal::Composer(composer)) => {
            let len = if composer.chosen.is_some() {
                composer.fields.len()
            } else {
                composer.actions.len()
            };
            if index < len {
                composer.focused_button = None;
                composer.selected = index;
            }
        }
        Some(Modal::Routing(model)) => {
            if model.draft.is_none() && index < model.handlers.len() {
                model.focus = crate::tui::modal::routing::RoutingFocus::List;
                model.selected = index;
            }
        }
        Some(Modal::ProtocolPicker { selected, .. }) => *selected = index,
        _ => {}
    }
}

/// Dispatch a modal button to the editor that owns it.
pub(crate) async fn run_modal_action(
    app: &mut DashboardApp,
    action: crate::tui::hit::ModalAction,
    state: &AppState,
) -> Outcome {
    use crate::tui::hit::ModalAction;
    match action {
        ModalAction::FormApply | ModalAction::FormCancel | ModalAction::FormWireshark => {
            run_form_action(app, action, state).await
        }
        ModalAction::DraftSave => {
            if let Some(Modal::Routing(model)) = app.modals.last_mut() {
                match model.commit_draft() {
                    Ok(()) => model.error = None,
                    Err(e) => {
                        if let Some(draft) = model.draft.as_mut() {
                            draft.error = Some(e.to_string());
                        }
                    }
                }
            }
            Outcome::Continue
        }
        ModalAction::DraftCancel => {
            if let Some(Modal::Routing(model)) = app.modals.last_mut() {
                model.draft = None;
            }
            Outcome::Continue
        }
        ModalAction::DraftKind(kind) => {
            if let Some(Modal::Routing(model)) = app.modals.last_mut() {
                if let Some(draft) = model.draft.as_mut() {
                    draft.set_kind(kind);
                    draft.focus = crate::tui::modal::routing::DraftFocus::Kind;
                }
            }
            Outcome::Continue
        }
        ModalAction::InterceptCompose
        | ModalAction::InterceptSend
        | ModalAction::InterceptDismiss => run_intercept_action(app, action, state).await,
        ModalAction::ComposerSend | ModalAction::ComposerRaw | ModalAction::ComposerBack => {
            run_composer_action(app, action, state).await
        }
        ModalAction::EditorAccept => {
            text_editor_accept(app);
            Outcome::Continue
        }
        ModalAction::EditorCancel => {
            if matches!(app.modals.last(), Some(Modal::TextEditor { .. })) {
                app.modals.pop();
            }
            Outcome::Continue
        }
        ModalAction::ConfirmYes => {
            if let Some(Modal::Confirm { action, .. }) = app.modals.pop() {
                if action == PendingAction::Quit {
                    return Outcome::Quit;
                }
                let line = confirm::execute(&action, state).await;
                app.push_system(line);
            }
            Outcome::Continue
        }
        ModalAction::ConfirmNo => {
            if matches!(app.modals.last(), Some(Modal::Confirm { .. })) {
                app.modals.pop();
            }
            Outcome::Continue
        }
        _ => run_routing_action(app, action, state).await,
    }
}
