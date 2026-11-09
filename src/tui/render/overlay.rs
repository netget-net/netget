//! Modal chrome: a centred, cleared box with a title, scrollable body and a
//! hint line.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::DashboardApp;
use crate::tui::hit::HitTarget;
use crate::tui::modal::{help, request_detail, Modal};
use crate::tui::wireshark::PlanLine;

pub fn draw(frame: &mut Frame, app: &mut DashboardApp, area: Rect) {
    let Some(modal) = app.modals.last() else {
        return;
    };
    let size = modal.size();
    // Stacked (narrow) layout: a modal takes the whole width, which is all there is.
    let (percent_x, max_cols) = if area.width < super::TWO_COLUMN_WIDTH {
        (100, u16::MAX)
    } else {
        (size.percent_x, size.max_cols)
    };
    let rect = super::centered_capped(area, percent_x, size.percent_y, max_cols, size.max_rows);
    let title = modal.title();
    let hint = modal.hint();

    let body_lines: Vec<Line> = match modal {
        Modal::Help { .. } => help::help_lines()
            .into_iter()
            .map(|(key, text)| match key {
                Some(key) => Line::from(vec![
                    Span::styled(format!("  {key:<22}"), app.styles.accent),
                    Span::styled(text.to_string(), app.styles.normal),
                ]),
                None => Line::from(Span::styled(format!("\n{text}"), app.styles.title)),
            })
            .collect(),
        Modal::RequestDetail { entry, .. } => request_detail::detail_lines(entry)
            .into_iter()
            .map(|l| Line::from(Span::styled(l, app.styles.normal)))
            .collect(),
        Modal::Confirm { message, .. } => vec![
            Line::from(Span::styled(message.clone(), app.styles.warning)),
            Line::from(""),
            Line::from(Span::styled("This cannot be undone.", app.styles.dimmed)),
        ],
        Modal::WebApproval { url, .. } => vec![
            Line::from(Span::styled(
                "The model wants to search the web:",
                app.styles.normal,
            )),
            Line::from(""),
            Line::from(Span::styled(url.clone(), app.styles.info)),
        ],
        Modal::BandDetail { key, .. } => band_detail_lines(app, *key),
        Modal::Wireshark { plan, .. } => plan
            .lines()
            .into_iter()
            .map(|line| match line {
                PlanLine::Heading(text) => Line::from(Span::styled(text, app.styles.title)),
                PlanLine::Value(text) => Line::from(Span::styled(text, app.styles.accent)),
                PlanLine::Note(text) => Line::from(Span::styled(text, app.styles.normal)),
                PlanLine::Blank => Line::from(""),
            })
            .collect(),
        // Rendered separately below (list + fixed detail pane).
        Modal::ProtocolPicker { .. } => Vec::new(),
        // Rendered separately below (scrolled fields, pinned error, buttons).
        Modal::Form(_) => Vec::new(),
        Modal::TextEditor { editor, .. } => {
            // The textarea widget renders itself; draw it after the chrome.
            let _ = editor;
            Vec::new()
        }
        // Rendered separately below (their own panes and button rows).
        Modal::Composer(_) | Modal::Routing(_) | Modal::Intercept(_) => Vec::new(),
    };

    let scroll = match modal {
        Modal::Help { scroll }
        | Modal::RequestDetail { scroll, .. }
        | Modal::BandDetail { scroll, .. }
        | Modal::Wireshark { scroll, .. } => *scroll,
        _ => 0,
    };

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.styles.accent)
        .title(Span::styled(format!(" {title} "), app.styles.title))
        .title_bottom(Span::styled(format!(" {hint} "), app.styles.dimmed));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    app.hits.push(rect, HitTarget::ModalBody);

    // The instance form: fields, then Apply / Cancel.
    if let Some(Modal::Form(form)) = app.modals.last() {
        let body = form_lines_with_offsets(app, form, inner.width);
        let error = form.error.clone();
        let buttons = form.buttons();
        let focused = form.focused_action();
        draw_scrolled(
            frame,
            app,
            rect,
            inner,
            body,
            error.as_deref(),
            &buttons,
            focused,
        );
        return;
    }

    // The routing editor: either the handler table, or the draft editor with
    // its kind control, its panes and its buttons.
    if let Some(Modal::Routing(model)) = app.modals.last() {
        if let Some(draft) = &model.draft {
            use crate::tui::modal::routing::DraftFocus;
            let kind = draft.kind;
            let kind_focused = draft.focus == DraftFocus::Kind;
            let buttons = draft.buttons();
            let focused = draft.focused_action();
            let error = draft.error.clone();
            let body = draft_body_lines(app, model, draft, inner.width);

            let rows = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    ratatui::layout::Constraint::Length(1),
                    ratatui::layout::Constraint::Length(2),
                    ratatui::layout::Constraint::Min(3),
                ])
                .split(inner);
            draw_kind_segments(frame, app, rows[0], kind, kind_focused);
            frame.render_widget(
                Paragraph::new(Span::styled(kind.blurb(), app.styles.dimmed))
                    .wrap(Wrap { trim: false }),
                rows[1],
            );
            // The body scrolls to whatever has focus and the error stays above
            // the buttons, as in the instance form: a long pattern list or
            // many static actions used to push both off the bottom of the box.
            draw_scrolled(
                frame,
                app,
                rect,
                rows[2],
                body,
                error.as_deref(),
                &buttons,
                focused,
            );
            return;
        }

        use crate::tui::modal::routing::RoutingFocus;

        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Min(3),
                ratatui::layout::Constraint::Length(1),
                ratatui::layout::Constraint::Length(2),
            ])
            .split(inner);

        // --- handler list ---
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            "Rules are matched in order; the first match wins.",
            app.styles.dimmed,
        ))];
        let handler_rows = model.rows();
        if handler_rows.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (none yet — Add one to answer an event without the model)",
                app.styles.dimmed,
            )));
        }
        let mut offsets = Vec::with_capacity(handler_rows.len());
        for (index, row) in handler_rows.iter().enumerate() {
            offsets.push(lines.len() as u16);
            let selected = model.focus == RoutingFocus::List && index == model.selected;
            lines.push(Line::from(vec![
                Span::styled(if selected { "▸ " } else { "  " }, app.styles.accent),
                Span::styled(
                    row.clone(),
                    if selected {
                        app.styles.selected
                    } else {
                        app.styles.normal
                    },
                ),
            ]));
        }
        if let Some(error) = &model.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("✗ {error}"),
                app.styles.error,
            )));
        }
        let buttons = model.buttons();
        let focused = model.focused_button();
        let note = model.fallback_note();
        frame.render_widget(Paragraph::new(lines), rows[0]);
        push_row_hits(app, rows[0], &offsets);
        draw_button_row(frame, app, rows[1], &buttons, focused);
        frame.render_widget(
            Paragraph::new(Span::styled(note, app.styles.dimmed)).wrap(Wrap { trim: false }),
            rows[2],
        );
        return;
    }

    // A pending intercept: what arrived, the answer being composed, buttons.
    if let Some(Modal::Intercept(model)) = app.modals.last() {
        let buttons = model.buttons();
        let focused = model.focused_action();
        let lines = intercept_lines(app, model);
        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Min(3),
                ratatui::layout::Constraint::Length(1),
            ])
            .split(inner);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), rows[0]);
        draw_button_row(frame, app, rows[1], &buttons, focused);
        return;
    }

    // The composer: list/fields above, buttons below.
    if let Some(Modal::Composer(composer)) = app.modals.last() {
        let buttons = composer.buttons();
        let focused = composer.focused_action();
        let error = composer.error.clone();
        let body = composer_lines_with_offsets(app, composer, inner.width);
        // Scrolled to the selected action or field, the validation error
        // pinned above the buttons: a verb with more parameters than the box
        // holds used to lose its last fields and the error below them.
        draw_scrolled(
            frame,
            app,
            rect,
            inner,
            body,
            error.as_deref(),
            &buttons,
            focused,
        );
        return;
    }

    // The picker is a list with a fixed detail pane beneath it.
    if let Some(Modal::ProtocolPicker {
        entries,
        filter,
        selected,
        ..
    }) = app.modals.last()
    {
        const DETAIL_HEIGHT: u16 = 7;
        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Min(3),
                ratatui::layout::Constraint::Length(DETAIL_HEIGHT),
            ])
            .split(inner);

        use crate::tui::modal::protocol_picker;
        let matches = protocol_picker::filter(entries, filter);

        // One header row (the filter), then a window over the matches sized to
        // what is left. Scrolling here is not optional: with every protocol
        // compiled in the list is far longer than the modal, and a selection
        // that runs off the bottom is invisible.
        let header = Line::from(vec![
            Span::styled("filter: ", app.styles.dimmed),
            Span::styled(filter.to_string(), app.styles.accent),
            Span::styled(
                format!("   {} of {} protocols", matches.len(), entries.len()),
                app.styles.dimmed,
            ),
        ]);
        let visible = rows[0].height.saturating_sub(1) as usize;
        let offset = if matches.is_empty() || visible == 0 {
            0
        } else {
            // Keep the selection inside the window, biased to show context
            // above it once we are scrolled down.
            selected.saturating_sub(visible.saturating_sub(1))
        };

        let mut list = vec![header];
        if matches.is_empty() {
            list.push(Line::from(Span::styled(
                "  (no protocol matches that filter)",
                app.styles.dimmed,
            )));
        }
        let mut hit_offsets: Vec<u16> = Vec::new();
        for (index, entry) in matches.iter().enumerate().skip(offset).take(visible) {
            // Absolute index, so a click after scrolling selects what was
            // clicked rather than the same slot in an unscrolled list.
            while hit_offsets.len() < index {
                hit_offsets.push(u16::MAX);
            }
            hit_offsets.push(list.len() as u16);
            let style = if index == *selected {
                app.styles.selected
            } else {
                app.styles.normal
            };
            let badge_style = match entry.state {
                crate::protocol::metadata::DevelopmentState::Beta
                | crate::protocol::metadata::DevelopmentState::Stable => app.styles.success,
                _ => app.styles.warning,
            };
            let kind_style = match entry.kind {
                crate::tui::app::Section::Servers => app.styles.server,
                crate::tui::app::Section::Clients => app.styles.client,
            };
            list.push(Line::from(vec![
                Span::styled(format!("  {:<18}", entry.name), style),
                Span::styled(format!("{:<8}", entry.kind_label()), kind_style),
                Span::styled(format!("{:<12}", entry.badge()), badge_style),
                Span::styled(
                    crate::utils::truncate_for_log(&entry.description, 70),
                    app.styles.dimmed,
                ),
            ]));
        }
        frame.render_widget(Paragraph::new(list), rows[0]);

        // Built before the hit registration below, because it is the last use
        // of the borrow on `app.modals` that `entries`/`filter` come from.
        let detail_lines = picker_detail_lines(app, entries, filter, *selected);

        push_row_hits(app, rows[0], &hit_offsets);

        let detail = Block::default()
            .borders(Borders::TOP)
            .border_style(app.styles.separator);
        let detail_inner = detail.inner(rows[1]);
        frame.render_widget(detail, rows[1]);
        frame.render_widget(
            Paragraph::new(detail_lines).wrap(Wrap { trim: false }),
            detail_inner,
        );
        return;
    }

    // The text editor is a live widget rather than static lines.
    if let Some(Modal::TextEditor { editor, .. }) = app.modals.last() {
        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Length(1),
                ratatui::layout::Constraint::Min(1),
                ratatui::layout::Constraint::Length(1),
                ratatui::layout::Constraint::Length(1),
            ])
            .split(inner);
        frame.render_widget(
            Paragraph::new(Span::styled(editor.help.clone(), app.styles.dimmed)),
            rows[0],
        );
        frame.render_widget(&editor.textarea, rows[1]);
        let error = editor.error.clone();
        if let Some(error) = error {
            frame.render_widget(
                Paragraph::new(Span::styled(error, app.styles.error)),
                rows[2],
            );
        }
        // Tab reaches these from the text; they are also clickable. Accepting
        // an edit must not be knowledge-gated on a chord.
        let buttons = editor.buttons();
        let focused = editor.focused_action();
        draw_button_row(frame, app, rows[3], &buttons, focused);
        return;
    }

    // The confirm dialog gets real Yes/No buttons (clickable; y/n/Enter/Esc
    // still work and stay the fast path).
    if let Some(Modal::Confirm { .. }) = app.modals.last() {
        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Min(2),
                ratatui::layout::Constraint::Length(1),
            ])
            .split(inner);
        frame.render_widget(
            Paragraph::new(body_lines).wrap(Wrap { trim: false }),
            rows[0],
        );
        draw_button_row(
            frame,
            app,
            rows[1],
            &[
                crate::tui::hit::ModalAction::ConfirmYes,
                crate::tui::hit::ModalAction::ConfirmNo,
            ],
            None,
        );
        return;
    }

    let paragraph = Paragraph::new(body_lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(paragraph, inner);
}

/// A modal body as pre-split rows: one `Line` per terminal row (nothing here
/// is wrapped by ratatui, so the row count is known), the row each selectable
/// item starts on (for hit-testing), and the first and one-past-last row of
/// what has focus (kept in view when the body is taller than the box).
struct ScrolledBody<'a> {
    lines: Vec<Line<'a>>,
    offsets: Vec<u16>,
    selection: (u16, u16),
}

/// Draw a body that scrolls to its selection, an error pinned above the
/// buttons, and the buttons, in `area`; say on `rect`'s top edge when there
/// are rows above or below the view.
///
/// The instance form, the composer and the routing draft all draw through
/// this. The error sits outside the scrolled rows because it answers the
/// button just pressed: it must be on screen whatever has focus and however
/// many fields there are. It takes at most half of what the buttons leave.
#[allow(clippy::too_many_arguments)]
fn draw_scrolled(
    frame: &mut Frame,
    app: &mut DashboardApp,
    rect: Rect,
    area: Rect,
    body: ScrolledBody<'_>,
    error: Option<&str>,
    buttons: &[crate::tui::hit::ModalAction],
    focused: Option<crate::tui::hit::ModalAction>,
) {
    let error_rows: Vec<String> = error
        .map(|e| crate::tui::wrap::wrap(&format!("✗ {e}"), area.width as usize))
        .unwrap_or_default();
    let error_height = (error_rows.len() as u16).min(area.height.saturating_sub(3) / 2);
    let rows = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Min(2),
            ratatui::layout::Constraint::Length(error_height),
            ratatui::layout::Constraint::Length(1),
        ])
        .split(area);
    let ScrolledBody {
        lines,
        offsets,
        selection: (top, bottom),
    } = body;
    // Scroll so the selection is in view, its top row first when it is
    // taller than the view.
    let viewport = rows[0].height;
    let mut scroll = bottom.saturating_sub(viewport);
    if top < scroll {
        scroll = top;
    }
    let total = lines.len() as u16;
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), rows[0]);
    for (index, offset) in offsets.iter().enumerate() {
        if *offset < scroll || *offset - scroll >= viewport {
            continue;
        }
        app.hits.push(
            Rect {
                x: rows[0].x,
                y: rows[0].y + (*offset - scroll),
                width: rows[0].width,
                height: 1,
            },
            HitTarget::ModalRow(index),
        );
    }
    let above = scroll > 0;
    let below = total > scroll + viewport;
    if above || below {
        let hint = match (above, below) {
            (true, true) => " ↑↓ more fields ",
            (true, false) => " ↑ more fields ",
            _ => " ↓ more fields ",
        };
        let width = (hint.chars().count() as u16).min(rect.width.saturating_sub(2));
        frame.render_widget(
            Paragraph::new(Span::styled(hint, app.styles.dimmed)),
            Rect {
                x: rect.x + rect.width.saturating_sub(width + 1),
                y: rect.y,
                width,
                height: 1,
            },
        );
    }
    if error_height > 0 {
        let lines: Vec<Line> = error_rows
            .into_iter()
            .take(error_height as usize)
            .map(|row| Line::from(Span::styled(row, app.styles.error)))
            .collect();
        frame.render_widget(Paragraph::new(lines), rows[1]);
    }
    draw_button_row(frame, app, rows[2], buttons, focused);
}

/// The end of what is being typed into a `room`-cell value column, with the
/// cursor, so the part being edited stays visible however long the value is.
fn typed_tail(typed: &str, room: usize) -> String {
    use ratatui::style::Style;
    let typed = format!("{typed}_");
    if crate::tui::wrap::cells(&typed) <= room || room <= 1 {
        return typed;
    }
    let span = Span::raw(typed.as_str());
    let graphemes: Vec<&str> = span
        .styled_graphemes(Style::default())
        .map(|g| g.symbol)
        .collect();
    let mut used = 0usize;
    let mut start = graphemes.len();
    while start > 0 {
        let w = crate::tui::wrap::cells(graphemes[start - 1]);
        if used + w > room - 1 {
            break;
        }
        used += w;
        start -= 1;
    }
    format!("…{}", graphemes[start..].concat())
}

/// Rows of `text` wrapped to `width` cells after `indent`, each in `style`.
fn wrapped<'a>(
    text: &str,
    indent: &str,
    width: usize,
    style: ratatui::style::Style,
) -> Vec<Line<'a>> {
    let room = width.saturating_sub(crate::tui::wrap::cells(indent)).max(1);
    crate::tui::wrap::wrap(text, room)
        .into_iter()
        .map(|row| Line::from(Span::styled(format!("{indent}{row}"), style)))
        .collect()
}

/// Detail for the highlighted protocol, rendered in a fixed pane so the list
/// above it never moves.
/// Register one clickable row per selectable item.
///
/// Modals used to push only their outer body and their buttons, so clicking a
/// field, a protocol or an action did nothing at all — the list looked
/// interactive and was not. `offsets[i]` is the line the i-th item was drawn
/// on, relative to `area`.
fn push_row_hits(app: &mut DashboardApp, area: ratatui::layout::Rect, offsets: &[u16]) {
    for (index, offset) in offsets.iter().enumerate() {
        if *offset >= area.height {
            break;
        }
        app.hits.push(
            ratatui::layout::Rect {
                x: area.x,
                y: area.y + offset,
                width: area.width,
                height: 1,
            },
            HitTarget::ModalRow(index),
        );
    }
}

/// Draw a row of modal buttons, registering each as a hit target.
fn draw_button_row(
    frame: &mut ratatui::Frame,
    app: &mut DashboardApp,
    area: ratatui::layout::Rect,
    buttons: &[crate::tui::hit::ModalAction],
    focused: Option<crate::tui::hit::ModalAction>,
) {
    let mut spans: Vec<Span> = Vec::new();
    let mut x = area.x;
    for action in buttons {
        let label = action.label();
        let width = label.chars().count() as u16;
        if x + width > area.x + area.width {
            break;
        }
        spans.push(Span::styled(
            label,
            if focused == Some(*action) {
                app.styles.selected
            } else {
                app.styles.button
            },
        ));
        spans.push(Span::raw(" "));
        app.hits.push(
            ratatui::layout::Rect {
                x,
                y: area.y,
                width,
                height: 1,
            },
            HitTarget::ModalActionButton(*action),
        );
        x += width + 1;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn picker_detail_lines<'a>(
    app: &DashboardApp,
    entries: &[crate::tui::modal::protocol_picker::ProtocolEntry],
    filter: &str,
    selected: usize,
) -> Vec<Line<'a>> {
    use crate::tui::modal::protocol_picker;
    let matches = protocol_picker::filter(entries, filter);
    let Some(entry) = matches.get(selected) else {
        return vec![Line::from(Span::styled(
            "(no protocol selected)",
            app.styles.dimmed,
        ))];
    };

    let mut lines = vec![Line::from(vec![
        Span::styled(entry.name.clone(), app.styles.accent),
        Span::styled(format!(" {}", entry.kind_label()), app.styles.normal),
        Span::styled(format!("  {}", entry.badge()), app.styles.dimmed),
    ])];
    lines.push(Line::from(Span::styled(
        entry.description.clone(),
        app.styles.normal,
    )));
    lines.push(Line::from(Span::styled(
        match (entry.kind, &entry.default_port) {
            (crate::tui::app::Section::Clients, _) => {
                "asks for the address to connect to".to_string()
            }
            (_, Some(default)) => match (default.well_known, default.fallback) {
                (Some(port), None) => format!("starts on well-known port {port}"),
                // Names the port it is passing over, and why.
                (Some(_), Some(_)) => default.describe(),
                (None, _) if default.port == 0 => "starts on an OS-assigned port (0)".to_string(),
                (None, _) => format!("starts on port {}", default.port),
            },
            (_, None) => "binds no port — an interface or a local path".to_string(),
        },
        app.styles.dimmed,
    )));
    if let Some(note) = &entry.privilege_note {
        lines.push(Line::from(Span::styled(
            format!("⚠ {note}"),
            app.styles.warning,
        )));
    }
    if let Some(notes) = &entry.notes {
        lines.push(Line::from(Span::styled(
            crate::utils::truncate_for_log(notes, 200),
            app.styles.dimmed,
        )));
    }
    lines
}

/// The form's fields as one row each, the selected field's help wrapped
/// beneath it; the row each field starts on (for hit-testing); and the first
/// and one-past-last row of the selected field with its help (for scrolling).
fn form_lines_with_offsets<'a>(
    app: &DashboardApp,
    form: &crate::tui::modal::form::FormModel,
    width: u16,
) -> ScrolledBody<'a> {
    use crate::tui::rail::fit;
    let width = width as usize;
    let mut offsets = Vec::with_capacity(form.fields.len());
    let mut lines = Vec::new();
    let mut selected_rows = (0u16, 0u16);
    for (index, field) in form.fields.iter().enumerate() {
        let top = lines.len() as u16;
        offsets.push(top);
        let is_selected = index == form.selected;
        let marker = if is_selected { "▸ " } else { "  " };
        let label_style = if is_selected {
            app.styles.accent
        } else {
            app.styles.normal
        };
        let mut label = format!(
            "{:<22}",
            format!("{}{}", field.label, if field.required { " *" } else { "" })
        );
        // A long parameter name (`first_byte_timeout_secs`) fills the column;
        // keep a space between it and its value.
        if !label.ends_with(' ') {
            label.push(' ');
        }
        let room = width.saturating_sub(2 + crate::tui::wrap::cells(&label));
        let value_display = if is_selected && form.editing.is_some() {
            // The end of what is being typed, where the cursor is.
            typed_tail(form.editing.as_deref().unwrap_or(""), room)
        } else {
            let text = if field.value.is_empty() {
                field.placeholder.clone()
            } else if field.multiline {
                let first = field.value.lines().next().unwrap_or("");
                let extra = field.value.lines().count().saturating_sub(1);
                if extra > 0 {
                    format!("{first} … (+{extra} lines)")
                } else {
                    first.to_string()
                }
            } else if field.is_default() {
                // Says the value is the protocol's own, which is why it will not be submitted.
                format!("{}  (default)", field.value)
            } else {
                field.value.clone()
            };
            fit(&text, room)
        };
        let value_style = if field.value.is_empty() && form.editing.is_none() {
            app.styles.dimmed
        } else {
            app.styles.info
        };
        lines.push(Line::from(vec![
            Span::styled(marker, app.styles.accent),
            Span::styled(label, label_style),
            Span::styled(value_display, value_style),
        ]));
        if is_selected {
            lines.extend(wrapped(&field.help, "    ", width, app.styles.dimmed));
            selected_rows = (top, lines.len() as u16);
        }
    }
    ScrolledBody {
        lines,
        offsets,
        selection: selected_rows,
    }
}

/// The handler editor's kind control: one segment per way of answering, the
/// selected one inverted, every segment clickable.
fn draw_kind_segments(
    frame: &mut ratatui::Frame,
    app: &mut DashboardApp,
    area: ratatui::layout::Rect,
    kind: crate::tui::modal::routing::HandlerKind,
    control_focused: bool,
) {
    use crate::tui::modal::routing::HandlerKind;

    let label = "respond with  ";
    let mut spans: Vec<Span> = vec![Span::styled(
        label,
        if control_focused {
            app.styles.accent
        } else {
            app.styles.normal
        },
    )];
    let mut x = area.x + label.chars().count() as u16;
    for candidate in HandlerKind::ALL {
        let text = format!(" {} ", candidate.label());
        let width = text.chars().count() as u16;
        if x + width > area.x + area.width {
            break;
        }
        let style = if candidate == kind {
            app.styles.selected
        } else {
            app.styles.button
        };
        spans.push(Span::styled(text, style));
        spans.push(Span::raw(" "));
        app.hits.push(
            ratatui::layout::Rect {
                x,
                y: area.y,
                width,
                height: 1,
            },
            HitTarget::ModalActionButton(crate::tui::hit::ModalAction::DraftKind(candidate)),
        );
        x += width + 1;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The draft editor's body, `width` cells wide: the pattern chooser, then the
/// selected kind's own fields, with the rows of whatever has focus as the
/// selection to keep in view. Every row here is a Tab stop; the `▸` marker
/// tracks focus. The draft's error is not here: the caller pins it above the
/// buttons.
fn draft_body_lines<'a>(
    app: &DashboardApp,
    model: &crate::tui::modal::routing::RoutingModel,
    draft: &crate::tui::modal::routing::HandlerDraft,
    width: u16,
) -> ScrolledBody<'a> {
    use crate::tui::modal::routing::{DraftFocus, HandlerDraft, HandlerKind};
    use crate::tui::rail::fit;

    let width = width as usize;
    let mut lines: Vec<Line<'a>> = Vec::new();
    let mut selection = (0u16, 0u16);
    let marker = |focused: bool| Span::styled(if focused { "▸ " } else { "  " }, app.styles.accent);
    let label = |text: &str, focused: bool| {
        Span::styled(
            format!("{text:<18}"),
            if focused {
                app.styles.accent
            } else {
                app.styles.normal
            },
        )
    };
    // What is left for a value after the marker and the label column.
    let room = width.saturating_sub(2 + 18);
    // One `▸ label  value` row; the selection when it has focus.
    let field_row = |lines: &mut Vec<Line<'a>>,
                     selection: &mut (u16, u16),
                     name: &str,
                     focused: bool,
                     value: String,
                     style: ratatui::style::Style| {
        let top = lines.len() as u16;
        lines.push(Line::from(vec![
            marker(focused),
            label(name, focused),
            Span::styled(value, style),
        ]));
        if focused {
            *selection = (top, top + 1);
        }
    };

    // --- when ---
    let pattern_focused = draft.focus == DraftFocus::Pattern;
    let pattern_display = if draft.editing.is_some() && pattern_focused {
        typed_tail(draft.editing.as_deref().unwrap_or(""), room)
    } else if draft.pattern == "*" {
        "* (every event)".to_string()
    } else {
        fit(&draft.pattern, room)
    };
    field_row(
        &mut lines,
        &mut selection,
        "when event",
        pattern_focused,
        pattern_display,
        app.styles.info,
    );
    if pattern_focused && draft.editing.is_none() {
        // The chooser: ←/→ walks these; Enter types a pattern by hand. The
        // selection narrows to the choice that is picked, so walking a long
        // list keeps it in view.
        let choices = HandlerDraft::pattern_choices(&model.event_ids);
        for choice in choices.iter().take(12) {
            let selected = *choice == draft.pattern;
            let description = if choice == "*" {
                "matches every event".to_string()
            } else {
                model
                    .event_ids
                    .iter()
                    .find(|(id, _)| id == choice)
                    .map(|(_, d)| d.clone())
                    .unwrap_or_default()
            };
            let name = format!("      {choice:<28}");
            let rest = width.saturating_sub(crate::tui::wrap::cells(&name) + 1);
            if selected {
                let top = lines.len() as u16;
                selection = (top, top + 1);
            }
            lines.push(Line::from(vec![
                Span::styled(
                    name,
                    if selected {
                        app.styles.selected
                    } else {
                        app.styles.dimmed
                    },
                ),
                Span::styled(format!(" {}", fit(&description, rest)), app.styles.dimmed),
            ]));
        }
    }
    lines.push(Line::from(""));

    // --- the kind's own fields ---
    match draft.kind {
        HandlerKind::Static => {
            let focused = draft.focus == DraftFocus::Actions;
            field_row(
                &mut lines,
                &mut selection,
                "response actions",
                focused,
                fit(
                    &if draft.actions.is_empty() {
                        "(Enter opens the JSON editor, prefilled with a working example)"
                            .to_string()
                    } else {
                        format!("{} action(s) — Enter edits, d deletes", draft.actions.len())
                    },
                    room,
                ),
                if draft.actions.is_empty() {
                    app.styles.dimmed
                } else {
                    app.styles.info
                },
            );
            for (index, action) in draft.actions.iter().enumerate() {
                let name = action
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("(no type)");
                let chosen = focused && index == draft.selected_action;
                if chosen {
                    let top = lines.len() as u16;
                    selection = (top, top + 1);
                }
                // The name once, then the fields it carries: repeating the
                // `type` inside the JSON spent the row on what it already said.
                let mut fields = action.clone();
                if let Some(object) = fields.as_object_mut() {
                    object.remove("type");
                }
                lines.push(Line::from(Span::styled(
                    fit(&format!("      {name}  {fields}"), width),
                    if chosen {
                        app.styles.selected
                    } else {
                        app.styles.info
                    },
                )));
            }
        }
        HandlerKind::Script => {
            let language_focused = draft.focus == DraftFocus::Language;
            field_row(
                &mut lines,
                &mut selection,
                "language",
                language_focused,
                format!("◂ {} ▸", draft.language),
                app.styles.info,
            );
            let code_focused = draft.focus == DraftFocus::Code;
            let top = lines.len() as u16;
            field_row(
                &mut lines,
                &mut selection,
                "script code",
                code_focused,
                if draft.code.is_empty() {
                    "(Enter opens the editor)".to_string()
                } else {
                    format!("{} line(s) — Enter edits", draft.code.lines().count())
                },
                if draft.code.is_empty() {
                    app.styles.dimmed
                } else {
                    app.styles.info
                },
            );
            for line in draft.code.lines().take(6) {
                lines.push(Line::from(Span::styled(
                    fit(&format!("      {line}"), width),
                    app.styles.dimmed,
                )));
            }
            if code_focused {
                selection = (top, lines.len() as u16);
            }
            let resident_focused = draft.focus == DraftFocus::Resident;
            field_row(
                &mut lines,
                &mut selection,
                "resident",
                resident_focused,
                fit(
                    if draft.resident {
                        "[x] one process stays alive and keeps state between events"
                    } else {
                        "[ ] a fresh interpreter per event (stateless)"
                    },
                    room,
                ),
                app.styles.info,
            );
        }
        HandlerKind::Llm => {
            let focused = draft.focus == DraftFocus::Instruction;
            field_row(
                &mut lines,
                &mut selection,
                "instruction",
                focused,
                if draft.instruction.is_empty() {
                    "(Enter opens the editor)".to_string()
                } else {
                    fit(&draft.instruction, room)
                },
                if draft.instruction.is_empty() {
                    app.styles.dimmed
                } else {
                    app.styles.info
                },
            );
        }
        HandlerKind::Manual => {
            let focused = draft.focus == DraftFocus::Timeout;
            let timeout_display = if draft.editing.is_some() && focused {
                typed_tail(draft.editing.as_deref().unwrap_or(""), room)
            } else {
                format!("{} seconds", draft.timeout_secs)
            };
            let top = lines.len() as u16;
            field_row(
                &mut lines,
                &mut selection,
                "wait for me",
                focused,
                timeout_display,
                app.styles.info,
            );
            lines.extend(wrapped(
                "Each matched event appears under the instance as “⚠ waiting for YOUR \
                 answer”. No answer in time fails closed — the peer gets an error, never an \
                 invented success.",
                "      ",
                width,
                app.styles.dimmed,
            ));
            if focused {
                selection = (top, lines.len() as u16);
            }
        }
    }
    ScrolledBody {
        lines,
        offsets: Vec::new(),
        selection,
    }
}

/// A pending intercept: what arrived and the answer composed so far.
fn intercept_lines<'a>(
    app: &DashboardApp,
    model: &crate::tui::modal::intercept::InterceptModel,
) -> Vec<Line<'a>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("event      ", app.styles.dimmed),
            Span::styled(model.event_type.clone(), app.styles.accent),
        ]),
        Line::from(vec![
            Span::styled("what       ", app.styles.dimmed),
            Span::styled(
                crate::utils::sanitize::line_field(&model.description),
                app.styles.normal,
            ),
        ]),
    ];
    // Near the top, so a long payload cannot push it out of a short box: the
    // operator has this long, and then the peer is refused without them.
    if let Some(deadline) = model.deadline_unix_ms {
        let left = deadline.saturating_sub(crate::state::intercepts::now_unix_ms()) / 1000;
        lines.push(Line::from(vec![
            Span::styled("deadline   ", app.styles.dimmed),
            Span::styled(
                if left == 0 {
                    "failing closed now".to_string()
                } else {
                    format!(
                        "fails closed in {}",
                        crate::tui::metrics::human_duration(left)
                    )
                },
                if left < 60 {
                    app.styles.error
                } else {
                    app.styles.warning
                },
            ),
            Span::styled(" if nobody answers", app.styles.dimmed),
        ]));
    }
    if let Some(error) = &model.error {
        lines.push(Line::from(Span::styled(
            format!("✗ {error}"),
            app.styles.error,
        )));
    }
    if let Some(data) = &model.event_data {
        lines.push(Line::from(Span::styled("payload", app.styles.dimmed)));
        // The peer's own bytes: `serde_json` escapes C0 inside a string but writes DEL and C1
        // (U+009B is an 8-bit CSI) raw, and a `Paragraph` hands them to the terminal.
        let pretty = crate::utils::sanitize::json_text(
            &serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string()),
        );
        for line in pretty.lines().take(20) {
            lines.push(Line::from(Span::styled(
                format!("  {line}"),
                app.styles.info,
            )));
        }
        let hidden = pretty.lines().count().saturating_sub(20);
        if hidden > 0 {
            lines.push(Line::from(Span::styled(
                format!("  … {hidden} more line(s)"),
                app.styles.dimmed,
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Compose answer…      ", app.styles.normal),
        Span::styled(
            format!(
                "pick one of {}'s {} action(s) and fill in its fields",
                model.protocol,
                model.vocabulary.len()
            ),
            app.styles.dimmed,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Answer with nothing  ", app.styles.normal),
        Span::styled(
            "acknowledge and send no reply (fine for a connect event)",
            app.styles.dimmed,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Fail closed          ", app.styles.normal),
        Span::styled(
            "refuse: the peer gets the protocol's error reply now",
            app.styles.dimmed,
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "The connection is waiting on you; Esc keeps it waiting.",
        app.styles.dimmed,
    )));
    lines
}

/// The composer's rows, `width` cells wide: the actions while choosing, the
/// parameters once chosen, each selectable row's offset, and the selection —
/// the highlighted action, or the selected field with its help — to keep in
/// view. The validation error is not here: the caller pins it above the
/// buttons.
fn composer_lines_with_offsets<'a>(
    app: &DashboardApp,
    composer: &crate::tui::modal::composer::ComposerModel,
    width: u16,
) -> ScrolledBody<'a> {
    use crate::tui::rail::fit;
    let width = width as usize;
    let mut offsets = Vec::new();
    let mut lines = Vec::new();
    let mut selection = (0u16, 0u16);
    match composer.chosen {
        None => {
            lines.extend(wrapped(
                &format!("{} actions — pick one:", composer.protocol),
                "",
                width,
                app.styles.dimmed,
            ));
            lines.push(Line::from(""));
            for (index, action) in composer.actions.iter().enumerate() {
                let top = lines.len() as u16;
                offsets.push(top);
                let style = if index == composer.selected {
                    selection = (top, top + 1);
                    app.styles.selected
                } else {
                    app.styles.normal
                };
                let name = format!("  {:<24}", action.name);
                let room = width.saturating_sub(crate::tui::wrap::cells(&name));
                lines.push(Line::from(vec![
                    Span::styled(name, style),
                    Span::styled(fit(&action.description, room), app.styles.dimmed),
                ]));
            }
        }
        Some(index) => {
            let action = &composer.actions[index];
            lines.extend(wrapped(
                &format!("{} — {}", action.name, action.description),
                "",
                width,
                app.styles.accent,
            ));
            lines.push(Line::from(""));
            if let Some(raw) = &composer.raw_json {
                let top = lines.len() as u16;
                lines.extend(wrapped(
                    "raw JSON — press [ Raw JSON ] again to go back to fields:",
                    "",
                    width,
                    app.styles.dimmed,
                ));
                selection = (top, lines.len() as u16);
                for line in raw.lines() {
                    lines.extend(wrapped(line, "", width, app.styles.info));
                }
            } else {
                for (i, field) in composer.fields.iter().enumerate() {
                    let top = lines.len() as u16;
                    offsets.push(top);
                    let is_selected = i == composer.selected;
                    let marker = if is_selected { "▸ " } else { "  " };
                    let label = format!(
                        "{:<20}",
                        format!("{}{}", field.name, if field.required { " *" } else { "" })
                    );
                    let room = width.saturating_sub(2 + crate::tui::wrap::cells(&label));
                    let value = if is_selected && composer.editing.is_some() {
                        typed_tail(composer.editing.as_deref().unwrap_or(""), room)
                    } else if field.kind == crate::tui::modal::composer::FieldKind::Bool {
                        // A checkbox: Enter or Space flips it.
                        if field.value.trim() == "true" {
                            "[x] true".to_string()
                        } else {
                            "[ ] false".to_string()
                        }
                    } else if field.kind == crate::tui::modal::composer::FieldKind::Choice {
                        // A radio group: Enter/Space/←/→ cycle the pick. An
                        // optional field with nothing picked shows every value
                        // unmarked, exactly like the unticked checkbox above.
                        fit(
                            &field
                                .choices
                                .iter()
                                .map(|choice| {
                                    if field.value.trim() == choice {
                                        format!("(x) {choice}")
                                    } else {
                                        format!("( ) {choice}")
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join("  "),
                            room,
                        )
                    } else if field.value.is_empty() {
                        fit(&field.placeholder, room)
                    } else {
                        fit(&field.value, room)
                    };
                    lines.push(Line::from(vec![
                        Span::styled(marker, app.styles.accent),
                        Span::styled(
                            label,
                            if is_selected {
                                app.styles.accent
                            } else {
                                app.styles.normal
                            },
                        ),
                        Span::styled(
                            value,
                            if field.value.is_empty() {
                                app.styles.dimmed
                            } else {
                                app.styles.info
                            },
                        ),
                    ]));
                    if is_selected {
                        lines.extend(wrapped(&field.help, "    ", width, app.styles.dimmed));
                        selection = (top, lines.len() as u16);
                    }
                }
                if composer.fields.is_empty() {
                    lines.extend(wrapped(
                        "(this action takes no parameters — Tab to [ Send ])",
                        "",
                        width,
                        app.styles.dimmed,
                    ));
                }
            }
        }
    }
    ScrolledBody {
        lines,
        offsets,
        selection,
    }
}

fn band_detail_lines<'a>(app: &DashboardApp, key: crate::tui::app::UiKey) -> Vec<Line<'a>> {
    use crate::tui::app::UiKey;
    let mut lines = Vec::new();
    let mut push = |text: String, style| lines.push(Line::from(Span::styled(text, style)));
    match key {
        UiKey::Server(id) => {
            if let Some(row) = app.snapshot.servers.iter().find(|s| s.id == id) {
                push(format!("protocol   {}", row.protocol), app.styles.normal);
                push(
                    format!(
                        "address    {}",
                        row.local_addr
                            .clone()
                            .unwrap_or_else(|| format!(":{}", row.port))
                    ),
                    app.styles.normal,
                );
                push(format!("status     {}", row.status), app.styles.normal);
                push(String::new(), app.styles.normal);
                push("instruction".to_string(), app.styles.title);
                for line in row.instruction.lines() {
                    push(
                        format!("  {}", crate::utils::sanitize::line_field(line)),
                        app.styles.dimmed,
                    );
                }
                push(String::new(), app.styles.normal);
                push("startup_params".to_string(), app.styles.title);
                let params = row
                    .startup_params
                    .as_ref()
                    .map(|p| {
                        crate::utils::sanitize::json_text(
                            &serde_json::to_string_pretty(p).unwrap_or_default(),
                        )
                    })
                    .unwrap_or_else(|| "(none)".to_string());
                for line in params.lines() {
                    push(format!("  {line}"), app.styles.dimmed);
                }
                push(String::new(), app.styles.normal);
                push("routing".to_string(), app.styles.title);
                let routing = row
                    .routing
                    .as_ref()
                    .map(|r| {
                        crate::utils::sanitize::json_text(
                            &serde_json::to_string_pretty(&r.handlers).unwrap_or_default(),
                        )
                    })
                    .unwrap_or_else(|| "(none — every event goes to the LLM)".to_string());
                for line in routing.lines() {
                    push(format!("  {line}"), app.styles.dimmed);
                }
            }
        }
        UiKey::Client(id) => {
            if let Some(row) = app.snapshot.clients.iter().find(|c| c.id == id) {
                push(format!("protocol   {}", row.protocol), app.styles.normal);
                push(format!("remote     {}", row.remote_addr), app.styles.normal);
                push(format!("status     {}", row.status), app.styles.normal);
                push(
                    format!(
                        "send       {}",
                        match row.send_state {
                            crate::tui::projection::SendState::Ready => "available (press n)",
                            crate::tui::projection::SendState::NotConnected => "not connected",
                            crate::tui::projection::SendState::ProtocolUnsupported =>
                                "this protocol has no command channel yet",
                        }
                    ),
                    app.styles.dimmed,
                );
                push(String::new(), app.styles.normal);
                push("instruction".to_string(), app.styles.title);
                for line in row.instruction.lines() {
                    push(
                        format!("  {}", crate::utils::sanitize::line_field(line)),
                        app.styles.dimmed,
                    );
                }
                push(String::new(), app.styles.normal);
                push("routing".to_string(), app.styles.title);
                let routing = row
                    .routing
                    .as_ref()
                    .map(|r| {
                        crate::utils::sanitize::json_text(
                            &serde_json::to_string_pretty(&r.handlers).unwrap_or_default(),
                        )
                    })
                    .unwrap_or_else(|| "(none — every event goes to the LLM)".to_string());
                for line in routing.lines() {
                    push(format!("  {line}"), app.styles.dimmed);
                }
            }
        }
    }
    lines
}
