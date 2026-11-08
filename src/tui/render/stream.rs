//! The stream: activity and conversation in one pane, newest at the bottom.
//!
//! Machine events (instances, peers, requests, questions parked for you, log
//! lines) and the conversation (what you typed, what the model reasoned and
//! answered, command output) are one timeline. Conversation entries wrap;
//! event lines are one row each and truncate, since Enter opens what they
//! point at — except failures, errors and warnings, which wrap: they usually
//! point at nothing, and their text is the explanation.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::activity::{ActivityEntry, ActivityFeed, ActivityKind};
use crate::tui::app::{DashboardApp, Focus, UiKey};
use crate::tui::chat::{EntryKind, ScrollPos};
use crate::tui::hit::HitTarget;
use crate::tui::rail::fit;

use super::pane_block;

/// The entries the pane shows, under the current filters.
pub fn visible_entries(app: &DashboardApp) -> Vec<&ActivityEntry> {
    let level = app.core.log_level;
    let only = if app.activity.only_selected {
        app.cursor_key()
    } else {
        None
    };
    app.activity
        .entries
        .iter()
        .filter(|e| ActivityFeed::passes(e, level, only))
        .collect()
}

pub fn draw(frame: &mut Frame, app: &mut DashboardApp, area: Rect) {
    if area.height < 3 {
        return;
    }
    let focused = app.focus == Focus::Stream;
    let mut title = vec![Span::styled(" ACTIVITY & CHAT ", app.styles.title)];
    if app.activity.only_selected {
        if let Some(key) = app.cursor_key() {
            if let Some(instance) = app.instance(key) {
                title.push(Span::styled(
                    format!("· only {} ", instance.tag()),
                    app.styles.warning,
                ));
            }
        }
    }
    title.push(Span::styled(
        format!("· log:{} ", app.core.log_level.as_str().to_lowercase()),
        app.styles.dimmed,
    ));
    let hint = if focused {
        " ↑↓ lines · Enter open · f filter · Esc "
    } else {
        " PageUp scrolls "
    };
    let block = pane_block(app, focused)
        .title(Line::from(title))
        .title_bottom(Span::styled(hint, app.styles.dimmed));
    let mut inner = block.inner(area);
    frame.render_widget(block, area);
    app.hits.push(inner, HitTarget::Stream);
    // Unscoped work (such as a global scheduled task) has no connection card.
    // Keep its current status above the input even while the timeline is scrolled.
    let background: Vec<_> = app
        .snapshot
        .llm_activity
        .iter()
        .filter(|work| {
            crate::tui::llm_activity::owner(work).is_none()
                && !matches!(
                    work.source,
                    crate::state::app_state::ConversationSource::User
                )
        })
        .collect();
    if let Some(work) = background.first().filter(|_| inner.height > 0) {
        let extra = if background.len() > 1 {
            format!(" (+{} more)", background.len() - 1)
        } else {
            String::new()
        };
        let text = format!(
            "{} {} {}{extra}",
            app.spinner(),
            work.source.display_label(),
            crate::tui::llm_activity::label(work)
        );
        frame.render_widget(
            Paragraph::new(fit(&text, inner.width as usize)).style(app.styles.reasoning),
            Rect {
                y: inner.y + inner.height - 1,
                height: 1,
                ..inner
            },
        );
        inner.height -= 1;
    }
    if inner.height == 0 {
        return;
    }

    let entries = visible_entries(app);
    if entries.is_empty() {
        let hint = if app.activity.entries.is_empty() {
            "Nothing yet. Instances starting, peers connecting, every request and its \
             answer, anything waiting on you, and the conversation all land here."
        } else {
            "(nothing matches the current filter)"
        };
        frame.render_widget(
            Paragraph::new(hint)
                .style(app.styles.dimmed)
                .wrap(ratatui::widgets::Wrap { trim: true }),
            Rect {
                x: inner.x + 1,
                y: inner.y + 1.min(inner.height.saturating_sub(1)),
                width: inner.width.saturating_sub(2),
                height: inner.height.saturating_sub(1).max(1),
            },
        );
        return;
    }

    // Every entry becomes one or more rows; the scroll is in rows.
    let width = inner.width as usize;
    let cursor = if focused {
        app.activity
            .cursor
            .and_then(|seq| entries.iter().position(|entry| entry.seq >= seq))
    } else {
        None
    };
    let mut rows: Vec<(usize, Line)> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let is_cursor = cursor == Some(index);
        for line in entry_lines(app, entry, width, is_cursor) {
            rows.push((index, line));
        }
    }
    let total = rows.len();
    let viewport = inner.height as usize;
    let max_offset = total.saturating_sub(viewport);
    let mut offset = match app.activity.scroll {
        ScrollPos::Follow => max_offset,
        ScrollPos::Up(up) => max_offset.saturating_sub(up),
    };
    if app.activity.scroll != ScrollPos::Follow {
        if let Some((seq, line)) = app.activity.scroll_anchor {
            if let Some(first) = rows
                .iter()
                .position(|(index, _)| entries[*index].seq >= seq)
            {
                let same = entries[rows[first].0].seq == seq;
                let count = rows[first..]
                    .iter()
                    .take_while(|(index, _)| *index == rows[first].0)
                    .count();
                offset = (first
                    + if same {
                        line.min(count.saturating_sub(1))
                    } else {
                        0
                    })
                .min(max_offset);
            }
        }
    }
    if let Some(cursor) = cursor {
        let first = rows.iter().position(|(i, _)| *i == cursor).unwrap_or(0);
        let last = rows
            .iter()
            .rposition(|(i, _)| *i == cursor)
            .unwrap_or(first);
        if first < offset {
            offset = first;
        } else if last >= offset + viewport {
            offset = last + 1 - viewport;
        }
    }

    let anchor = rows.get(offset).map(|(index, _)| {
        let first = rows
            .iter()
            .position(|(other, _)| other == index)
            .unwrap_or(offset);
        (entries[*index].seq, offset - first)
    });
    let selected_seq = cursor.map(|index| entries[index].seq);
    let shown = total.saturating_sub(offset).min(viewport);
    let pad = viewport - shown;
    let mut lines: Vec<Line> = Vec::with_capacity(viewport);
    for _ in 0..pad {
        lines.push(Line::from(""));
    }
    let mut hits: Vec<(Rect, HitTarget)> = Vec::new();
    for (screen_index, (entry_index, line)) in
        rows.into_iter().skip(offset).take(viewport).enumerate()
    {
        lines.push(line);
        hits.push((
            Rect {
                x: inner.x,
                y: inner.y + (pad + screen_index) as u16,
                width: inner.width,
                height: 1,
            },
            HitTarget::StreamRow(entries[entry_index].seq),
        ));
    }
    drop(entries);
    if focused {
        app.activity.cursor = selected_seq;
    }
    if app.activity.scroll != ScrollPos::Follow {
        app.activity.scroll_anchor = anchor;
        app.activity.scroll = ScrollPos::Up(max_offset.saturating_sub(offset));
    }
    for (rect, target) in hits {
        app.hits.push(rect, target);
    }
    frame.render_widget(Paragraph::new(lines), inner);

    if app.activity.unseen > 0 {
        let label = format!(" {} new ↓ ", app.activity.unseen);
        let label_width = (label.chars().count() as u16).min(inner.width);
        frame.render_widget(
            Paragraph::new(label).style(app.styles.selected),
            Rect {
                x: inner.x + inner.width.saturating_sub(label_width),
                y: inner.y + inner.height.saturating_sub(1),
                width: label_width,
                height: 1,
            },
        );
    }
}

fn kind_glyph_and_style(app: &DashboardApp, kind: ActivityKind) -> (&'static str, Style) {
    use crate::ui::app::LogLevel;
    match kind {
        ActivityKind::Log(LogLevel::Error) => ("✗ ", app.styles.error),
        ActivityKind::Log(LogLevel::Warn) => ("⚠ ", app.styles.warning),
        ActivityKind::Log(LogLevel::Info) => ("· ", app.styles.info),
        ActivityKind::Log(LogLevel::Debug) => ("○ ", app.styles.debug),
        ActivityKind::Log(LogLevel::Trace) => ("· ", app.styles.trace),
        ActivityKind::Lifecycle => ("◆ ", app.styles.success),
        ActivityKind::Peer => ("⇄ ", app.styles.connection),
        ActivityKind::Request => ("→ ", app.styles.normal),
        ActivityKind::Waiting => ("⚠ ", app.styles.error),
        ActivityKind::Failure => ("✗ ", app.styles.error),
        ActivityKind::Chat(EntryKind::User) => ("▶ ", app.styles.user),
        ActivityKind::Chat(EntryKind::Reasoning) => ("∴ ", app.styles.reasoning),
        ActivityKind::Chat(_) => ("  ", app.styles.normal),
    }
}

/// One entry's rows: an event is one truncated row, except a failure, an
/// error or a warning, which wraps under its own text; a conversation entry
/// is word-wrapped with a hanging indent. Nothing that explains a failure is
/// cut off.
fn entry_lines<'a>(
    app: &DashboardApp,
    entry: &ActivityEntry,
    width: usize,
    cursor: bool,
) -> Vec<Line<'a>> {
    let (glyph, style) = kind_glyph_and_style(app, entry.event.kind);
    let sel = |s: Style| if cursor { app.styles.selected } else { s };

    if let ActivityKind::Chat(_) = entry.event.kind {
        let body_width = width.saturating_sub(2).max(1);
        let mut rows = Vec::new();
        for (j, chunk) in crate::tui::wrap::wrap(&entry.event.text, body_width)
            .into_iter()
            .enumerate()
        {
            let prefix = if j == 0 { glyph } else { "  " };
            let filled = 2 + crate::tui::wrap::cells(&chunk);
            let mut spans = vec![
                Span::styled(prefix, sel(style)),
                Span::styled(chunk, sel(style)),
            ];
            if cursor && filled < width {
                spans.push(Span::styled(
                    " ".repeat(width - filled),
                    app.styles.selected,
                ));
            }
            rows.push(Line::from(spans));
        }
        return rows;
    }

    let tag_style = match entry.event.owner {
        Some(UiKey::Server(_)) => app.styles.server,
        Some(UiKey::Client(_)) => app.styles.client,
        None => app.styles.dimmed,
    };
    let time = format!("{} ", entry.time);
    let tag = if entry.event.tag.is_empty() {
        String::new()
    } else {
        format!("{:<9}", fit(&entry.event.tag, 9))
    };
    use crate::ui::app::LogLevel;
    let used = time.chars().count() + tag.chars().count() + glyph.chars().count();
    let room = width.saturating_sub(used);
    // An event is one row — except a failure, which wraps under its own text:
    // the reason a server would not start is the one line the operator has to
    // read whole, and at 80 columns a single row holds about 25 characters of it.
    let wraps = matches!(
        entry.event.kind,
        ActivityKind::Failure
            | ActivityKind::Log(LogLevel::Error)
            | ActivityKind::Log(LogLevel::Warn)
    );
    let texts = if wraps && room > 0 {
        crate::tui::wrap::wrap(&entry.event.text, room)
    } else {
        vec![fit(&entry.event.text, room)]
    };
    let mut lines = Vec::with_capacity(texts.len());
    for (index, text) in texts.into_iter().enumerate() {
        let filled = used + crate::tui::wrap::cells(&text);
        let mut spans = if index == 0 {
            vec![
                Span::styled(time.clone(), sel(app.styles.dimmed)),
                Span::styled(tag.clone(), sel(tag_style)),
                Span::styled(glyph, sel(style)),
            ]
        } else {
            vec![Span::styled(" ".repeat(used), sel(style))]
        };
        spans.push(Span::styled(text, sel(style)));
        if cursor && filled < width {
            spans.push(Span::styled(
                " ".repeat(width - filled),
                app.styles.selected,
            ));
        }
        lines.push(Line::from(spans));
    }
    lines
}
