//! Word wrapping in terminal cells.
//!
//! Every pane here is a `Paragraph` of pre-split lines, because the stream,
//! the cards and the forms need to know how many rows a piece of text takes
//! (to scroll, to hit-test, to keep a cursor visible) and ratatui 0.29 cannot
//! say how many rows its own `Wrap` produced. So text that must not be lost —
//! an error, a reply, a help line — is split here, at word boundaries where a
//! line has one, and each piece is one row.

use ratatui::style::Style;
use ratatui::text::Span;

/// Terminal cells `text` occupies (wide CJK = 2, combining marks = 0).
pub fn cells(text: &str) -> usize {
    Span::raw(text).width()
}

/// Split `text` into rows of at most `width` terminal cells.
///
/// Breaks after the last space that fits; a word longer than a whole row is
/// cut where the row ends. Every visible grapheme of the input appears in the
/// output exactly once, in order; only a space that falls exactly on a break
/// is dropped. Leading indentation is kept and never becomes a break of its
/// own. Embedded newlines start a new row. An empty input is one empty row.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    for line in text.split('\n') {
        wrap_line(line, width, &mut rows);
    }
    rows
}

fn wrap_line(line: &str, width: usize, rows: &mut Vec<String>) {
    let mut row = String::new();
    let mut used = 0usize;
    // Whether `row` holds anything but indentation yet.
    let mut has_text = false;
    // Byte offset in `row` just past the last space, and the cells used up to it.
    let mut last_break: Option<(usize, usize)> = None;
    let span = Span::raw(line);
    for styled in span.styled_graphemes(Style::default()) {
        let grapheme = styled.symbol;
        let w = cells(grapheme);
        let space = grapheme.chars().all(char::is_whitespace);
        if used + w > width && !row.is_empty() {
            if space {
                // The break falls on the space itself.
                rows.push(std::mem::take(&mut row));
                used = 0;
                has_text = false;
                last_break = None;
                continue;
            }
            match last_break {
                // Carry the partial word to the next row.
                Some((at, before)) if at < row.len() => {
                    let rest = row.split_off(at);
                    rows.push(std::mem::take(&mut row));
                    row = rest;
                    used -= before;
                }
                _ => {
                    rows.push(std::mem::take(&mut row));
                    used = 0;
                    has_text = false;
                }
            }
            last_break = None;
        }
        row.push_str(grapheme);
        used += w;
        if space {
            if has_text {
                last_break = Some((row.len(), used));
            }
        } else {
            has_text = true;
        }
    }
    rows.push(row);
}
