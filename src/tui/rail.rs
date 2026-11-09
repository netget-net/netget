//! The one-line instance summary: status glyph, id, protocol, address, live
//! peers, sparkline, driver badge. A card's header row is one of these.

use crate::tui::app::UiKey;
use crate::tui::driver::{driver_of, Driver};
use crate::tui::projection::{ClientRow, ServerRow};

/// How a piece of text should be coloured, resolved by the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Dim,
    Good,
    Warn,
    Bad,
    Accent,
    Server,
    Client,
    Title,
    Reasoning,
}

impl Driver {
    pub fn tone(&self) -> Tone {
        match self {
            Driver::Manual => Tone::Warn,
            Driver::Llm => Tone::Reasoning,
            Driver::Silent => Tone::Dim,
            Driver::Rules => Tone::Good,
        }
    }
}

/// Everything one instance line shows, before it is fitted to a width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceLine {
    pub key: UiKey,
    pub glyph: &'static str,
    pub glyph_tone: Tone,
    pub id: u32,
    pub protocol: String,
    /// `:8080` for a server, `→ host:port` for a client.
    pub target: String,
    /// `2⇄` live peers for a server; empty for a client.
    pub peers: String,
    pub driver: Driver,
    /// Requests parked for the human.
    pub waiting: usize,
    /// The error message when the instance is in an error state.
    pub error: Option<String>,
}

pub fn server_line(row: &ServerRow) -> InstanceLine {
    use crate::state::server::ServerStatus;
    let (glyph, glyph_tone, error) = match &row.status {
        ServerStatus::Running => ("●", Tone::Good, None),
        ServerStatus::Starting => ("◐", Tone::Warn, None),
        ServerStatus::Stopped => ("○", Tone::Dim, None),
        ServerStatus::Error(e) => ("✗", Tone::Bad, Some(e.clone())),
    };
    let live = row.conns.iter().filter(|c| c.active).count();
    InstanceLine {
        key: UiKey::Server(row.id),
        glyph,
        glyph_tone,
        id: row.id.as_u32(),
        protocol: row.protocol.to_lowercase(),
        target: row
            .local_addr
            .as_deref()
            .and_then(|a| a.rsplit_once(':').map(|(_, p)| format!(":{p}")))
            .unwrap_or_else(|| format!(":{}", row.port)),
        peers: format!("{live}⇄"),
        driver: driver_of(row.routing.as_ref()),
        waiting: row.intercepts.len(),
        error,
    }
}

pub fn client_line(row: &ClientRow) -> InstanceLine {
    use crate::state::client::ClientStatus;
    let (glyph, glyph_tone, error) = match &row.status {
        ClientStatus::Connected => ("●", Tone::Good, None),
        ClientStatus::Connecting => ("◐", Tone::Warn, None),
        ClientStatus::Disconnected => ("○", Tone::Dim, None),
        ClientStatus::Error(e) => ("✗", Tone::Bad, Some(e.clone())),
    };
    InstanceLine {
        key: UiKey::Client(row.id),
        glyph,
        glyph_tone,
        id: row.id.as_u32(),
        protocol: row.protocol.to_lowercase(),
        target: format!("→{}", row.remote_addr),
        peers: String::new(),
        driver: driver_of(row.routing.as_ref()),
        waiting: row.intercepts.len(),
        error,
    }
}

/// Truncate to `width` terminal cells with an ellipsis.
///
/// Counts cells, not chars: a wide (CJK, emoji) grapheme takes two and a
/// combining mark none, so a truncated label is as wide on screen as the
/// column it was fitted to. A grapheme is never split, and a wide one that
/// would straddle the ellipsis is left out whole.
pub fn fit(text: &str, width: usize) -> String {
    use ratatui::style::Style;
    use ratatui::text::Span;
    if crate::tui::wrap::cells(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let room = width - 1;
    let mut used = 0usize;
    let mut out = String::new();
    for grapheme in Span::raw(text).styled_graphemes(Style::default()) {
        let w = crate::tui::wrap::cells(grapheme.symbol);
        if used + w > room {
            break;
        }
        out.push_str(grapheme.symbol);
        used += w;
    }
    out.push('…');
    out
}
