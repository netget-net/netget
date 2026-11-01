//! Peer text is made terminal-safe where it enters the operator's view.
//!
//! `src/logging/emit.rs` fans a message out to `netget.log` and the status channel the TUI
//! and the headless runner print; `src/tui/cards.rs::payload_summary` is the one row a
//! request gets on a card. Both carry a peer's own bytes, and neither filtered ESC, C1 or
//! BEL — so an unauthenticated telnet line could write the operator's clipboard (OSC 52),
//! retitle the window, clear the screen to hide itself, or send a DSR query whose answer
//! the terminal types back into the chat box as keystrokes. The TUI frame half of this is
//! `tests/dashboard_frame_test.rs::peer_escape_sequences_are_not_painted_as_terminal_cells`.

use netget::logging::emit::{Level, Log, Sink};
use netget::state::app_state::AccessLogEntry;
use netget::tui::cards::payload_summary;
use netget::tui::modal::request_detail::detail_lines;
use netget::utils::sanitize;

const HOSTILE: &str = "user\u{1b}]52;c;QUJD\u{7}\u{9b}31m\u{1b}[2J\u{1b}[6n\u{85}name";

fn has_controls_other_than_newline_and_tab(s: &str) -> bool {
    s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

#[test]
fn a_status_line_reaches_the_channel_with_no_escape_sequence_in_it() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    Log::new(Some(&tx)).with_payloads(true).emit(
        Level::Warn,
        Sink::Both,
        format!("SSH auth for '{HOSTILE}': decision=model_reject"),
    );
    let line = rx.try_recv().expect("the TUI copy");
    assert!(line.starts_with("[WARN] "), "{line:?}");
    assert!(
        !has_controls_other_than_newline_and_tab(&line),
        "escape bytes survived into the status line: {line:?}"
    );
    assert!(
        line.contains("user") && line.contains("name") && line.contains("decision=model_reject"),
        "the text around them must survive: {line:?}"
    );
}

#[test]
fn a_request_row_is_one_line_of_plain_text() {
    let row = payload_summary(&serde_json::json!({"message": HOSTILE, "connection_id": "c"}));
    assert!(!row.chars().any(char::is_control), "{row:?}");
    assert!(row.starts_with("user") && row.ends_with("name"), "{row:?}");

    // What it did before is kept: CR dropped, LF shown as ⏎, a request line as one.
    assert_eq!(
        payload_summary(&serde_json::json!({"data": "a\r\nb"})),
        "a⏎b"
    );
    // An escape sequence goes whole, a space per character it occupied, so no `[31m` is left.
    assert_eq!(
        payload_summary(&serde_json::json!({"method": "GET", "path": "/x\u{1b}[31m"})),
        "GET /x     "
    );
}

/// Removing only the ESC leaves the rest of the sequence painted as text: deliberate dim
/// styling read `[2m…[0m` in the stream. A sequence goes as a whole, 7-bit or 8-bit.
#[test]
fn a_csi_sequence_is_removed_whole_with_no_residue() {
    for (input, expected) in [
        ("a\u{1b}[2mdim\u{1b}[0mb", "adimb"),
        ("a\u{1b}[38;5;196mred\u{1b}[mb", "aredb"),
        ("a\u{9b}31mred\u{9b}0mb", "aredb"),
        ("a\u{1b}]0;title\u{7}b", "ab"),
        ("a\u{1b}]52;c;QUJD\u{1b}\\b", "ab"),
        ("a\u{9d}52;c;QUJD\u{9c}b", "ab"),
        ("a\u{1b}P1$r\u{1b}\\b", "ab"),
        ("a\u{1b}(Bb\u{1b}c", "ab"),
    ] {
        assert_eq!(sanitize::multiline(input), expected, "multiline({input:?})");
        assert_eq!(
            sanitize::strip_controls(input),
            expected,
            "strip_controls({input:?})"
        );
        let field = sanitize::line_field(input);
        assert_eq!(field.chars().count(), input.chars().count(), "{field:?}");
        assert_eq!(
            field.split_whitespace().collect::<String>(),
            expected,
            "{field:?}"
        );
    }
}

/// A control string removed only when terminated: a dangling `ESC ]` from a peer's field must
/// not swallow the text NetGet writes after it.
#[test]
fn a_dangling_control_string_does_not_hide_the_rest_of_the_line() {
    let line = sanitize::multiline("SSH auth for 'x\u{1b}]52;c;': decision=model_reject");
    assert_eq!(line, "SSH auth for 'x52;c;': decision=model_reject");
}

/// `format_indented_dimmed_lines` styles status text with `ESC [2m … ESC [0m`; what the
/// stream and headless stdout apply to it leaves the text and nothing of the styling.
#[test]
fn dimmed_status_lines_reach_the_operator_with_no_escape_residue() {
    let lines = netget::llm::format_indented_dimmed_lines("{\n  \"port\": 23\n}", 8);
    assert_eq!(lines.len(), 3);
    for line in lines {
        let shown = sanitize::multiline(&format!("[INFO] {line}"));
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(
            !shown.contains("[2m") && !shown.contains("[0m"),
            "{shown:?}"
        );
        assert!(shown.starts_with("[INFO]         "), "{shown:?}");
    }
}

/// `serde_json` escapes U+0000..U+001F inside a string but writes DEL and C1 raw, so a U+009B
/// (8-bit CSI) in a peer's payload reached the terminal from the request detail modal. It is
/// written as its JSON escape instead, which keeps the text valid JSON for the same value.
#[test]
fn a_c1_csi_in_a_json_payload_is_not_painted() {
    let payload = serde_json::json!({"message": "hi\u{9b}31m\u{7f}\u{85}there", "n": 1});
    let entry = AccessLogEntry {
        id: 1,
        unix_ms: 1_700_000_000_000,
        server_id: Some(1),
        client_id: None,
        protocol: "TELNET".into(),
        connection_id: Some(7),
        event_type: "telnet_line_received".into(),
        request: payload.clone(),
        response: vec![serde_json::json!({"type": "send_telnet_line", "text": "\u{9b}2J"})],
        answered_by: None,
    };
    let lines = detail_lines(&entry);
    for line in &lines {
        assert!(!line.chars().any(char::is_control), "{line:?}");
    }
    let text = lines.join("\n");
    assert!(text.contains(r"hi\u009b31m\u007f\u0085there"), "{text}");
    assert!(text.contains(r"\u009b2J"), "{text}");

    let pretty = sanitize::json_text(&serde_json::to_string_pretty(&payload).unwrap());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&pretty).unwrap(),
        payload,
        "the escaped form must still be JSON for the same value"
    );
}
