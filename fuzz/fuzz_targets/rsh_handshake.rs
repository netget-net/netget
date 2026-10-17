//! `netget::server::rsh::wire` — everything the rsh, rexec and rlogin servers and clients run
//! on what a peer sends: the NUL-terminated handshake fields against each cap, the stderr-port
//! field, rlogin's `terminal/speed`, a refusal line after `\1`, the window-size message split
//! across reads, and the line editor standing in for a pty.
//!
//! What parses is checked to stay within its bound: a field never longer than its cap, a port
//! in 1..=65535, at most eleven bytes held as a partial window message, a line never longer
//! than MAX_LINE_BYTES, and a refusal line never longer than MAX_ERROR_LINE characters. Nothing
//! here recurses, so the corpus carries the long inputs instead: a field one byte past the
//! command cap's neighbourhood, a run of FF bytes (every one a possible message start), a line
//! of DELs, and a line at the bound.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::rsh::wire;

fuzz_target!(|data: &[u8]| {
    // The handshake as a server reads it: port, two fields, a command, each with its cap.
    let mut rest = data;
    for max in [
        wire::MAX_PORT_FIELD,
        wire::MAX_USER,
        wire::MAX_PASSWORD,
        wire::MAX_COMMAND,
    ] {
        match wire::split_field(rest, max) {
            wire::FieldScan::Complete(n) => {
                assert!(n <= max);
                assert_eq!(rest[n], 0);
                if max == wire::MAX_PORT_FIELD {
                    if let Ok(Some(p)) = wire::parse_port(&rest[..n]) {
                        assert!(p >= 1);
                    }
                }
                rest = &rest[n + 1..];
            }
            wire::FieldScan::TooLong => {
                assert!(rest.len() > max);
                break;
            }
            wire::FieldScan::NeedMore => {
                assert!(rest.len() <= max);
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(data);
    let _ = wire::parse_terminal(&text);
    if let Some(line) = wire::refusal_line(data, true) {
        assert!(line.chars().count() <= wire::MAX_ERROR_LINE);
    }

    // rlogin's keystrokes in two reads split at every position the first byte picks.
    let cut = data
        .first()
        .map(|b| *b as usize % (data.len() + 1))
        .unwrap_or(0);
    let mut input = wire::RloginInput::default();
    let mut editor = wire::LineEditor::default();
    for part in [&data[..cut], &data[cut..]] {
        let (keys, sizes) = input.feed(part);
        assert!(input.held() < wire::WINDOW_MESSAGE_LEN);
        for s in sizes {
            let again = wire::WindowSize::decode(&s.encode()).unwrap();
            assert_eq!(again, s);
        }
        for event in editor.feed(&keys) {
            if let wire::LineEvent::Line(l) = event {
                assert!(l.len() <= 3 * wire::MAX_LINE_BYTES);
            }
        }
        assert!(editor.pending() <= wire::MAX_LINE_BYTES);
    }
    let _ = wire::crlf(&text);
});
