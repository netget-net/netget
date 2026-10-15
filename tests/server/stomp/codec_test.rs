//! Unit tests for the STOMP 1.2 frame codec (`src/server/stomp/frame.rs`).
//!
//! These bind no socket and make no LLM call. They exist because the codec is the part of this
//! protocol that a real client would reject first, and the e2e test cannot reach the edges: a
//! body containing NUL, an undefined escape sequence, a frame split across two reads, a peer
//! that opens a frame and never closes it.
//!
//! The expectations are taken from the STOMP 1.2 specification, not from what the encoder
//! happens to produce — several assert against byte literals written out by hand for that
//! reason.

mod stomp_codec_test {
    use netget::server::stomp::frame::{
        error_frame, escape_header, is_safe_unescaped_header, parse_frame, receipt_frame,
        should_escape, unescape_header, FrameError, ParseOutcome, StompFrame, MAX_FRAME_BYTES,
        MAX_HEADERS,
    };

    fn parse_one(bytes: &[u8]) -> (StompFrame, usize) {
        match parse_frame(bytes).expect("frame should parse") {
            ParseOutcome::Frame { frame, consumed } => (frame, consumed),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_minimal_frame_and_reports_what_it_consumed() {
        let wire = b"CONNECT\naccept-version:1.2\nhost:/\n\n\0";
        let (frame, consumed) = parse_one(wire);
        assert_eq!(frame.command, "CONNECT");
        assert_eq!(frame.header("accept-version"), Some("1.2"));
        assert_eq!(frame.header("host"), Some("/"));
        assert!(frame.body.is_empty());
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn accepts_crlf_line_endings() {
        let (frame, _) = parse_one(b"SEND\r\ndestination:/queue/a\r\n\r\nhi\0");
        assert_eq!(frame.command, "SEND");
        assert_eq!(frame.header("destination"), Some("/queue/a"));
        assert_eq!(frame.body, b"hi");
    }

    /// The body runs to the first NUL when no `content-length` is given.
    #[test]
    fn body_without_content_length_ends_at_the_nul() {
        let (frame, consumed) = parse_one(b"SEND\ndestination:/q\n\nhello\0TRAILING");
        assert_eq!(frame.body, b"hello");
        assert_eq!(consumed, b"SEND\ndestination:/q\n\nhello\0".len());
    }

    /// `content-length` is authoritative, so a body may contain NUL bytes. This is the case
    /// that a "read to the terminator" parser silently truncates.
    #[test]
    fn content_length_is_authoritative_and_a_body_may_contain_nul() {
        let mut wire = b"SEND\ndestination:/q\ncontent-length:5\n\n".to_vec();
        wire.extend_from_slice(&[b'a', 0, b'b', 0, b'c']);
        wire.push(0);
        let (frame, consumed) = parse_one(&wire);
        assert_eq!(frame.body, vec![b'a', 0, b'b', 0, b'c']);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn content_length_not_followed_by_nul_is_fatal() {
        let wire = b"SEND\ncontent-length:2\n\nabX";
        assert_eq!(
            parse_frame(wire).unwrap_err(),
            FrameError::MissingNulTerminator
        );
    }

    #[test]
    fn a_non_numeric_content_length_is_fatal() {
        let wire = b"SEND\ncontent-length:banana\n\nab\0";
        assert!(matches!(
            parse_frame(wire).unwrap_err(),
            FrameError::BadContentLength(_)
        ));
    }

    // === escaping ===

    #[test]
    fn escapes_exactly_the_four_sequences_the_spec_defines() {
        assert_eq!(escape_header("a:b"), "a\\cb");
        assert_eq!(escape_header("a\nb"), "a\\nb");
        assert_eq!(escape_header("a\rb"), "a\\rb");
        assert_eq!(escape_header("a\\b"), "a\\\\b");
        // Everything else is left alone, including characters a naive escaper often touches.
        assert_eq!(escape_header("a/b c\"d'e"), "a/b c\"d'e");
    }

    #[test]
    fn unescape_round_trips_escape() {
        for original in ["plain", "a:b", "a\nb", "a\rb", "a\\b", "\\c", "::\n\\"] {
            assert_eq!(
                unescape_header(&escape_header(original)).unwrap(),
                original,
                "round trip failed for {original:?}"
            );
        }
    }

    /// An undefined escape sequence is a fatal protocol error, not something to pass through.
    /// Passing it through would let a peer smuggle a raw `:` past the parser and forge a header.
    #[test]
    fn an_undefined_escape_sequence_is_fatal() {
        assert!(matches!(
            unescape_header("a\\qb").unwrap_err(),
            FrameError::InvalidEscape(_)
        ));
        assert!(matches!(
            unescape_header("trailing\\").unwrap_err(),
            FrameError::InvalidEscape(_)
        ));
        // ...and it fails the whole frame, not just the header.
        assert!(matches!(
            parse_frame(b"SEND\nname:a\\qb\n\n\0").unwrap_err(),
            FrameError::InvalidEscape(_)
        ));
    }

    /// STOMP 1.2 exempts the handshake frames from escaping, for compatibility with 1.0/1.1
    /// peers that knew nothing about it. Getting this backwards corrupts every `host` header
    /// that contains a colon.
    #[test]
    fn the_handshake_frames_are_exempt_from_escaping() {
        assert!(!should_escape("CONNECT"));
        assert!(!should_escape("STOMP"));
        assert!(!should_escape("CONNECTED"));
        assert!(should_escape("SEND"));
        assert!(should_escape("MESSAGE"));
        assert!(should_escape("ERROR"));

        // A CONNECT header value keeps its colon verbatim on the way in...
        let (frame, _) = parse_one(b"CONNECT\nhost:example.com:61613\n\n\0");
        assert_eq!(frame.header("host"), Some("example.com:61613"));

        // ...while the same value in a MESSAGE arrives escaped and is decoded.
        let (frame, _) = parse_one(b"MESSAGE\ndestination:/q\\ca\n\n\0");
        assert_eq!(frame.header("destination"), Some("/q:a"));
    }

    #[test]
    fn a_header_line_without_a_colon_is_fatal() {
        assert!(matches!(
            parse_frame(b"SEND\nnocolon\n\n\0").unwrap_err(),
            FrameError::MalformedHeader(_)
        ));
    }

    // === framing across reads ===

    #[test]
    fn a_partial_frame_is_incomplete_and_consumes_nothing() {
        let full = b"SEND\ndestination:/q\n\nhello\0";
        for split in 1..full.len() {
            assert_eq!(
                parse_frame(&full[..split]).unwrap(),
                ParseOutcome::Incomplete,
                "prefix of length {split} should be incomplete"
            );
        }
        assert!(matches!(
            parse_frame(full).unwrap(),
            ParseOutcome::Frame { .. }
        ));
    }

    /// A bare EOL is a STOMP heart-beat, and clients also leave trailing newlines after a
    /// frame's NUL. Neither is an empty command.
    #[test]
    fn inter_frame_eols_are_drained_as_heartbeats() {
        assert_eq!(
            parse_frame(b"\n\n").unwrap(),
            ParseOutcome::Heartbeat { consumed: 2 }
        );
        assert_eq!(
            parse_frame(b"\r\n").unwrap(),
            ParseOutcome::Heartbeat { consumed: 2 }
        );
        // Leading EOLs are skipped when a frame follows them.
        let (frame, consumed) = parse_one(b"\n\nDISCONNECT\n\n\0");
        assert_eq!(frame.command, "DISCONNECT");
        assert_eq!(consumed, b"\n\nDISCONNECT\n\n\0".len());
    }

    /// A peer that opens a frame and never terminates it must not make the server grow a
    /// buffer without bound.
    #[test]
    fn an_unterminated_frame_is_refused_once_it_passes_the_size_bound() {
        let mut wire = b"SEND\ndestination:/q\n\n".to_vec();
        wire.resize(MAX_FRAME_BYTES + 16, b'x');
        assert!(matches!(
            parse_frame(&wire).unwrap_err(),
            FrameError::FrameTooLarge(_)
        ));
    }

    /// A `content-length` a peer picked must not be able to wrap the index that reads it.
    ///
    /// `18446744073709551615` parses cleanly into a `usize`, and `pos + len` then overflowed:
    /// a panic in debug and test builds, where `overflow-checks` is on, and in release a wrap
    /// to `pos - 1` that made the whole thing invisible in the shipped profile while it was
    /// live in every test run. The panic happened inside the connection's `tokio::spawn`, so
    /// it was swallowed: the connection's cleanup never ran and the peer handle and the
    /// `AppState` row leaked with the connection stuck `Active`. One frame, from any peer,
    /// before the CONNECT gate.
    #[test]
    fn a_content_length_that_would_wrap_the_index_is_refused() {
        let wire = format!("SEND\ndestination:/q\ncontent-length:{}\n\n\0", usize::MAX);
        assert!(matches!(
            parse_frame(wire.as_bytes()).unwrap_err(),
            FrameError::FrameTooLarge(_)
        ));
        // Anything past the frame bound is refused on sight rather than buffered toward.
        let wire = format!(
            "SEND\ndestination:/q\ncontent-length:{}\n\n\0",
            MAX_FRAME_BYTES + 1
        );
        assert!(matches!(
            parse_frame(wire.as_bytes()).unwrap_err(),
            FrameError::FrameTooLarge(_)
        ));
    }

    /// `MAX_FRAME_BYTES` bounds the memory but not the work.
    ///
    /// The connection loop re-parses the whole pending buffer after every read, allocating two
    /// `String`s per header line each time, so a megabyte of three-byte header lines is ~350k
    /// headers re-parsed ~128 times as the 8 KB reads arrive — tens of millions of allocations
    /// from a megabyte of input, per connection, with nothing capping connections.
    #[test]
    fn a_frame_with_absurdly_many_headers_is_refused() {
        let mut wire = b"SEND\n".to_vec();
        for i in 0..=MAX_HEADERS {
            wire.extend_from_slice(format!("h{i}:v\n").as_bytes());
        }
        wire.extend_from_slice(b"\n\0");
        assert_eq!(parse_frame(&wire).unwrap_err(), FrameError::TooManyHeaders);

        // The bound is generous: no real frame comes close, and one that does still parses.
        let mut ok = b"SEND\n".to_vec();
        for i in 0..(MAX_HEADERS - 1) {
            ok.extend_from_slice(format!("h{i}:v\n").as_bytes());
        }
        ok.extend_from_slice(b"\n\0");
        assert!(matches!(
            parse_frame(&ok).unwrap(),
            ParseOutcome::Frame { .. }
        ));
    }

    /// A peer's own malformed input is quoted back to it, and must be quoted in a bounded way.
    ///
    /// A `FrameError` reaches the `ERROR` frame, `netget.log` and the TUI status stream, which
    /// is an unbounded channel with no backpressure. `MalformedHeader` carried the entire
    /// offending line — up to a megabyte — and `{:?}` escaping roughly doubles it, so the peer
    /// chose how much memory NetGet spent on its behalf, three times over.
    #[test]
    fn a_malformed_header_is_quoted_back_in_a_bounded_way() {
        let mut wire = b"SEND\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 500_000]);
        wire.extend_from_slice(b"\n\n\0");
        let rendered = parse_frame(&wire).unwrap_err().to_string();
        assert!(
            rendered.len() < 400,
            "a malformed-header error must not carry the peer's whole line; got {} bytes",
            rendered.len()
        );
        assert!(rendered.contains("no ':' separator"));
    }

    /// The one place a string reaches the wire without the escaper in front of it.
    ///
    /// STOMP 1.2 exempts `CONNECT`/`STOMP`/`CONNECTED` from escaping so a 1.2 endpoint can
    /// read a 1.0/1.1 peer's handshake, which means `encode()` writes their header values raw.
    /// `send_stomp_connected` copies the model's `session` and `server` straight in, and this
    /// protocol's own startup example builds the session out of peer input
    /// (`'session-' + login`), so it is reachable from a script handler as readily as from the
    /// model. Rejecting rather than escaping, because escaping is exactly what those commands
    /// cannot do.
    #[test]
    fn values_that_would_forge_a_header_on_an_unescaped_command_are_rejected() {
        assert!(!should_escape("CONNECTED"));
        assert!(is_safe_unescaped_header("session-1"));
        assert!(is_safe_unescaped_header("netget/stomp"));
        assert!(!is_safe_unescaped_header("s\nversion:1.0"));
        assert!(!is_safe_unescaped_header("s\r\nlogin:root"));
        assert!(!is_safe_unescaped_header("a:b"));
        assert!(!is_safe_unescaped_header("a\0b"));
    }

    // === encoding ===

    #[test]
    fn encode_adds_content_length_for_a_non_empty_body_only() {
        let with_body = StompFrame::new(
            "MESSAGE",
            vec![("destination".into(), "/q".into())],
            b"hi".to_vec(),
        )
        .encode();
        assert_eq!(
            with_body,
            b"MESSAGE\ndestination:/q\ncontent-length:2\n\nhi\0".to_vec()
        );

        let empty =
            StompFrame::new("RECEIPT", vec![("receipt-id".into(), "r-1".into())], vec![]).encode();
        assert_eq!(empty, b"RECEIPT\nreceipt-id:r-1\n\n\0".to_vec());
    }

    /// The encoder escapes on the way out exactly where the parser unescapes on the way in,
    /// which is what makes the round trip lossless.
    #[test]
    fn encode_then_parse_round_trips_a_hostile_header_and_a_binary_body() {
        let original = StompFrame::new(
            "MESSAGE",
            vec![
                ("destination".into(), "/queue/a:b\nc\\d".into()),
                ("subscription".into(), "sub-0".into()),
                ("message-id".into(), "msg-1".into()),
            ],
            vec![0, 1, 2, 0, 255],
        );
        let wire = original.encode();
        let (parsed, consumed) = parse_one(&wire);
        assert_eq!(consumed, wire.len());
        assert_eq!(parsed.command, "MESSAGE");
        assert_eq!(parsed.header("destination"), Some("/queue/a:b\nc\\d"));
        assert_eq!(parsed.body, vec![0, 1, 2, 0, 255]);
    }

    #[test]
    fn receipt_and_error_helpers_produce_the_frames_the_spec_describes() {
        assert_eq!(
            receipt_frame("r-7"),
            b"RECEIPT\nreceipt-id:r-7\n\n\0".to_vec()
        );

        let err = error_frame("unknown command", "FOO is not a STOMP 1.2 client command.");
        let (parsed, _) = parse_one(&err);
        assert_eq!(parsed.command, "ERROR");
        assert_eq!(parsed.header("message"), Some("unknown command"));
        assert_eq!(parsed.header("content-type"), Some("text/plain"));
        assert_eq!(parsed.body, b"FOO is not a STOMP 1.2 client command.");
    }

    #[test]
    fn headers_except_keeps_the_first_value_and_drops_what_was_asked_for() {
        let (frame, _) = parse_one(
            b"SEND\ndestination:/q\ncontent-type:text/plain\ntransaction:tx-1\ndestination:/other\n\n\0",
        );
        // First occurrence wins, per the spec.
        assert_eq!(frame.header("destination"), Some("/q"));
        let rest = frame.headers_except(&["destination"]);
        assert_eq!(rest.len(), 2);
        assert_eq!(rest["content-type"], "text/plain");
        assert_eq!(rest["transaction"], "tx-1");
        assert!(!rest.contains_key("destination"));
    }
}
