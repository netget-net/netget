//! The PostgreSQL server's frontend screen (`server::postgresql::guard::FrontendScreen`) refuses
//! every malformed frontend message before pgwire sees it, and passes every well-formed one byte
//! for byte.
//!
//! The server is upstream pgwire, 0.42.3 or later: the first release that isolates each message's
//! body before decoding it and refuses a short body instead of panicking (sunng87/pgwire#484).
//! Before it, six bytes after the handshake panicked the connection task. Two things are still
//! left to the screen, and this file pins both:
//!
//! - When pgwire's decoder refuses a message, `process_socket` ends the session without writing
//!   anything; PostgreSQL answers `FATAL 08P01`. The screen runs the same decoder first and
//!   answers it.
//! - pgwire does not check that a decoder read the whole body. An unterminated string reads as
//!   empty (a Query of `x` with no NUL is served as an empty query), and trailing bytes are
//!   dropped. The screen re-encodes each message and refuses one that is not the bytes that
//!   arrived.
//!
//! Each case runs the decoder under `catch_unwind` too, so a regression in pgwire names the case.
//! The wire-level counterpart, the six original shapes against a running server, is
//! `tests/server/postgresql/decoder_panic_test.rs`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use bytes::BytesMut;
use netget::server::postgresql::guard::{FrontendScreen, Refusal, MAX_FRONTEND_MESSAGE_BYTES};
use pgwire::messages::{DecodeContext, PgWireFrontendMessage};

/// Every `[[package]]` entry in Cargo.lock named `name`: (version, source).
fn locked(name: &str) -> Vec<(String, Option<String>)> {
    let lock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )
    .expect("Cargo.lock");
    lock.split("[[package]]")
        .skip(1)
        .filter_map(|entry| {
            let field = |key: &str| {
                entry.lines().find_map(|l| {
                    l.strip_prefix(&format!("{key} = "))
                        .map(|v| v.trim_matches('"').to_string())
                })
            };
            (field("name")? == name).then(|| (field("version").unwrap(), field("source")))
        })
        .collect()
}

#[test]
fn cargo_builds_upstream_pgwire_0_42_3_or_later_from_crates_io() {
    let pgwire = locked("pgwire");
    assert_eq!(pgwire.len(), 1, "Cargo.lock resolves pgwire as {pgwire:?}");
    let (version, source) = &pgwire[0];
    let parts: Vec<u64> = version
        .split('.')
        .map(|p| p.parse().expect("numeric version"))
        .collect();
    assert!(
        parts.as_slice() >= [0, 42, 3].as_slice(),
        "pgwire {version} predates 0.42.3, which is the first release that does not panic on a \
         short frontend message"
    );
    assert_eq!(
        source.as_deref(),
        Some("registry+https://github.com/rust-lang/crates.io-index"),
        "pgwire must come from crates.io, not a local [patch] or path"
    );
}

/// A frontend message: type byte, Int32 length counting itself, body.
fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    msg_with_len(tag, (body.len() + 4) as i32, body)
}

/// A frontend message whose declared length is `len`, whatever the body actually is.
fn msg_with_len(tag: u8, len: i32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn startup(params: &[u8]) -> Vec<u8> {
    let mut body = 196_608i32.to_be_bytes().to_vec();
    body.extend_from_slice(params);
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

const STARTUP: &[u8] = b"user\0netget\0database\0netget\0\0";

/// A screen that has admitted a valid StartupMessage, so it is reading typed messages.
fn started() -> FrontendScreen {
    let mut screen = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES);
    let start = startup(STARTUP);
    let (forwarded, refused) = screen.admit(&start);
    assert_eq!(
        forwarded, start,
        "a valid StartupMessage must be forwarded whole"
    );
    assert!(
        refused.is_none(),
        "a valid StartupMessage was refused: {refused:?}"
    );
    screen
}

/// pgwire's decoder on `bytes`, in the state the server's codec would be in.
fn decoder_panics(bytes: &[u8], awaiting_startup: bool) -> bool {
    let mut ctx = DecodeContext::default();
    ctx.awaiting_frontend_ssl = false;
    ctx.awaiting_frontend_startup = awaiting_startup;
    let mut buf = BytesMut::from(bytes);
    catch_unwind(AssertUnwindSafe(|| {
        let _ = PgWireFrontendMessage::decode(&mut buf, &ctx);
    }))
    .is_err()
}

#[test]
fn malformed_frontend_messages_are_refused_before_pgwire_sees_them() {
    let sync = msg(b'S', b"");
    let mut query_then_sync = msg_with_len(b'Q', 5, b"x");
    query_then_sync.extend_from_slice(&sync);

    let mut bind_short_param = Vec::new();
    bind_short_param.extend_from_slice(b"\0\0"); // portal, statement
    bind_short_param.extend_from_slice(&0u16.to_be_bytes()); // no format codes
    bind_short_param.extend_from_slice(&1u16.to_be_bytes()); // one parameter
    bind_short_param.extend_from_slice(&100i32.to_be_bytes()); // of 100 bytes
    bind_short_param.push(b'5'); // ... and one byte of it

    // A result-format count of -1 (pgwire before 0.42.3 read it as i16 and sized a Vec with it).
    let mut bind_negative_count = b"\0\0".to_vec();
    bind_negative_count.extend_from_slice(&0u16.to_be_bytes());
    bind_negative_count.extend_from_slice(&0u16.to_be_bytes());
    bind_negative_count.extend_from_slice(&(-1i16).to_be_bytes());

    let mut parse_missing_oids = b"s\0SELECT $1\0".to_vec();
    parse_missing_oids.extend_from_slice(&2u16.to_be_bytes()); // two oids, none present

    // A NULL parameter written as length -2: only -1 means NULL.
    let mut bind_negative_length = b"\0\0".to_vec();
    bind_negative_length.extend_from_slice(&0u16.to_be_bytes());
    bind_negative_length.extend_from_slice(&1u16.to_be_bytes());
    bind_negative_length.extend_from_slice(&(-2i32).to_be_bytes());
    bind_negative_length.extend_from_slice(&0u16.to_be_bytes());

    let typed: Vec<(&str, Vec<u8>)> = vec![
        ("Query without its NUL", msg_with_len(b'Q', 5, b"x")),
        (
            "Query without its NUL, followed by a Sync it must not read into",
            query_then_sync,
        ),
        ("Query with bytes after its NUL", msg(b'Q', b"SELECT 1\0x")),
        ("Query declaring length 0", msg_with_len(b'Q', 0, b"")),
        ("CopyData declaring length 3", msg_with_len(b'd', 3, b"")),
        ("Close with no body", msg(b'C', b"")),
        ("Describe with no body", msg(b'D', b"")),
        ("Execute with a name and no row limit", msg(b'E', b"p\0")),
        ("Execute whose name has no NUL", msg(b'E', b"p")),
        ("Parse with no parameter count", msg(b'P', b"s\0SELECT 1\0")),
        (
            "Parse missing its declared oids",
            msg(b'P', &parse_missing_oids),
        ),
        ("Bind with no body", msg(b'B', b"")),
        (
            "Bind whose parameter runs past the message",
            msg(b'B', &bind_short_param),
        ),
        (
            "Bind with a result-format count of -1",
            msg(b'B', &bind_negative_count),
        ),
        (
            "Bind with a parameter length of -2",
            msg(b'B', &bind_negative_length),
        ),
        ("CopyFail without its NUL", msg(b'f', b"oops")),
        ("Sync carrying a byte", msg(b'S', b"x")),
        ("a message type pgwire does not know", msg(b'~', b"")),
    ];

    let mut failures = Vec::new();
    for (name, bytes) in &typed {
        if decoder_panics(bytes, false) {
            failures.push(format!("{name}: pgwire's decoder PANICKED"));
        }
        let (forwarded, refused) = started().admit(bytes);
        if !forwarded.is_empty() {
            failures.push(format!("{name}: forwarded {forwarded:?} to pgwire"));
        }
        match refused {
            Some(Refusal::Malformed(_)) => {}
            other => failures.push(format!(
                "{name}: {other:?}, not a malformed-message refusal"
            )),
        }
    }
    for (name, params) in [
        ("StartupMessage whose key has no NUL", &b"user"[..]),
        ("StartupMessage whose value has no NUL", b"user\0net"),
        ("StartupMessage with no terminator", b"user\0netget\0"),
        (
            "StartupMessage with bytes after its terminator",
            b"user\0netget\0\0x",
        ),
    ] {
        let bytes = startup(params);
        if decoder_panics(&bytes, true) {
            failures.push(format!("{name}: pgwire's decoder PANICKED"));
        }
        let (forwarded, refused) = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES).admit(&bytes);
        if !forwarded.is_empty() || !matches!(refused, Some(Refusal::Malformed(_))) {
            failures.push(format!(
                "{name}: forwarded {forwarded:?}, refusal {refused:?}"
            ));
        }
    }
    // pgwire reads an SSLRequest or GSSENCRequest as 8 bytes whatever its length says, so a longer
    // one would carry a StartupMessage and typed messages past the screen inside its "body" (found
    // by `fuzz/fuzz_targets/pgwire_frontend.rs`; the seed is `ssl_request_length_lie`).
    for (name, code) in [("SSLRequest", 80_877_103u32), ("GSSENCRequest", 80_877_104)] {
        let mut smuggled = startup(STARTUP);
        smuggled.extend_from_slice(&msg_with_len(b'Q', 5, b"x"));
        let mut bytes = ((8 + smuggled.len()) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.extend_from_slice(&smuggled);
        let (forwarded, refused) = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES).admit(&bytes);
        if !forwarded.is_empty() || !matches!(refused, Some(Refusal::Malformed(_))) {
            failures.push(format!(
                "{name} declaring {} bytes: forwarded {forwarded:?}, refusal {refused:?}",
                bytes.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "every malformed message must be refused, and none forwarded:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn well_formed_frontend_messages_pass_the_screen_unchanged() {
    let mut parse = b"s\0SELECT $1\0".to_vec();
    parse.extend_from_slice(&1u16.to_be_bytes());
    parse.extend_from_slice(&23u32.to_be_bytes());

    let mut bind = b"\0s\0".to_vec();
    bind.extend_from_slice(&1u16.to_be_bytes());
    bind.extend_from_slice(&0i16.to_be_bytes());
    bind.extend_from_slice(&2u16.to_be_bytes());
    bind.extend_from_slice(&1i32.to_be_bytes());
    bind.push(b'5');
    bind.extend_from_slice(&(-1i32).to_be_bytes()); // NULL
    bind.extend_from_slice(&0i16.to_be_bytes());

    // Binary parameters and result formats: bytes that are not UTF-8 in a binary field.
    let mut bind_binary = b"p\0s\0".to_vec();
    bind_binary.extend_from_slice(&1u16.to_be_bytes());
    bind_binary.extend_from_slice(&1i16.to_be_bytes());
    bind_binary.extend_from_slice(&1u16.to_be_bytes());
    bind_binary.extend_from_slice(&4i32.to_be_bytes());
    bind_binary.extend_from_slice(&[0xff, 0xfe, 0x80, 0x00]);
    bind_binary.extend_from_slice(&1u16.to_be_bytes());
    bind_binary.extend_from_slice(&1i16.to_be_bytes());

    let mut execute = b"\0".to_vec();
    execute.extend_from_slice(&0i32.to_be_bytes());

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("Query", msg(b'Q', b"SELECT 1\0")),
        ("empty Query", msg(b'Q', b"\0")),
        // pgwire reads strings lossily; the screen passes invalid UTF-8 on as it arrived.
        (
            "Query with invalid UTF-8",
            msg(b'Q', b"SELECT '\xff\xfe'\0"),
        ),
        ("Parse", msg(b'P', &parse)),
        ("Bind", msg(b'B', &bind)),
        ("Bind with binary values", msg(b'B', &bind_binary)),
        ("Describe", msg(b'D', b"S\0")),
        ("Execute", msg(b'E', &execute)),
        ("Close", msg(b'C', b"Ps\0")),
        ("Sync", msg(b'S', b"")),
        ("Flush", msg(b'H', b"")),
        ("CopyData", msg(b'd', b"1\t2\n")),
        ("CopyDone", msg(b'c', b"")),
        ("CopyFail", msg(b'f', b"no\0")),
        ("Terminate", msg(b'X', b"")),
    ];
    let mut failures = Vec::new();
    for (name, bytes) in &cases {
        // A message behind it must be read as its own.
        let mut two = bytes.clone();
        two.extend_from_slice(&msg(b'S', b""));
        let (forwarded, refused) = started().admit(&two);
        if forwarded != two || refused.is_some() {
            failures.push(format!(
                "{name}: forwarded {forwarded:?}, refusal {refused:?}"
            ));
        }
        // The same a byte at a time, and nothing of a message until it is whole.
        let mut screen = started();
        let mut bytewise = Vec::new();
        for (i, b) in two.iter().enumerate() {
            let (f, r) = screen.admit(std::slice::from_ref(b));
            if r.is_some() || (i + 1 < bytes.len() && !f.is_empty()) {
                failures.push(format!("{name}: byte {i} gave {f:?} / {r:?}"));
                break;
            }
            bytewise.extend_from_slice(&f);
        }
        if bytewise != two {
            failures.push(format!("{name}: a byte at a time forwarded {bytewise:?}"));
        }
    }
    // An 8-byte SSLRequest, then the StartupMessage, as psql sends them.
    let mut ssl_then_start = 8u32.to_be_bytes().to_vec();
    ssl_then_start.extend_from_slice(&80_877_103u32.to_be_bytes());
    ssl_then_start.extend_from_slice(&startup(STARTUP));
    let (forwarded, refused) =
        FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES).admit(&ssl_then_start);
    if forwarded != ssl_then_start || refused.is_some() {
        failures.push(format!(
            "SSLRequest then StartupMessage: forwarded {forwarded:?}, refusal {refused:?}"
        ));
    }
    let start = startup(b"user\0netget\0application_name\0\0\0");
    let (forwarded, refused) = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES).admit(&start);
    if forwarded != start || refused.is_some() {
        failures.push(format!(
            "StartupMessage with an empty value: forwarded {forwarded:?}, refusal {refused:?}"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// pgwire's own encoding of a CopyFail decodes back as that CopyFail. The screen re-encodes every
/// message it checks, so a CopyFail written with another tag would be refused. pgwire 0.35 wrote
/// it with CopyDone's tag `c` (found by `fuzz/fuzz_targets/pgwire_frontend.rs`'s round trip).
#[test]
fn copy_fail_encodes_with_its_own_tag_and_round_trips() {
    use pgwire::messages::copy::CopyFail;

    let original = PgWireFrontendMessage::CopyFail(CopyFail::new("aborted by client".into()));
    let mut encoded = BytesMut::new();
    original.encode(&mut encoded).expect("CopyFail encodes");
    assert_eq!(
        &encoded[..],
        &msg(b'f', b"aborted by client\0")[..],
        "CopyFail must be written with its own tag `f`"
    );
    let (forwarded, refused) = started().admit(&encoded);
    assert_eq!(forwarded, &encoded[..]);
    assert!(refused.is_none(), "{refused:?}");
}
