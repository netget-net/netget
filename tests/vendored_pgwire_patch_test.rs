//! The vendored pgwire in `vendor/pgwire` is the one Cargo builds, and it refuses malformed
//! frontend messages instead of panicking on them.
//!
//! pgwire 0.35.0's framer checks a message's declared length only from above and then hands
//! the body decoder the *whole* receive buffer; the decoders read with `Buf::get_*` and
//! `split_to`, which panic when the bytes are not there. So a `Query` with no NUL, a `Close`
//! with no body or a `Bind` whose parameter length runs past the message panicked the
//! connection task (IMPROVEMENTS #77), and a short message could be decoded out of the bytes
//! of the message after it. `vendor/pgwire/README.md` has the patch.
//!
//! Two halves, like `vendored_hyper_patch_test.rs`:
//!
//! - Cargo must actually build the copy. `[patch.crates-io]` silently stops applying (it is
//!   listed under `[[patch.unused]]`) when something wants a different pgwire.
//! - The decoder itself, driven through pgwire's public `PgWireFrontendMessage::decode` with
//!   every malformed shape found. Against upstream 0.35.0 most of these cases panic; each
//!   runs under `catch_unwind` so a regression names the case rather than aborting the run.
//!   The wire-level counterpart is `tests/server/postgresql/decoder_panic_test.rs`.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use bytes::{BufMut, BytesMut};
use pgwire::error::PgWireError;
use pgwire::messages::{DecodeContext, PgWireFrontendMessage};

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn manifest_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(v) = line.strip_prefix("version = ") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    panic!("vendor/pgwire/Cargo.toml has no [package] version");
}

#[test]
fn cargo_builds_the_vendored_pgwire_at_the_vendored_version() {
    let root = read("Cargo.toml");
    // The section header is a line of its own; match the line, not the words, which comments
    // may also contain.
    let patch = root
        .split_once("\n[patch.crates-io]\n")
        .map(|(_, rest)| rest.split("\n[").next().unwrap_or(rest))
        .unwrap_or("");
    assert!(
        patch
            .lines()
            .any(|l| l.trim() == r#"pgwire = { path = "vendor/pgwire" }"#),
        "Cargo.toml's [patch.crates-io] must point pgwire at vendor/pgwire (vendor/pgwire/README.md)"
    );

    let vendored = manifest_version(&read("vendor/pgwire/Cargo.toml"));
    let lock = read("Cargo.lock");
    let locked: Vec<(String, Option<String>)> = lock
        .split("[[package]]")
        .skip(1)
        .filter_map(|entry| {
            let field = |key: &str| {
                entry.lines().find_map(|l| {
                    l.strip_prefix(&format!("{key} = "))
                        .map(|v| v.trim_matches('"').to_string())
                })
            };
            (field("name")? == "pgwire").then(|| (field("version").unwrap(), field("source")))
        })
        .collect();
    assert!(!locked.is_empty(), "Cargo.lock has no pgwire at all");
    for (version, source) in &locked {
        assert!(
            source.is_none() && *version == vendored,
            "Cargo.lock resolves pgwire {version} from {} but vendor/pgwire is {vendored}: the \
             patched decoder is not the one being built. Re-vendor and re-apply the patch as \
             vendor/pgwire/README.md describes, or restore the [patch.crates-io] entry.",
            source.as_deref().unwrap_or("a path")
        );
    }
    let unused = lock.split("[[patch.unused]]").skip(1).any(|entry| {
        entry
            .lines()
            .take_while(|l| !l.starts_with("[["))
            .any(|l| l.trim() == r#"name = "pgwire""#)
    });
    assert!(
        !unused,
        "Cargo.lock lists vendor/pgwire under [[patch.unused]]: Cargo is building crates.io's \
         pgwire, which panics on malformed messages."
    );
}

/// A frontend message: type byte, Int32 length counting itself, body.
fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A frontend message whose declared length is `len`, whatever the body actually is.
fn msg_with_len(tag: u8, len: i32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn ctx(awaiting_startup: bool) -> DecodeContext {
    let mut ctx = DecodeContext::default();
    ctx.awaiting_ssl = false;
    ctx.awaiting_startup = awaiting_startup;
    ctx
}

type Decoded = Result<Option<PgWireFrontendMessage>, PgWireError>;

fn decode(bytes: &[u8], awaiting_startup: bool) -> (std::thread::Result<Decoded>, usize) {
    let mut buf = BytesMut::new();
    buf.put_slice(bytes);
    let ctx = ctx(awaiting_startup);
    let result = catch_unwind(AssertUnwindSafe(|| {
        PgWireFrontendMessage::decode(&mut buf, &ctx)
    }));
    (result, buf.len())
}

fn startup(params: &[u8]) -> Vec<u8> {
    let mut body = 196_608i32.to_be_bytes().to_vec();
    body.extend_from_slice(params);
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

#[test]
fn malformed_frontend_messages_are_refused_not_panicked_on() {
    let sync = msg(b'S', b"");
    let mut query_then_sync = msg_with_len(b'Q', 5, b"x");
    query_then_sync.extend_from_slice(&sync);

    let mut bind_short_param = Vec::new();
    bind_short_param.extend_from_slice(b"\0\0"); // portal, statement
    bind_short_param.extend_from_slice(&0u16.to_be_bytes()); // no format codes
    bind_short_param.extend_from_slice(&1u16.to_be_bytes()); // one parameter
    bind_short_param.extend_from_slice(&100i32.to_be_bytes()); // of 100 bytes
    bind_short_param.push(b'5'); // ... and one byte of it

    // A result-format count of -1: upstream read it as i16 and sized a Vec with it.
    let mut bind_negative_count = b"\0\0".to_vec();
    bind_negative_count.extend_from_slice(&0u16.to_be_bytes());
    bind_negative_count.extend_from_slice(&0u16.to_be_bytes());
    bind_negative_count.extend_from_slice(&(-1i16).to_be_bytes());

    let mut parse_missing_oids = b"s\0SELECT $1\0".to_vec();
    parse_missing_oids.extend_from_slice(&2u16.to_be_bytes()); // two oids, none present

    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        // IMPROVEMENTS #77: six bytes after the handshake.
        ("Query without its NUL", msg_with_len(b'Q', 5, b"x"), false),
        (
            "Query without its NUL, followed by a Sync it must not read into",
            query_then_sync,
            false,
        ),
        (
            "Query declaring length 0",
            msg_with_len(b'Q', 0, b""),
            false,
        ),
        (
            "CopyData declaring length 3",
            msg_with_len(b'd', 3, b""),
            false,
        ),
        ("Close with no body", msg(b'C', b""), false),
        ("Describe with no body", msg(b'D', b""), false),
        (
            "Execute with a name and no row limit",
            msg(b'E', b"p\0"),
            false,
        ),
        ("Execute whose name has no NUL", msg(b'E', b"p"), false),
        (
            "Parse with no parameter count",
            msg(b'P', b"s\0SELECT 1\0"),
            false,
        ),
        (
            "Parse missing its declared oids",
            msg(b'P', &parse_missing_oids),
            false,
        ),
        ("Bind with no body", msg(b'B', b""), false),
        (
            "Bind whose parameter runs past the message",
            msg(b'B', &bind_short_param),
            false,
        ),
        (
            "Bind with a result-format count of -1",
            msg(b'B', &bind_negative_count),
            false,
        ),
        ("CopyFail without its NUL", msg(b'f', b"oops"), false),
        ("Sync carrying a byte", msg(b'S', b"x"), false),
        (
            "StartupMessage whose key has no NUL",
            startup(b"user"),
            true,
        ),
        (
            "StartupMessage whose value has no NUL",
            startup(b"user\0net"),
            true,
        ),
    ];

    let mut failures = Vec::new();
    for (name, bytes, awaiting_startup) in &cases {
        match decode(bytes, *awaiting_startup).0 {
            Err(_) => failures.push(format!("{name}: PANICKED")),
            Ok(Ok(Some(m))) => failures.push(format!("{name}: decoded as {m:?}")),
            Ok(Ok(None)) => failures.push(format!("{name}: waited for more bytes")),
            Ok(Err(PgWireError::InvalidMessageFormat(_))) => {}
            Ok(Err(other)) => failures.push(format!("{name}: refused with {other:?}")),
        }
    }
    assert!(
        failures.is_empty(),
        "every malformed message must be PgWireError::InvalidMessageFormat \
         (vendor/pgwire/README.md):\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn well_formed_frontend_messages_still_decode_exactly() {
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

    let mut execute = b"\0".to_vec();
    execute.extend_from_slice(&0i32.to_be_bytes());

    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        ("Query", msg(b'Q', b"SELECT 1\0"), false),
        ("empty Query", msg(b'Q', b"\0"), false),
        ("Parse", msg(b'P', &parse), false),
        ("Bind", msg(b'B', &bind), false),
        ("Describe", msg(b'D', b"S\0"), false),
        ("Execute", msg(b'E', &execute), false),
        ("Close", msg(b'C', b"Ps\0"), false),
        ("Sync", msg(b'S', b""), false),
        ("Flush", msg(b'H', b""), false),
        ("CopyData", msg(b'd', b"1\t2\n"), false),
        ("CopyDone", msg(b'c', b""), false),
        ("CopyFail", msg(b'f', b"no\0"), false),
        ("Terminate", msg(b'X', b""), false),
        (
            "StartupMessage",
            startup(b"user\0netget\0database\0netget\0\0"),
            true,
        ),
    ];
    let mut failures = Vec::new();
    for (name, bytes, awaiting_startup) in &cases {
        // A second message behind it must be left untouched.
        let mut two = bytes.clone();
        two.extend_from_slice(&msg(b'S', b""));
        match decode(&two, *awaiting_startup) {
            (Ok(Ok(Some(_))), 5) => {}
            (Ok(Ok(Some(m))), left) => failures.push(format!(
                "{name}: decoded as {m:?} but left {left} bytes, not the 5 of the next message"
            )),
            (other, _) => failures.push(format!("{name}: {other:?}")),
        }
        // And a partial frame is still "wait for more", not an error.
        let (partial, _) = decode(&bytes[..bytes.len() - 1], *awaiting_startup);
        if !matches!(partial, Ok(Ok(None))) {
            failures.push(format!("{name} minus its last byte: {partial:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// pgwire's own encoding of a CopyFail decodes back as that CopyFail. Upstream 0.35.0's
/// `CopyFail::message_type()` returns CopyDone's tag (`c`), so the encoding read back as a
/// CopyDone with a body and was refused for its leftover bytes. Found by
/// `fuzz/fuzz_targets/pgwire_frontend.rs`'s round trip.
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

    match decode(&encoded, false) {
        (Ok(Ok(Some(PgWireFrontendMessage::CopyFail(m)))), 0) => {
            assert_eq!(m.message, "aborted by client");
        }
        other => panic!("pgwire's own CopyFail encoding did not decode as a CopyFail: {other:?}"),
    }
}
