//! NetGet's pgwire fork (`netget-pgwire`, github.com/netget-net/pgwire) is the one Cargo
//! builds, still carries its patches, and refuses malformed frontend messages instead of
//! panicking on them. The fork's NETGET.md lists every change.
//!
//! pgwire 0.35.0's framer checks a message's declared length only from above and then hands
//! the body decoder the *whole* receive buffer; the decoders read with `Buf::get_*` and
//! `split_to`, which panic when the bytes are not there. So a `Query` with no NUL, a `Close`
//! with no body or a `Bind` whose parameter length runs past the message panicked the
//! connection task (IMPROVEMENTS #77), and a short message could be decoded out of the bytes
//! of the message after it.
//!
//! Two halves, like `vendored_kafka_protocol_patch_test.rs`:
//!
//! - Cargo must build the fork, at the version whose patches were checked, and upstream
//!   `pgwire` must not be in the graph at all.
//! - The decoder itself, driven through pgwire's public `PgWireFrontendMessage::decode` with
//!   every malformed shape found. Against upstream 0.35.0 most of these cases panic; each
//!   runs under `catch_unwind` so a regression names the case rather than aborting the run.
//!   The wire-level counterpart is `tests/server/postgresql/decoder_panic_test.rs`.

#[path = "helpers/fork_source.rs"]
mod fork_source;

use std::panic::{catch_unwind, AssertUnwindSafe};

use bytes::{BufMut, BytesMut};
use fork_source::{assert_fork_is_built, fork_dir, read_fork};
use pgwire::error::PgWireError;
use pgwire::messages::{DecodeContext, PgWireFrontendMessage};

const FORK: &str = "netget-pgwire";

#[test]
fn cargo_builds_the_pgwire_fork_from_crates_io() {
    assert_fork_is_built("pgwire", "0.35.0");
    let locked = fork_source::locked_packages(FORK);
    assert!(
        locked.iter().all(|(_, source)| source.as_deref()
            == Some("registry+https://github.com/rust-lang/crates.io-index")),
        "Cargo.lock resolves {FORK} from {locked:?}, not crates.io: a local [patch] or path \
         dependency is standing in for the published fork"
    );
}

#[test]
fn pgwire_fork_keeps_its_version_licenses_and_patches() {
    let manifest = read_fork(FORK, "Cargo.toml");
    assert!(manifest.contains("name = \"netget-pgwire\""));
    assert!(manifest.contains("version = \"0.35.0\""));
    assert!(manifest.contains("license = \"MIT/Apache-2.0\""));
    for file in ["LICENSE-APACHE", "LICENSE-MIT", "NETGET.md"] {
        assert!(fork_dir(FORK).join(file).is_file(), "{file} missing");
    }
    let codec = read_fork(FORK, "src/messages/codec.rs");
    assert!(
        codec.contains("pub(crate) fn decode_frontend_packet")
            || codec.contains("pub fn decode_frontend_packet"),
        "the fork's codec.rs lost decode_frontend_packet, the end-of-message check"
    );
    assert!(
        codec.contains("fn split_declared"),
        "the fork's codec.rs lost split_declared, the checked split for declared lengths"
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
         (the fork's NETGET.md):\n  {}",
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
