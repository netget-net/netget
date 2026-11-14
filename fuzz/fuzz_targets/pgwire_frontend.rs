//! The PostgreSQL server's frontend decoder: `pgwire::messages::PgWireFrontendMessage::decode`,
//! from **NetGet's fork, `netget-pgwire`** (github.com/netget-net/pgwire; this crate depends on
//! it as the root manifest does), driven through the connection states pgwire's own server codec
//! walks: SSL/GSS negotiation, then Startup or CancelRequest, then every post-startup message.
//!
//! NetGet has no PostgreSQL byte parser of its own — the server hands the socket to pgwire's
//! `process_socket` — so this decoder is the whole pre-authentication surface. Upstream
//! pgwire 0.35.0 panics on six bytes after a valid handshake (the fork's NETGET.md has the
//! table); the fork refuses those as `FATAL 08P01`. This target is the search for the shapes
//! that table does not list. Built against unpatched pgwire, the `query_without_nul` seed
//! panics at once.
//!
//! Asserted:
//!
//! 1. Nothing panics, whatever the bytes and whichever state they arrive in.
//! 2. A decoded message consumes bytes (the codec would otherwise spin), except the one
//!    zero-length verdict the SSL state exists for.
//! 3. Re-encoding is a fixed point: a message that decodes encodes, its encoding decodes, and
//!    that re-encodes to the same bytes. This found upstream pgwire encoding CopyFail with
//!    CopyDone's tag on its first seed; the fork carries the fix.
//!
//! 4. NetGet's own code on the same bytes. The frontend-size screen in front of pgwire
//!    (`server::postgresql::guard::FrontendScreen`) forwards only bytes it was given, in order,
//!    whatever the chunking — the input is fed to it whole and again a byte at a time, and the
//!    two must forward the same prefix and agree on a refusal. Every SQL text pgwire decodes
//!    (Query, Parse) goes through the placeholder scanner and the statement classifier the
//!    handler runs on it.
//!
//! The wire format is flat — a type byte, an `Int32` length, a body — so the protocol has no
//! depth bomb; the SQL inside it does. PostgreSQL's block comments nest, and the placeholder
//! scanner counts them, so the corpus carries a Query of 30 000 nested `/*` (and one of 30 000
//! `(`) as well as the size lies: lengths of `0x7fffffff`, of 3, a Bind whose parameter count
//! and lengths run past the message, and a 60 000-parameter Bind at the edge.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use netget::server::postgresql::actions::answer_with_for_query;
use netget::server::postgresql::guard::{FrontendScreen, MAX_FRONTEND_MESSAGE_BYTES};
use netget::server::postgresql::{highest_placeholder, parameter_types};
use pgwire::messages::{DecodeContext, PgWireFrontendMessage, SslNegotiationMetaMessage};

/// The screen must forward a prefix of what it was given, and the same prefix however the bytes
/// were chunked.
fn screen(data: &[u8]) {
    let mut whole = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES);
    let (forwarded, refused) = whole.admit(data);
    assert!(
        data.starts_with(&forwarded),
        "the screen forwarded bytes it was not given, or out of order"
    );
    let mut bytewise = FrontendScreen::new(MAX_FRONTEND_MESSAGE_BYTES);
    let mut forwarded_bytewise = Vec::new();
    let mut refused_bytewise = None;
    for b in data {
        let (f, r) = bytewise.admit(std::slice::from_ref(b));
        forwarded_bytewise.extend_from_slice(&f);
        if r.is_some() {
            refused_bytewise = r;
            break;
        }
    }
    assert_eq!(
        forwarded, forwarded_bytewise,
        "chunking changed what was forwarded"
    );
    assert_eq!(refused, refused_bytewise, "chunking changed the refusal");
}

/// What the handler runs on a statement's text, before anything else sees it.
fn sql(text: &str) {
    let n = highest_placeholder(text);
    assert!(
        n <= u16::MAX as usize,
        "a placeholder past Bind's Int16 count"
    );
    assert_eq!(parameter_types(text, &[]).len(), n);
    let _ = answer_with_for_query(text);
}

fn fixed_point(msg: &PgWireFrontendMessage, ctx: &DecodeContext) {
    let mut first = BytesMut::new();
    if msg.encode(&mut first).is_err() {
        return;
    }
    let mut again = first.clone();
    let redecoded = PgWireFrontendMessage::decode(&mut again, ctx)
        .unwrap_or_else(|e| panic!("pgwire's own encoding of {msg:?} did not decode: {e}"))
        .unwrap_or_else(|| panic!("pgwire's own encoding of {msg:?} decoded as incomplete"));
    let mut second = BytesMut::new();
    redecoded
        .encode(&mut second)
        .expect("a re-decoded message must encode");
    assert_eq!(
        first, second,
        "encode/decode is not a fixed point for {msg:?}"
    );
}

/// `DecodeContext` is neither `Clone` nor constructible outside pgwire, so the state is kept
/// as the two flags pgwire's server codec sets and a context is built per decode.
fn ctx(awaiting_ssl: bool, awaiting_startup: bool) -> DecodeContext {
    let mut c = DecodeContext::default();
    c.awaiting_ssl = awaiting_ssl;
    c.awaiting_startup = awaiting_startup;
    c
}

fuzz_target!(|data: &[u8]| {
    screen(data);
    let mut buf = BytesMut::from(data);
    let (mut awaiting_ssl, mut awaiting_startup) = (true, true);

    // Every iteration consumes bytes or changes state, so this terminates; the bound is a
    // backstop against a regression that does neither.
    for _ in 0..data.len() + 4 {
        let before = buf.len();
        let state = ctx(awaiting_ssl, awaiting_startup);
        let decoded = match PgWireFrontendMessage::decode(&mut buf, &state) {
            Ok(Some(m)) => m,
            Ok(None) | Err(_) => break,
        };
        match &decoded {
            PgWireFrontendMessage::SslNegotiation(SslNegotiationMetaMessage::None) => {
                assert_eq!(buf.len(), before, "the no-SSL verdict must not consume");
                awaiting_ssl = false;
                continue;
            }
            // No TLS is configured, so the server answers 'N' and waits for the Startup.
            PgWireFrontendMessage::SslNegotiation(_) => awaiting_ssl = false,
            PgWireFrontendMessage::Startup(_) => awaiting_startup = false,
            PgWireFrontendMessage::Query(q) => sql(&q.query),
            PgWireFrontendMessage::Parse(p) => sql(&p.query),
            _ => {}
        }
        assert!(
            buf.len() < before,
            "decoded {decoded:?} without consuming a byte"
        );
        fixed_point(&decoded, &state);
        if let PgWireFrontendMessage::CancelRequest(_) = decoded {
            break;
        }
    }
});
