//! Unit tests for the AMQP 0-9-1 field-table decoder (`src/server/amqp/codec.rs`).
//!
//! These bind no socket and make no LLM call. They exist because the field table is the one
//! recursive structure on the AMQP wire, and it is decoded **before authentication** — the
//! `client-properties` table in `Connection.Start-Ok` is read in `Phase::AwaitStartOk`, before
//! any credential is examined and before any model decision is asked for.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features amqp --test server -- amqp::codec --test-threads=100

use netget::server::amqp::codec::Decoder;
use serde_json::Value;

/// How deeply the returned JSON actually nests, counting objects and arrays.
///
/// The decoder is deliberately lenient: an entry it cannot finish is dropped and what was
/// decoded so far is returned, so an over-deep value comes back **truncated** rather than
/// absent. That is the right behaviour — the outer payload stays in sync — and it means the
/// assertion has to be about the depth of the result, not its presence.
fn json_depth(v: &Value) -> usize {
    match v {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Mirrors `MAX_FIELD_TABLE_DEPTH` in `src/server/amqp/codec.rs`, which is private. The
/// assertions below use a generous multiple of it, so this staying in step is not critical —
/// what matters is that the result is bounded by a small constant rather than by the frame.
const DEPTH_BOUND: usize = 32;

/// A field table holding one entry whose value is `inner`, framed with its 32-bit length.
fn table_of(key: &[u8], inner: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(key.len() as u8);
    body.extend_from_slice(key);
    body.extend_from_slice(&inner);
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// `depth` nested field-array values (`A` + a 32-bit length each), innermost first.
///
/// Five bytes per level is the whole problem: at the default `frame_max` of 128 KiB a peer
/// buys ~26 000 levels in a single frame, and at the permitted maximum of 1 MiB about
/// 210 000.
fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::new();
    for _ in 0..depth {
        let mut next = vec![b'A'];
        next.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        next.extend_from_slice(&inner);
        inner = next;
    }
    inner
}

/// `depth` nested field tables (`F` + a 32-bit length + an empty key each).
fn nested_tables(depth: usize) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::new();
    for _ in 0..depth {
        // one entry: zero-length key, then the value
        let mut body = vec![0u8];
        body.push(b'F');
        body.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        body.extend_from_slice(&inner);
        inner = body;
    }
    inner
}

/// The shape a real client sends: a flat map with one nested `capabilities` table, depth 2.
#[test]
fn a_realistic_client_properties_table_still_decodes() {
    // capabilities = { "publisher_confirms": true }
    let mut caps_body = Vec::new();
    caps_body.push(18u8);
    caps_body.extend_from_slice(b"publisher_confirms");
    caps_body.push(b't');
    caps_body.push(1);
    let mut caps = (caps_body.len() as u32).to_be_bytes().to_vec();
    caps.extend_from_slice(&caps_body);

    let mut value = vec![b'F'];
    value.extend_from_slice(&caps);
    let wire = table_of(b"capabilities", value);

    let mut d = Decoder::new(&wire);
    let table = d.field_table().expect("a two-deep table must decode");
    assert_eq!(
        table["capabilities"]["publisher_confirms"],
        serde_json::Value::Bool(true)
    );
}

/// The depth bound admits far more nesting than any real client produces.
#[test]
fn nesting_well_inside_the_bound_is_accepted() {
    let mut value = vec![b'A'];
    let arrays = nested_arrays(8);
    value.extend_from_slice(&(arrays.len() as u32).to_be_bytes());
    value.extend_from_slice(&arrays);
    let wire = table_of(b"x", value);

    let mut d = Decoder::new(&wire);
    assert!(
        d.field_table().is_ok(),
        "eight levels is an order of magnitude past anything amq-protocol emits"
    );
}

/// A deeply nested field **array** must be refused, not recursed into.
///
/// `field_value` recursed with no depth counter. Each level costs the peer five bytes — the
/// `A` tag plus a four-byte length — so 100_000 levels is half a megabyte on the wire and
/// fits inside one frame at the permitted maximum `frame_max`. A 2 MiB tokio worker stack
/// does not survive it, and a Rust stack overflow is a `SIGSEGV` against a guard page rather
/// than a panic: `tokio::spawn` cannot contain it, so the whole NetGet process died, taking
/// every other server and client hosted in it.
///
/// This test failing to complete is itself the regression.
#[test]
fn a_deeply_nested_field_array_is_refused_rather_than_recursed_into() {
    let mut value = vec![b'A'];
    let arrays = nested_arrays(100_000);
    value.extend_from_slice(&(arrays.len() as u32).to_be_bytes());
    value.extend_from_slice(&arrays);
    let wire = table_of(b"x", value);

    let mut d = Decoder::new(&wire);
    // Reaching this line at all is the assertion: the old decoder never returned from here.
    let table = d
        .field_table()
        .expect("the outer table itself is well-formed");
    let depth = json_depth(&table);
    assert!(
        depth <= DEPTH_BOUND + 2,
        "100_000 declared levels must come back bounded, got depth {depth}"
    );
}

/// The same, through the `F` (nested table) arm, which recurses by a different path.
///
/// This is the arm reachable from `Connection.Start-Ok`'s `client-properties`, i.e. the
/// pre-authentication one: protocol header, then one method frame.
#[test]
fn a_deeply_nested_field_table_is_refused_rather_than_recursed_into() {
    let tables = nested_tables(100_000);
    let mut wire = (tables.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&tables);

    let mut d = Decoder::new(&wire);
    let table = d
        .field_table()
        .expect("the outermost table is well-formed; only the nesting inside it is not");
    let depth = json_depth(&table);
    assert!(
        depth <= DEPTH_BOUND + 2,
        "100_000 declared levels must come back bounded, got depth {depth}"
    );
}

/// Mixed `A`/`F` nesting must not sidestep the bound by alternating arms.
#[test]
fn alternating_array_and_table_nesting_is_bounded_too() {
    let mut inner: Vec<u8> = Vec::new();
    for i in 0..50_000 {
        if i % 2 == 0 {
            let mut next = vec![b'A'];
            next.extend_from_slice(&(inner.len() as u32).to_be_bytes());
            next.extend_from_slice(&inner);
            inner = next;
        } else {
            let mut body = vec![0u8, b'F'];
            body.extend_from_slice(&(inner.len() as u32).to_be_bytes());
            body.extend_from_slice(&inner);
            let mut next = vec![b'F'];
            next.extend_from_slice(&(body.len() as u32).to_be_bytes());
            next.extend_from_slice(&body);
            inner = next;
        }
    }
    let wire = table_of(b"x", inner);

    let mut d = Decoder::new(&wire);
    let table = d.field_table().expect("the outer table is well-formed");
    let depth = json_depth(&table);
    assert!(
        depth <= DEPTH_BOUND + 2,
        "alternating arms must not escape the depth bound, got depth {depth}"
    );
}
