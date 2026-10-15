//! JSON-RPC's connection bounds, driven from the wire.
//!
//! `src/server/jsonrpc/mod.rs` declares three numbers and argues each beside itself:
//! `FIRST_BYTE_READ_TIMEOUT` (30s — HTTP is client-speaks-first, so a peer that has sent no byte
//! has asked nothing), `IDLE_BETWEEN_REQUESTS_TIMEOUT` (75s — five minutes' worth of application
//! think time is not needed: a long poll is a request in flight, so nginx's `keepalive_timeout`
//! covers the only thing this bound measures.) and
//! `MAX_CONNECTIONS` (256). A bound nobody tested is a comment, so these drive all three from
//! a socket.
//!
//! The mechanics, the three-socket design and the removal-verification notes are in
//! `tests/helpers/http_bounds.rs`; this file supplies only what is specific to JSON-RPC.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features jsonrpc \
//!       --test server -- server::jsonrpc::connection_bounds_test --test-threads=100

mod jsonrpc_connection_bounds {
    use crate::helpers::http_bounds::{
        assert_connection_cap, assert_read_deadlines, HttpBoundsCase,
    };
    use crate::helpers::E2EResult;

    /// The numbers exactly as `src/server/jsonrpc/mod.rs` declares them. Copied on purpose: if one
    /// of them moves, this file should be re-read rather than silently follow.
    fn case() -> HttpBoundsCase {
        HttpBoundsCase {
            base_stack: "jsonrpc",
            label: "JSON-RPC-bounds",
            max_connections: 256,
            idle_secs: 75,
            startup_params: None,
            // A POST carrying a JSON-RPC envelope: a GET raises no jsonrpc_method_call, and a
            // request that raises no event would be idle rather than busy, which is a different test.
            event_request: b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}",
        }
    }

    #[tokio::test]
    async fn the_connection_cap_refuses_over_the_limit_in_http_s_own_vocabulary() -> E2EResult<()> {
        assert_connection_cap(&case()).await
    }

    #[tokio::test]
    async fn a_silent_or_stalled_peer_is_closed_and_a_parked_one_is_not() -> E2EResult<()> {
        assert_read_deadlines(&case()).await
    }
}
