//! OpenID Connect's connection bounds, driven from the wire.
//!
//! `src/server/openid/mod.rs` declares three numbers and argues each beside itself:
//! `FIRST_BYTE_READ_TIMEOUT` (30s — HTTP is client-speaks-first, so a peer that has sent no byte
//! has asked nothing), `IDLE_BETWEEN_REQUESTS_TIMEOUT` (60s — between Apache's browser-tuned
//! `KeepAliveTimeout` of 5s and nginx's pool-tuned 75s, because both kinds of client reach these
//! endpoints.) and
//! `MAX_CONNECTIONS` (256). A bound nobody tested is a comment, so these drive all three from
//! a socket.
//!
//! The mechanics, the three-socket design and the removal-verification notes are in
//! `tests/helpers/http_bounds.rs`; this file supplies only what is specific to OpenID Connect.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openid \
//!       --test server -- server::openid::connection_bounds_test --test-threads=100

mod openid_connection_bounds {
    use crate::helpers::http_bounds::{
        assert_connection_cap, assert_read_deadlines, HttpBoundsCase,
    };
    use crate::helpers::E2EResult;

    /// The numbers exactly as `src/server/openid/mod.rs` declares them. Copied on purpose: if one
    /// of them moves, this file should be re-read rather than silently follow.
    fn case() -> HttpBoundsCase {
        HttpBoundsCase {
            base_stack: "openid",
            label: "OpenID-bounds",
            max_connections: 256,
            idle_secs: 60,
            startup_params: None,
            // Any path: this server raises its request event before routing, so a bare GET
            // is enough to park one and hold the connection busy.
            event_request: b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n",
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
