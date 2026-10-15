//! OCI registry's connection bounds, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time, so a
//! peer that connected and said nothing held a socket, a connection task and an `AppState` entry
//! forever, pre-authentication, on a server that would happily accept 255 more. The pair of
//! bounds and the cap that close that are declared in `src/server/oci_registry/mod.rs`; this file is the
//! evidence they are wired rather than merely written down.
//!
//! Each check fails without the thing it tests — see `tests/helpers/http_bounds.rs`, which states
//! how, and holds the assertions shared by the eleven hyper servers in this family.
//!
//! The second check is the one specific to OCI registry: crane pulls a manifest and then each blob, writing layers to disk in between.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features oci-registry --test server -- \
//!       oci_registry::connection_bounds --test-threads=100


use std::time::Duration;

use crate::helpers::http_bounds::HttpBounds;

/// The numbers `src/server/oci_registry/mod.rs` declares. Copied rather than imported, deliberately: a
/// changed bound should make someone re-read this file, not be followed silently.
fn bounds() -> HttpBounds {
    HttpBounds {
        protocol: "oci-registry",
        label: "OCI registry",
        first_byte: Duration::from_secs(30),
        idle: Duration::from_secs(300),
        max_connections: 256,
        probe: "GET /v2/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    }
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_byte_bound() {
    bounds()
        .silent_peer_is_closed_at_the_first_byte_bound()
        .await;
}

#[tokio::test]
async fn an_answered_connection_outlives_the_first_byte_bound() {
    bounds()
        .an_answered_connection_outlives_the_first_byte_bound()
        .await;
}

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_and_the_slot_comes_back() {
    bounds()
        .the_connection_past_the_cap_is_refused_and_the_slot_comes_back()
        .await;
}
