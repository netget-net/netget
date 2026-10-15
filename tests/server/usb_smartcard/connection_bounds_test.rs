//! The read deadlines on a real, running USB smart card server, driven from a raw socket.
//!
//! The mechanics and the full argument are in `tests/helpers/usbip_bounds.rs`, because all six
//! USB servers hand their socket to the same screen (`src/server/usb/guard.rs`) and there is
//! exactly one place in the process that reads from it. This file supplies what is specific to
//! USB smart card: its registry name, and the sentence below.
//!
//! A CCID reader answers every bulk message synchronously — an APDU the model has not answered
//! yet comes back as the card's own 'not ready' rather than by holding the URB — so the idle
//! bound never counts a model round-trip here either.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features usb-smartcard --test server -- \
//!       usb_smartcard::connection_bounds --test-threads=100

#![cfg(all(unix, feature = "libusb"))]

use crate::helpers::usbip_bounds;

/// The canonical registry name (`src/protocol/server_registry.rs`).
const PROTOCOL: &str = "usb-smartcard";

#[tokio::test]
async fn a_peer_that_connects_and_speaks_no_usbip_is_closed_at_the_first_message_bound(
) -> crate::helpers::E2EResult<()> {
    usbip_bounds::silent_peer_is_closed_at_the_first_message_bound(PROTOCOL).await
}

#[tokio::test]
async fn once_a_message_has_been_admitted_the_idle_bound_governs() -> crate::helpers::E2EResult<()>
{
    usbip_bounds::an_admitted_session_is_governed_by_the_idle_bound(PROTOCOL).await
}
