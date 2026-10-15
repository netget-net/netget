//! The read deadlines on a real, running USB keyboard server, driven from a raw socket.
//!
//! The mechanics and the full argument are in `tests/helpers/usbip_bounds.rs`, because all six
//! USB servers hand their socket to the same screen (`src/server/usb/guard.rs`) and there is
//! exactly one place in the process that reads from it. This file supplies what is specific to
//! USB keyboard: its registry name, and the sentence below.
//!
//! A host with a HID keyboard bound polls the interrupt endpoint every 10ms, so it looks busy
//! whatever the idle bound is. That is a property of the host's driver, not of USB/IP, and it is
//! why the number is argued against the protocol rather than against this device.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features usb-keyboard --test server -- \
//!       usb_keyboard::connection_bounds --test-threads=100

#![cfg(all(unix, feature = "libusb"))]

use crate::helpers::usbip_bounds;

/// The canonical registry name (`src/protocol/server_registry.rs`).
const PROTOCOL: &str = "USB-Keyboard";

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

/// The default is the one number a person can get wrong by copying the neighbouring protocol,
/// so it is asserted once, here, for the whole family: the two bounds are 30 and 1800 seconds
/// and collapsing them onto one short number would close an attached host at 30 seconds.
#[tokio::test]
async fn the_defaults_leave_an_attached_and_quiet_host_alone() -> crate::helpers::E2EResult<()> {
    usbip_bounds::an_admitted_session_outlives_the_first_message_default(PROTOCOL).await
}
