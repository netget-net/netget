//! BLE HID Keyboard tests

#![cfg(all(unix, feature = "bluetooth"))]

mod decision_tag_test;
mod e2e_test;
/// The HID report-descriptor walker, shared with the mouse, gamepad and remote suites via
/// `#[path]`. It lives here rather than in `tests/helpers/` so that it stays inside the BLE
/// HID profile boundary: `tests/helpers/mod.rs` is shared with every protocol in the tree.
mod hid_descriptor;
mod report_descriptor_test;
