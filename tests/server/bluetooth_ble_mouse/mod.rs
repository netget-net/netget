//! BLE HID Mouse tests

#![cfg(all(unix, feature = "bluetooth"))]

mod decision_tag_test;
mod e2e_test;
mod report_descriptor_test;
