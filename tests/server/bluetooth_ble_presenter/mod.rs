//! BLE presentation clicker tests

#[cfg(all(unix, feature = "bluetooth"))]
mod e2e_test;
#[cfg(all(unix, feature = "bluetooth"))]
mod gatt_examples_test;
#[cfg(all(unix, feature = "bluetooth"))]
mod report_descriptor_test;
