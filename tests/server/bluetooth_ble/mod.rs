//! Bluetooth LE GATT server tests

#![cfg(all(unix, feature = "bluetooth"))]

mod e2e_test;
mod llm_failure_test;
mod read_default_value_test;
mod shared_peripheral_routing_test;
