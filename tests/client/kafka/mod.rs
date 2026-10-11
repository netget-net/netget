//! Kafka client tests

#[cfg(all(test, feature = "kafka"))]
mod command_channel_test;
#[cfg(all(test, feature = "kafka"))]
mod e2e_test;
#[cfg(all(test, feature = "kafka"))]
pub mod real_server_test;
