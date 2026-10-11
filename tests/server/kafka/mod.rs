//! Kafka protocol E2E tests

#[cfg(all(test, feature = "kafka"))]
pub mod connection_task_cleanup_test;
#[cfg(all(test, feature = "kafka"))]
pub mod declared_array_length_test;
#[cfg(all(test, feature = "kafka"))]
pub mod e2e_test;
#[cfg(all(test, feature = "kafka"))]
pub mod flexible_versions_test;
#[cfg(all(test, feature = "kafka"))]
pub mod peer_inject_test;
#[cfg(all(test, feature = "kafka"))]
pub mod real_client_test;
