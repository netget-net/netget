//! MQTT protocol E2E tests

#[cfg(all(test, feature = "mqtt"))]
mod answer_with_test;
#[cfg(all(test, feature = "mqtt"))]
mod connection_bounds_test;

#[cfg(all(test, feature = "mqtt"))]
pub mod e2e_test;
#[cfg(all(test, feature = "mqtt"))]
pub mod llm_failure_test;
#[cfg(all(test, feature = "mqtt"))]
pub mod peer_inject_test;
#[cfg(all(test, feature = "mqtt"))]
pub mod real_client_test;
#[cfg(all(test, feature = "mqtt"))]
pub mod v5_real_client_test;
#[cfg(all(test, feature = "mqtt"))]
mod v5_property_limits_test;
#[cfg(all(test, feature = "mqtt"))]
pub mod v5_wire_test;
