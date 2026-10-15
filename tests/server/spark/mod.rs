#[cfg(all(test, feature = "spark"))]
pub mod datadog_check_test;
#[cfg(all(test, feature = "spark"))]
pub mod e2e_test;
#[cfg(all(test, feature = "spark"))]
pub mod llm_failure_test;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
#[cfg(all(test, feature = "spark"))]
mod connection_bounds_test;
