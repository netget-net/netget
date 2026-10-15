#[cfg(all(test, feature = "yarn"))]
pub mod e2e_test;
#[cfg(all(test, feature = "yarn"))]
pub mod llm_failure_test;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
#[cfg(all(test, feature = "yarn"))]
mod connection_bounds_test;

/// Datadog's YARN integration, an independent consumer of the RM REST API, against the server.
#[cfg(all(test, feature = "yarn"))]
mod datadog_check_test;
