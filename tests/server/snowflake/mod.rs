//! Snowflake server E2E tests.
pub mod e2e_test;
pub mod llm_failure_test;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
mod connection_bounds_test;

/// NetGet's server against snowflake-connector-python, Snowflake's official Python driver.
mod real_client_test;
