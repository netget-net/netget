//! PyPI protocol tests

pub mod e2e_test;

pub mod e2e_test_mocked;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
mod connection_bounds_test;
