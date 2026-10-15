//! OCI Distribution v2 container-registry protocol tests

/// Pure protocol logic: digest computation, path parsing, descriptor rewriting.
/// No LLM calls, no sockets.
mod digest_test;

mod schema_guard_test;

/// Mocked end-to-end tests over real HTTP, plus a `crane`-driven test that runs
/// only where the binary is installed.
mod e2e_test;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
mod connection_bounds_test;
