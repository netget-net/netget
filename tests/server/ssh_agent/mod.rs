#[cfg(unix)]
mod e2e_test;

// Wire-format unit tests (no server, no LLM).
#[cfg(unix)]
mod test;

// Executor-level assertions on the two actions that carry key material.
#[cfg(unix)]
mod executor_test;

// The connection cap and both read deadlines, from the peer's side.
#[cfg(unix)]
mod connection_bounds_test;
