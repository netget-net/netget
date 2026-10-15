//! XMPP server E2E tests

#[cfg(unix)]
pub mod test;

#[cfg(unix)]
pub mod peer_inject_test;

#[cfg(unix)]
pub mod llm_failure_test;

#[cfg(unix)]
pub mod connection_bounds_test;

#[cfg(unix)]
pub mod xml_escape_test;
