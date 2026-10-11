//! QUIC protocol tests (raw QUIC streams, not HTTP/3 - see src/server/quic/AGENTS.md)

#[cfg(all(test, feature = "quic"))]
mod e2e_test;

#[cfg(all(test, feature = "quic"))]
mod llm_failure_test;

mod independent_peer_test;

#[cfg(all(test, feature = "quic"))]
mod certificate_validation_test;

#[cfg(all(test, feature = "quic"))]
mod state_contention_test;

#[cfg(all(test, feature = "quic"))]
mod datagram_test;
