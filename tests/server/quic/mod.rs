//! QUIC protocol tests (raw QUIC streams, not HTTP/3 - see src/server/quic/AGENTS.md)

mod e2e_test;

mod llm_failure_test;

mod independent_peer_test;

mod certificate_validation_test;

mod state_contention_test;

mod datagram_test;
