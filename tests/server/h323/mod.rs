//! H.323 server suites: the PER/Q.931 codec against tshark, NetGet's own client against its
//! gatekeeper and endpoint, and real H.323 stacks against both.
pub mod codec_test;
pub mod e2e_test;
pub mod real_peer_test;
pub mod support;
