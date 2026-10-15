pub mod e2e_test;
pub mod llm_failure_test;
pub mod required_fields_test;
// The peer-handle test needs only the server: it speaks raw OP_MSG rather than driving the
// `mongodb` client crate, so it is gated on `mongodb-server` alone.
pub mod peer_inject_test;
// Deadlines only: raw sockets, no BSON driver, so the server feature alone is enough.
pub mod connection_bounds_test;
pub mod real_client_test;
// Raw OP_MSG over a socket; decodes replies with `bson`, which `mongodb-server` already brings.
pub mod bson_depth_test;
// Raw OP_MSG kind-1 sections, plus one driver test gated inside the file on `mongodb`.
pub mod document_sequence_test;
