//! HSRP server tests.
//!
//! * `codec_test` is pure — no socket, no LLM. It owns the authentication field, the one place
//!   in HSRP where a string crosses between the wire, the model and a log line.
//! * `e2e_test` binds a real UDP socket (port 1985 is unprivileged, so the transport genuinely
//!   executes) and pins both wire layouts byte for byte through a running server.

mod codec_test;

mod e2e_test;
