// The server suite's helpers (SCTP framing for the oracle, the lab framing, the live capture),
// compiled into this test crate too rather than copied.
#[path = "../../server/ngap/support.rs"]
pub mod support;

pub mod bounds_test;
#[cfg(target_os = "linux")]
pub mod real_server_test;
pub mod security_lab_test;
