pub mod e2e_test;
#[cfg(target_os = "linux")]
pub mod real_server_test;
/// The slave harness, shared with the server suite.
#[path = "../../server/ethercat/support.rs"]
pub mod support;
