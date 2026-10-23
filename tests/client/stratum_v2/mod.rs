pub mod bounds_test;
pub mod job_declarator_test;
/// Regtest and SRI peers, shared with the server tests.
#[path = "../../server/stratum_v2/peers.rs"]
#[allow(dead_code)]
pub mod peers;
pub mod real_server_test;
pub mod template_client_test;
