// The server suite's SS7 helpers (jSS7's captured messages, the live capture, the driver),
// compiled into this test crate too rather than copied.
#[path = "../../server/m3ua/ss7_support.rs"]
pub mod support;
#[cfg(target_os = "linux")]
#[path = "../../server/m3ua/ss7_live.rs"]
pub mod live;

pub mod bounds_test;
#[cfg(target_os = "linux")]
pub mod osmo_stp_test;
#[cfg(target_os = "linux")]
pub mod real_server_test;
