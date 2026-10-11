#[cfg(all(test, feature = "dns"))]
pub mod e2e_test;

#[cfg(all(test, feature = "dns"))]
pub mod command_channel_test;
#[cfg(all(test, feature = "dns"))]
mod real_server_test;
#[cfg(all(test, feature = "dns"))]
mod transfer_bound_test;
