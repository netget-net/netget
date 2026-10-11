#[cfg(all(test, feature = "dns"))]
mod bounds_test;
#[cfg(all(test, feature = "dns"))]
mod dig_test;
#[cfg(feature = "dns")]
pub mod dnssec_test;
#[cfg(all(test, feature = "dns"))]
pub mod kdig_test;
#[cfg(all(test, feature = "dns"))]
mod llm_failure_test;
#[cfg(all(test, feature = "dns"))]
mod test;
#[cfg(feature = "dns")]
pub mod transfer_test;
#[cfg(feature = "dns")]
pub mod transport_bounds_test;
#[cfg(feature = "dns")]
pub mod zone_support;
