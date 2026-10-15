//! M3UA (RFC 4666) test module.

#[cfg(all(test, feature = "m3ua"))]
pub mod codec_test;

#[cfg(all(test, feature = "m3ua"))]
pub mod transport_test;

#[cfg(all(test, feature = "m3ua"))]
pub mod e2e_test;

#[cfg(all(test, feature = "m3ua"))]
pub mod ss7_support;

#[cfg(all(test, feature = "m3ua"))]
pub mod ss7_codec_test;

#[cfg(all(test, feature = "m3ua", target_os = "linux"))]
pub mod ss7_live;

#[cfg(all(test, feature = "m3ua", target_os = "linux"))]
pub mod real_peer_test;

#[cfg(all(test, feature = "m3ua", target_os = "linux"))]
pub mod osmo_stp_test;

#[cfg(all(test, feature = "m3ua"))]
pub mod ss7_e2e_test;
