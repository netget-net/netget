//! M3UA (RFC 4666) test module.

#[cfg(unix)]
pub mod codec_test;

#[cfg(unix)]
pub mod transport_test;

#[cfg(unix)]
pub mod e2e_test;

#[cfg(unix)]
pub mod ss7_support;

#[cfg(unix)]
pub mod ss7_codec_test;

#[cfg(all(unix, target_os = "linux"))]
pub mod ss7_live;

#[cfg(all(unix, target_os = "linux"))]
pub mod real_peer_test;

#[cfg(all(unix, target_os = "linux"))]
pub mod osmo_stp_test;

#[cfg(unix)]
pub mod ss7_e2e_test;
