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
