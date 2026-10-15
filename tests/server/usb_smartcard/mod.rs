#[cfg(all(unix, feature = "libusb"))]
mod e2e_test;

#[cfg(all(unix, feature = "libusb"))]
mod llm_failure_test;

#[cfg(all(unix, feature = "libusb"))]
mod connection_bounds_test;
