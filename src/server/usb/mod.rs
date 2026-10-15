//! USB protocol implementations
//!
//! This module provides virtual USB device protocols using USB/IP. Each is its
//! own Cargo feature, and each enables the shared `usb-common` feature that
//! gates `common` (USB constant tables) and `descriptors` (descriptor builders):
//!
//! - usb-keyboard: HID Keyboard device
//! - usb-mouse: HID Mouse device
//! - usb-serial: CDC ACM Serial device
//! - usb-msc: Mass Storage Class device (flash drive/disk)
//! - usb-fido2: FIDO2/U2F Security Key device
//! - usb-smartcard: Smart Card (CCID) device over USB/IP (no external daemon)
//!
//! The separate `usb` feature is the USB *client* (`nusb`) in `src/client/usb`,
//! not a server, and does not build anything in this module.

#[cfg(all(unix, feature = "libusb"))]
pub mod common;

#[cfg(all(unix, feature = "libusb"))]
pub mod descriptors;

/// The USB/IP message screen every USB server runs the `usbip` crate behind.
#[cfg(all(unix, feature = "libusb"))]
pub mod guard;

#[cfg(all(unix, feature = "libusb"))]
pub mod keyboard;

#[cfg(all(unix, feature = "libusb"))]
pub mod mouse;

#[cfg(all(unix, feature = "libusb"))]
pub mod serial;

#[cfg(all(unix, feature = "libusb"))]
pub mod msc;

#[cfg(all(unix, feature = "libusb"))]
pub mod fido2;

#[cfg(all(unix, feature = "libusb"))]
pub mod smartcard;

// Re-export protocol implementations
#[cfg(all(unix, feature = "libusb"))]
pub use keyboard::UsbKeyboardProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use mouse::UsbMouseProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use serial::actions::UsbSerialProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use msc::UsbMscProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use fido2::actions::UsbFido2Protocol;

#[cfg(all(unix, feature = "libusb"))]
pub use smartcard::actions::UsbSmartCardProtocol;
