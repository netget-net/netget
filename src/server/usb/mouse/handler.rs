//! USB HID mouse handler
//!
//! The `usbip` crate ships `hid::UsbHidKeyboardHandler` but has no mouse equivalent, so this
//! implements `UsbInterfaceHandler` directly. It is the same shape as the crate's keyboard
//! handler: a queue of pending reports, drained one per interrupt-IN URB, with an automatic
//! all-zero "release" report after any report that holds a button down, so a click does not
//! stick.

#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::descriptors::{build_hid_mouse_report_descriptor, MouseReport};
#[cfg(all(unix, feature = "libusb"))]
use std::collections::VecDeque;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, trace, warn};

/// HID descriptor type codes (HID 1.11 section 7.1).
#[cfg(all(unix, feature = "libusb"))]
mod hid_descriptor_type {
    pub const HID: u8 = 0x21;
    pub const REPORT: u8 = 0x22;
}

/// A virtual USB HID mouse.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct UsbHidMouseHandler {
    /// HID report descriptor handed to the host on GET_DESCRIPTOR(Report)
    report_descriptor: Vec<u8>,
    /// Reports waiting to be delivered on the next interrupt-IN URBs
    pending_reports: VecDeque<[u8; 4]>,
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for UsbHidMouseHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbHidMouseHandler {
    pub fn new() -> Self {
        Self {
            report_descriptor: build_hid_mouse_report_descriptor(),
            pending_reports: VecDeque::new(),
        }
    }

    /// The endpoint set a HID mouse needs: a single interrupt IN endpoint.
    pub fn endpoints() -> Vec<usbip::UsbEndpoint> {
        vec![usbip::UsbEndpoint {
            address: 0x81,      // EP1 IN
            attributes: 0x03,   // Interrupt
            max_packet_size: 4, // buttons, dx, dy, wheel
            interval: 10,       // 10ms polling
        }]
    }

    /// Queue a single report.
    pub fn queue(&mut self, report: MouseReport) {
        trace!(
            "USB mouse queue report: buttons={:#04x} x={} y={} wheel={}",
            report.buttons,
            report.x,
            report.y,
            report.wheel
        );
        self.pending_reports.push_back(report.to_bytes());
    }

    /// Queue a report that holds buttons down, followed by the matching release.
    ///
    /// Without the trailing all-zero report the host sees the button as still held, which is
    /// how a "click" turns into a stuck drag.
    pub fn queue_with_release(&mut self, report: MouseReport) {
        let held = report.buttons != 0;
        self.queue(report);
        if held {
            self.queue(MouseReport::new());
        }
    }

    /// Number of reports still waiting to go out (used by tests and diagnostics).
    #[allow(dead_code)]
    pub fn pending_len(&self) -> usize {
        self.pending_reports.len()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl usbip::UsbInterfaceHandler for UsbHidMouseHandler {
    fn handle_urb(
        &mut self,
        _interface: &usbip::UsbInterface,
        ep: usbip::UsbEndpoint,
        _transfer_buffer_length: u32,
        setup: usbip::SetupPacket,
        _req: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        if ep.is_ep0() {
            // Control transfers on endpoint 0.
            match (setup.request_type, setup.request) {
                // GET_DESCRIPTOR (device-to-host, standard, interface)
                (0b1000_0001, 0x06) => {
                    let desc_type = (setup.value >> 8) as u8;
                    if desc_type == hid_descriptor_type::REPORT {
                        debug!(
                            "USB mouse GET_DESCRIPTOR(Report): {} bytes",
                            self.report_descriptor.len()
                        );
                        Ok(self.report_descriptor.clone())
                    } else {
                        warn!("USB mouse: unsupported descriptor type {:#04x}", desc_type);
                        Ok(vec![])
                    }
                }
                // SET_IDLE / SET_PROTOCOL (host-to-device, class, interface)
                (0b0010_0001, 0x0A) | (0b0010_0001, 0x0B) => Ok(vec![]),
                // GET_REPORT (device-to-host, class, interface): answer with current state.
                (0b1010_0001, 0x01) => Ok(self
                    .pending_reports
                    .front()
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![0u8; 4])),
                _ => {
                    // Unknown control requests are answered empty rather than with an error:
                    // an error aborts the USB/IP session for the whole device, and a host
                    // probing an optional request must not disconnect the mouse.
                    debug!(
                        "USB mouse: unhandled control request type={:#04x} request={:#04x}",
                        setup.request_type, setup.request
                    );
                    Ok(vec![])
                }
            }
        } else if let usbip::Direction::In = ep.direction() {
            // Interrupt IN: hand the host the next queued report, or nothing.
            Ok(self
                .pending_reports
                .pop_front()
                .map(|r| r.to_vec())
                .unwrap_or_default())
        } else {
            // A boot-protocol mouse has no OUT endpoint; ignore anything that arrives.
            Ok(vec![])
        }
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        let len = self.report_descriptor.len();
        vec![
            0x09,                     // bLength
            hid_descriptor_type::HID, // bDescriptorType: HID
            0x11,
            0x01,                        // bcdHID 1.11
            0x00,                        // bCountryCode
            0x01,                        // bNumDescriptors
            hid_descriptor_type::REPORT, // bDescriptorType[0]
            len as u8,
            (len >> 8) as u8, // wDescriptorLength[0]
        ]
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
