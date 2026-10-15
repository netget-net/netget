//! USB HID keyboard handler.
//!
//! Wraps `usbip::hid::UsbHidKeyboardHandler` rather than replacing it: the crate's key-down /
//! key-up state machine on the interrupt IN endpoint is exactly right, and reimplementing it
//! would be a second copy to keep in step. Everything on **endpoint 0** is handled here
//! instead, for two reasons.
//!
//! **1. LED output reports.** A host tells a keyboard about Caps/Num/Scroll Lock with a class
//! `SET_REPORT` on the control endpoint (the device has no OUT endpoint). The crate's handler
//! never sees it, which is why `usb_keyboard_led_status` was a declared event with no emit site
//! for its entire existence — advertised to the model, unable to fire. This intercepts it and
//! reports the LED byte on a channel; `mod.rs` turns that into the event.
//!
//! **2. The crate panics on anything else.** `UsbHidKeyboardHandler::handle_urb` ends its
//! control arm with `unimplemented!("hid request {:?}", setup)`, and `handle_urb` is called from
//! a tokio worker inside the USB/IP session task. A host issuing `GET_PROTOCOL`, `GET_IDLE`, a
//! `GET_REPORT`, or the very `SET_REPORT` above would take the connection down with a panic
//! rather than get an answer — and `SET_REPORT` is not exotic: pressing Caps Lock sends one.
//! Unknown control requests are answered empty here, because returning an error aborts the
//! USB/IP session for the whole device and a host probing an optional request must not
//! disconnect the keyboard.

#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::mpsc::UnboundedSender;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, trace, warn};
#[cfg(all(unix, feature = "libusb"))]
use usbip::hid::{UsbHidKeyboardHandler, UsbHidKeyboardReport};

/// HID descriptor type codes (HID 1.11 §7.1).
#[cfg(all(unix, feature = "libusb"))]
mod hid_descriptor_type {
    pub const REPORT: u8 = 0x22;
}

/// The LED byte a host writes with `SET_REPORT`, decoded (HID Usage Tables, LED page).
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedState {
    pub raw: u8,
}

#[cfg(all(unix, feature = "libusb"))]
impl LedState {
    pub fn num_lock(&self) -> bool {
        self.raw & 0x01 != 0
    }
    pub fn caps_lock(&self) -> bool {
        self.raw & 0x02 != 0
    }
    pub fn scroll_lock(&self) -> bool {
        self.raw & 0x04 != 0
    }
    pub fn compose(&self) -> bool {
        self.raw & 0x08 != 0
    }
    pub fn kana(&self) -> bool {
        self.raw & 0x10 != 0
    }
}

/// A virtual USB HID keyboard that also reports LED changes.
#[cfg(all(unix, feature = "libusb"))]
pub struct NetGetKeyboardHandler {
    inner: UsbHidKeyboardHandler,
    /// Where LED changes are posted for the connection task. Unbounded because
    /// `UnboundedSender::send` is synchronous, and this is reached from `handle_urb`, which
    /// cannot await — the same seam `usb/msc` uses for sector transfers.
    led_tx: Option<UnboundedSender<LedState>>,
    /// Whether the last report handed out held a key down and still needs its release.
    key_is_down: bool,
    /// Last state reported, so an unchanged repeat does not raise an event. A host re-sends the
    /// full LED byte on every change to *any* LED, and X11 in particular re-asserts it
    /// periodically; without this the model gets woken by a stream of identical events.
    last_led: Option<LedState>,
}

#[cfg(all(unix, feature = "libusb"))]
impl std::fmt::Debug for NetGetKeyboardHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetGetKeyboardHandler")
            .field("pending_key_events", &self.inner.pending_key_events.len())
            .field("last_led", &self.last_led)
            .finish()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for NetGetKeyboardHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl NetGetKeyboardHandler {
    pub fn new() -> Self {
        Self {
            inner: UsbHidKeyboardHandler::new_keyboard(),
            led_tx: None,
            key_is_down: false,
            last_led: None,
        }
    }

    /// Attach the channel LED changes are reported on.
    pub fn with_led_events(mut self, led_tx: UnboundedSender<LedState>) -> Self {
        self.led_tx = Some(led_tx);
        self
    }

    /// Queue a report to be delivered on the next interrupt-IN URB.
    pub fn queue(&mut self, report: UsbHidKeyboardReport) {
        self.inner.pending_key_events.push_back(report);
    }

    /// How many reports are still waiting (tests and diagnostics).
    #[allow(dead_code)]
    pub fn pending_len(&self) -> usize {
        self.inner.pending_key_events.len()
    }

    /// The last LED state the host set, if it has set one.
    #[allow(dead_code)]
    pub fn led_state(&self) -> Option<LedState> {
        self.last_led
    }

    fn report_descriptor(&self) -> Vec<u8> {
        self.inner.report_descriptor.clone()
    }

    /// The next 8-byte input report to hand the host: a key-down, then its release.
    ///
    /// This is the crate's state machine reimplemented for one reason: the crate answers a
    /// release with `vec![0; 6]`. A boot-protocol keyboard report is **8 bytes** (modifier,
    /// reserved, six key slots), and a short release is not the report a host is decoding — it
    /// is a different message with the same intent, which a strict HID parser reads as
    /// malformed rather than as "all keys up".
    fn next_input_report(&mut self) -> Vec<u8> {
        if self.key_is_down {
            self.key_is_down = false;
            trace!("USB keyboard: key up");
            return vec![0u8; 8];
        }

        match self.inner.pending_key_events.pop_front() {
            Some(report) => {
                let mut out = Vec::with_capacity(8);
                out.push(report.modifier);
                out.push(0); // reserved
                out.extend_from_slice(&report.keys);
                self.key_is_down = true;
                trace!(
                    "USB keyboard: key down modifier={:#04x} keys={:?}",
                    report.modifier,
                    report.keys
                );
                out
            }
            // Nothing queued. An empty URB response is how this transport says "no report".
            None => Vec::new(),
        }
    }

    /// Record an LED byte and report it if it changed.
    fn set_leds(&mut self, raw: u8) {
        let state = LedState { raw };
        if self.last_led == Some(state) {
            trace!("USB keyboard LED report unchanged ({:#04x})", raw);
            return;
        }
        self.last_led = Some(state);
        debug!(
            "USB keyboard LEDs: num={} caps={} scroll={} (raw {:#04x})",
            state.num_lock(),
            state.caps_lock(),
            state.scroll_lock(),
            raw
        );
        if let Some(ref tx) = self.led_tx {
            // The connection task may already be gone; that is not an error here.
            let _ = tx.send(state);
        }
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl usbip::UsbInterfaceHandler for NetGetKeyboardHandler {
    fn handle_urb(
        &mut self,
        interface: &usbip::UsbInterface,
        ep: usbip::UsbEndpoint,
        transfer_buffer_length: u32,
        setup: usbip::SetupPacket,
        req: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        if !ep.is_ep0() {
            let _ = (interface, transfer_buffer_length, req);
            if let usbip::Direction::In = ep.direction() {
                return Ok(self.next_input_report());
            }
            // A boot keyboard has no OUT endpoint; LEDs arrive as SET_REPORT on ep0.
            return Ok(vec![]);
        }

        match (setup.request_type, setup.request) {
            // GET_DESCRIPTOR (device-to-host, standard, interface)
            (0b1000_0001, 0x06) => {
                let desc_type = (setup.value >> 8) as u8;
                if desc_type == hid_descriptor_type::REPORT {
                    Ok(self.report_descriptor())
                } else {
                    warn!(
                        "USB keyboard: unsupported descriptor type {:#04x}",
                        desc_type
                    );
                    Ok(vec![])
                }
            }

            // SET_REPORT (host-to-device, class, interface). wValue high byte 0x02 is an
            // Output report, which for a keyboard is the LED byte.
            (0b0010_0001, 0x09) => {
                let report_type = (setup.value >> 8) as u8;
                if report_type == 0x02 {
                    match req.first() {
                        Some(&leds) => self.set_leds(leds),
                        None => warn!("USB keyboard SET_REPORT(Output) carried no data"),
                    }
                } else {
                    debug!(
                        "USB keyboard SET_REPORT of type {:#04x} ignored",
                        report_type
                    );
                }
                Ok(vec![])
            }

            // GET_REPORT (device-to-host, class, interface): the current LED byte.
            (0b1010_0001, 0x01) => Ok(vec![self.last_led.map_or(0, |s| s.raw)]),

            // GET_IDLE / GET_PROTOCOL (device-to-host, class, interface)
            (0b1010_0001, 0x02) => Ok(vec![0]), // report protocol
            (0b1010_0001, 0x03) => Ok(vec![0]), // idle: indefinite

            // SET_IDLE / SET_PROTOCOL (host-to-device, class, interface)
            (0b0010_0001, 0x0A) | (0b0010_0001, 0x0B) => Ok(vec![]),

            _ => {
                // Empty rather than an error: an error aborts the USB/IP session for the whole
                // device, and the crate's own handler panicked here.
                debug!(
                    "USB keyboard: unhandled control request type={:#04x} request={:#04x}",
                    setup.request_type, setup.request
                );
                Ok(vec![])
            }
        }
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        self.inner.get_class_specific_descriptor()
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
