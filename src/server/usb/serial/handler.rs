//! USB CDC ACM interface handler.
//!
//! `usbip` 0.9 ships `cdc::UsbCdcAcmHandler`, but it is a demo: a host write on the bulk OUT
//! endpoint is logged and thrown away, and the class-specific control requests that make a
//! serial port a serial port (`SET_LINE_CODING`, `GET_LINE_CODING`,
//! `SET_CONTROL_LINE_STATE`) are not handled at all. Both matter here — without the first,
//! `usb_serial_data_received` can never fire; without the second, a host that opens the port
//! and configures it gets no answer.
//!
//! So the CDC *descriptors* and the endpoint layout are taken from the crate (it is the
//! authority on what a CDC ACM interface looks like on the wire) while the URB handling is
//! implemented here.

#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::descriptors::{ControlLineState, LineCoding};
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::mpsc;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, trace, warn};

/// CDC class-specific requests (CDC PSTN 1.2, table 13).
#[cfg(all(unix, feature = "libusb"))]
mod cdc_request {
    pub const SET_LINE_CODING: u8 = 0x20;
    pub const GET_LINE_CODING: u8 = 0x21;
    pub const SET_CONTROL_LINE_STATE: u8 = 0x22;
    pub const SEND_BREAK: u8 = 0x23;
}

/// `bmRequestType` values for class requests addressed to an interface.
#[cfg(all(unix, feature = "libusb"))]
mod request_type {
    /// Host-to-device, class, interface.
    pub const CLASS_INTERFACE_OUT: u8 = 0b0010_0001;
    /// Device-to-host, class, interface.
    pub const CLASS_INTERFACE_IN: u8 = 0b1010_0001;
}

/// CDC class-specific notifications (CDC PSTN 1.2, table 30), sent on the interrupt IN endpoint.
#[cfg(all(unix, feature = "libusb"))]
mod cdc_notification {
    /// `bmRequestType` for a device-to-host class notification about an interface.
    pub const REQUEST_TYPE: u8 = 0b1010_0001;
    /// `SERIAL_STATE` (CDC PSTN 1.2 §6.5.4): the UART state bitmap.
    pub const SERIAL_STATE: u8 = 0x20;

    /// `bOverRun` (D6) — "received data has been discarded due to overrun in the device".
    pub const UART_STATE_OVERRUN: u16 = 1 << 6;
}

/// Most device-to-host bytes held waiting for the host's bulk IN URBs.
///
/// The model fills this buffer and the host drains it, so with no cap the model's pace decides
/// how much memory a port holds and a host that never polls never gives any of it back.
/// 64 KiB is several seconds of traffic at 115200 baud, the port's own default line rate.
#[cfg(all(unix, feature = "libusb"))]
const MAX_TX_BUFFER: usize = 64 * 1024;

/// A virtual CDC ACM serial port.
///
/// `Debug` is required by `usbip::UsbInterfaceHandler` as of 0.9. It is derived: the only
/// buffered content is bytes the LLM asked to send, which are already logged at TRACE.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct UsbCdcAcmSerialHandler {
    /// Device-to-host bytes, drained by bulk IN URBs.
    tx_buffer: Vec<u8>,
    /// Host-to-device bytes. Handed to the connection task, which raises
    /// `usb_serial_data_received`; `handle_urb` is sync and cannot call the LLM itself.
    rx_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Line parameters the port reports back on `GET_LINE_CODING`.
    line_coding: LineCoding,
    /// DTR/RTS as last set by the host.
    control_lines: ControlLineState,
    /// Whole CDC notifications waiting for the host's next interrupt IN URB.
    ///
    /// Queued as messages rather than as a byte stream: a host parses one notification per
    /// transfer, so two must never be merged into one URB.
    notifications: std::collections::VecDeque<Vec<u8>>,
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbCdcAcmSerialHandler {
    pub fn new(rx_tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            tx_buffer: Vec::new(),
            rx_tx,
            line_coding: LineCoding::default_115200_8n1(),
            control_lines: ControlLineState::from_value(0),
            notifications: std::collections::VecDeque::new(),
        }
    }

    /// Tell the host its bytes were dropped, in CDC's own vocabulary.
    ///
    /// A serial port has no request/response framing, so there is no reply to fail — but CDC
    /// PSTN 1.2 does define what a device says when it could not take what the host wrote:
    /// `SERIAL_STATE` with `bOverRun` set, on the interrupt IN (notification) endpoint. That is
    /// what this queues. A Linux `cdc-acm` host counts it as a receive overrun on the tty.
    ///
    /// Silence would be the alternative and it is the wrong one: a port that says nothing is
    /// indistinguishable from a port with nothing to say, so an LLM outage would look exactly
    /// like a quiet peer.
    pub fn queue_serial_state_overrun(&mut self) {
        let state = cdc_notification::UART_STATE_OVERRUN;
        // bmRequestType, bNotification, wValue, wIndex (interface 0), wLength, then the bitmap.
        let mut message = Vec::with_capacity(10);
        message.push(cdc_notification::REQUEST_TYPE);
        message.push(cdc_notification::SERIAL_STATE);
        message.extend_from_slice(&0u16.to_le_bytes()); // wValue
        message.extend_from_slice(&0u16.to_le_bytes()); // wIndex: the comms interface
        message.extend_from_slice(&2u16.to_le_bytes()); // wLength
        message.extend_from_slice(&state.to_le_bytes());
        debug!("USB serial queueing SERIAL_STATE notification with bOverRun set");
        self.notifications.push_back(message);
    }

    /// Notifications still waiting to go out. Used by tests and diagnostics.
    #[allow(dead_code)]
    pub fn pending_notifications(&self) -> usize {
        self.notifications.len()
    }

    /// The endpoints a CDC ACM interface needs, taken verbatim from the `usbip` crate:
    /// interrupt IN for notifications, bulk IN and bulk OUT for data.
    pub fn endpoints() -> Vec<usbip::UsbEndpoint> {
        usbip::cdc::UsbCdcAcmHandler::endpoints()
    }

    /// Queue bytes for the host to read on the next bulk IN URB.
    ///
    /// Bounded: the host drains this one bulk IN URB at a time and may never poll at all, while
    /// `send_data` can be called on every model turn. An unbounded buffer therefore grows at
    /// the model's pace and shrinks at the host's, which is the wrong way round. A real UART
    /// drops on a full transmit buffer and reports it, so that is what this does -- the drop is
    /// returned rather than swallowed so the caller can tell the model its bytes did not go.
    pub fn queue_tx(&mut self, data: &[u8]) -> usize {
        let room = MAX_TX_BUFFER.saturating_sub(self.tx_buffer.len());
        let taken = data.len().min(room);
        self.tx_buffer.extend_from_slice(&data[..taken]);
        let dropped = data.len() - taken;
        if dropped > 0 {
            warn!(
                "USB serial transmit buffer is full at {} byte(s); dropped {} of {} queued",
                self.tx_buffer.len(),
                dropped,
                data.len()
            );
        } else {
            trace!("USB serial queue {} byte(s) for the host", data.len());
        }
        dropped
    }

    /// Replace the reported line parameters.
    pub fn set_line_coding(&mut self, line_coding: LineCoding) {
        debug!(
            "USB serial line coding set by handler: {} baud, {} data bits, parity {}, stop {}",
            line_coding.baud_rate, line_coding.data_bits, line_coding.parity, line_coding.stop_bits
        );
        self.line_coding = line_coding;
    }

    /// The line parameters currently reported to the host.
    pub fn line_coding(&self) -> LineCoding {
        self.line_coding
    }

    /// Bytes still waiting to go out. Used by tests and diagnostics.
    #[allow(dead_code)]
    pub fn pending_tx(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Handle a class-specific control transfer addressed to this interface.
    fn handle_control(
        &mut self,
        setup: usbip::SetupPacket,
        req: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        match (setup.request_type, setup.request) {
            (request_type::CLASS_INTERFACE_OUT, cdc_request::SET_LINE_CODING) => {
                // The length check lives in `LineCoding::from_bytes`, which is `pub` and takes
                // an arbitrary slice; duplicating it here is how the unchecked indexing it used
                // to do looked safe.
                match LineCoding::from_bytes(req) {
                    Some(coding) => {
                        self.line_coding = coding;
                        debug!(
                            "USB serial host set line coding: {} baud, {} data bits, parity {}, \
                             stop {}",
                            self.line_coding.baud_rate,
                            self.line_coding.data_bits,
                            self.line_coding.parity,
                            self.line_coding.stop_bits
                        );
                    }
                    None => warn!(
                        "USB serial SET_LINE_CODING carried {} bytes, expected {} - ignored",
                        req.len(),
                        LineCoding::WIRE_LEN
                    ),
                }
                // A control OUT transfer must answer with an empty buffer; usbip's own
                // `debug_assert` in `usbip_ret_submit_success` enforces it.
                Ok(vec![])
            }
            (request_type::CLASS_INTERFACE_IN, cdc_request::GET_LINE_CODING) => {
                Ok(self.line_coding.to_bytes().to_vec())
            }
            (request_type::CLASS_INTERFACE_OUT, cdc_request::SET_CONTROL_LINE_STATE) => {
                self.control_lines = ControlLineState::from_value(setup.value);
                debug!(
                    "USB serial host set control lines: DTR={} RTS={}",
                    self.control_lines.dtr, self.control_lines.rts
                );
                Ok(vec![])
            }
            (request_type::CLASS_INTERFACE_OUT, cdc_request::SEND_BREAK) => {
                debug!("USB serial host sent a break of {} ms", setup.value);
                Ok(vec![])
            }
            _ => {
                // Answer unknown control requests empty rather than with an error: an error
                // aborts the USB/IP session for the whole device, and a host probing an
                // optional request must not unplug the port.
                debug!(
                    "USB serial: unhandled control request type={:#04x} request={:#04x}",
                    setup.request_type, setup.request
                );
                Ok(vec![])
            }
        }
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl usbip::UsbInterfaceHandler for UsbCdcAcmSerialHandler {
    fn handle_urb(
        &mut self,
        _interface: &usbip::UsbInterface,
        ep: usbip::UsbEndpoint,
        transfer_buffer_length: u32,
        setup: usbip::SetupPacket,
        req: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        if ep.is_ep0() {
            return self.handle_control(setup, req);
        }

        match ep.direction() {
            usbip::Direction::Out => {
                // Bulk OUT: the host wrote to the port. This is the path the stock
                // `UsbCdcAcmHandler` drops on the floor.
                if !req.is_empty() {
                    trace!("USB serial received {} byte(s) from the host", req.len());
                    if self.rx_tx.send(req.to_vec()).is_err() {
                        // The connection task is gone, so nothing will ever raise an event
                        // for these bytes. Say so rather than silently discarding them.
                        warn!(
                            "USB serial dropped {} byte(s): connection task has exited",
                            req.len()
                        );
                    }
                }
                Ok(vec![])
            }
            usbip::Direction::In => {
                if ep.attributes == usbip::EndpointAttributes::Interrupt as u8 {
                    // The notification endpoint. One whole message per transfer; a message
                    // longer than the URB is split and the remainder pushed back to the front,
                    // so it reassembles without ever being merged with the next one.
                    let limit = (ep.max_packet_size as usize).min(transfer_buffer_length as usize);
                    let Some(mut message) = self.notifications.pop_front() else {
                        return Ok(vec![]);
                    };
                    if message.len() > limit {
                        let remainder = message.split_off(limit);
                        self.notifications.push_front(remainder);
                    }
                    trace!(
                        "USB serial sent a {} byte CDC notification to the host",
                        message.len()
                    );
                    return Ok(message);
                }

                // Bulk IN: hand the host as much as this URB can take.
                let limit = (ep.max_packet_size as usize).min(transfer_buffer_length as usize);
                let take = self.tx_buffer.len().min(limit);
                let resp: Vec<u8> = self.tx_buffer.drain(..take).collect();
                if !resp.is_empty() {
                    trace!("USB serial sent {} byte(s) to the host", resp.len());
                }
                Ok(resp)
            }
        }
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        // The CDC header and ACM functional descriptors, as built by the usbip crate.
        usbip::UsbInterfaceHandler::get_class_specific_descriptor(
            &usbip::cdc::UsbCdcAcmHandler::new(),
        )
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
