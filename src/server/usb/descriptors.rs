//! USB descriptor builders for various device types
//!
//! This module provides functions to build USB descriptors for:
//! - HID devices (keyboard, mouse)
//! - CDC ACM devices (serial)
//! - Custom devices
//!
//! # Most of the builders here have no callers, and that is not obvious
//!
//! Nine of them — `build_device_descriptor`, `build_string_descriptor`,
//! `build_language_id_descriptor`, `char_to_usage`, and every `build_*_config_descriptor`
//! (keyboard, mouse, FIDO2, CDC ACM, MSC) — are reachable from nothing in `src/` or `tests/`.
//! The `usbip` crate builds the device and configuration descriptors itself from
//! `UsbDevice::new(..).with_interface(class, subclass, protocol, name, endpoints, handler)`,
//! so every protocol here describes its device that way and none of these are consulted.
//!
//! They do not warn, because `dead_code` does not fire on a `pub` item in a library crate. So
//! a reader — or a model reading the source — reasonably concludes the wire format a device
//! presents is decided here, when it is decided by the endpoint lists in each protocol's
//! `mod.rs`. Verify with:
//!
//! ```bash
//! grep -rn build_device_descriptor src/ tests/ | grep -v descriptors.rs
//! ```
//!
//! What *is* live: `MouseReport` and `mouse_buttons`, `build_hid_mouse_report_descriptor`,
//! `FIDO_HID_REPORT_DESCRIPTOR`, `LineCoding` and `ControlLineState`, and the MSC
//! `CommandBlockWrapper` / `CommandStatusWrapper` / `scsi_*` tables. HID *report* descriptors
//! are the exception to the rule above precisely because `usbip` cannot invent one — it is the
//! device's own description of its report layout, which is why those are the ones with callers.
//!
//! The rest are kept as a checked reference rather than deleted, but do not read a caller into
//! them.

use crate::server::usb::common::*;

/// Standard USB device descriptor (18 bytes)
pub fn build_device_descriptor(
    vendor_id: u16,
    product_id: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    manufacturer_str_index: u8,
    product_str_index: u8,
    serial_str_index: u8,
) -> Vec<u8> {
    vec![
        18,                      // bLength
        descriptor_type::DEVICE, // bDescriptorType
        0x00,
        0x02,                      // bcdUSB (USB 2.0)
        device_class,              // bDeviceClass
        device_subclass,           // bDeviceSubClass
        device_protocol,           // bDeviceProtocol
        64,                        // bMaxPacketSize0 (EP0)
        (vendor_id & 0xff) as u8,  // idVendor (low byte)
        (vendor_id >> 8) as u8,    // idVendor (high byte)
        (product_id & 0xff) as u8, // idProduct (low byte)
        (product_id >> 8) as u8,   // idProduct (high byte)
        0x00,
        0x01,                   // bcdDevice (1.0)
        manufacturer_str_index, // iManufacturer
        product_str_index,      // iProduct
        serial_str_index,       // iSerialNumber
        1,                      // bNumConfigurations
    ]
}

/// HID keyboard report descriptor (boot protocol compatible)
/// Defines the format of keyboard input reports:
/// - Byte 0: Modifier keys (Ctrl, Shift, Alt, GUI)
/// - Byte 1: Reserved
/// - Bytes 2-7: Up to 6 simultaneous key presses
#[cfg(all(unix, feature = "libusb"))]
pub fn build_hid_keyboard_report_descriptor() -> Vec<u8> {
    vec![
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x06, // Usage (Keyboard)
        0xA1, 0x01, // Collection (Application)
        // Modifier keys (byte 0)
        0x05, 0x07, //   Usage Page (Key Codes)
        0x19, 0xE0, //   Usage Minimum (224) - Left Control
        0x29, 0xE7, //   Usage Maximum (231) - Right GUI
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1 bit)
        0x95, 0x08, //   Report Count (8 bits = 8 modifier keys)
        0x81, 0x02, //   Input (Data, Variable, Absolute) - Modifier byte
        // Reserved byte (byte 1)
        0x95, 0x01, //   Report Count (1)
        0x75, 0x08, //   Report Size (8 bits)
        0x81, 0x01, //   Input (Constant) - Reserved byte
        // LED output report (Num Lock, Caps Lock, Scroll Lock, etc.)
        0x95, 0x05, //   Report Count (5)
        0x75, 0x01, //   Report Size (1 bit)
        0x05, 0x08, //   Usage Page (LEDs)
        0x19, 0x01, //   Usage Minimum (1) - Num Lock
        0x29, 0x05, //   Usage Maximum (5) - Kana
        0x91, 0x02, //   Output (Data, Variable, Absolute) - LED bits
        // LED padding (3 bits)
        0x95, 0x01, //   Report Count (1)
        0x75, 0x03, //   Report Size (3 bits)
        0x91, 0x01, //   Output (Constant) - Padding
        // Key array (bytes 2-7)
        0x95, 0x06, //   Report Count (6) - Up to 6 simultaneous keys
        0x75, 0x08, //   Report Size (8 bits)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x65, //   Logical Maximum (101) - Max key code
        0x05, 0x07, //   Usage Page (Key Codes)
        0x19, 0x00, //   Usage Minimum (0)
        0x29, 0x65, //   Usage Maximum (101)
        0x81, 0x00, //   Input (Data, Array) - Key array
        0xC0, // End Collection
    ]
}

/// Build a complete HID keyboard configuration descriptor
/// Includes: Configuration, Interface, HID, and Endpoint descriptors
#[cfg(all(unix, feature = "libusb"))]
pub fn build_hid_keyboard_config_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration descriptor (9 bytes)
    desc.extend_from_slice(&[
        9,                              // bLength
        descriptor_type::CONFIGURATION, // bDescriptorType
        34,
        0,    // wTotalLength (34 bytes total) - will be calculated
        1,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration (no string)
        0xA0, // bmAttributes (bus powered, remote wakeup)
        50,   // bMaxPower (100mA)
    ]);

    // Interface descriptor (9 bytes)
    desc.extend_from_slice(&[
        9,                          // bLength
        descriptor_type::INTERFACE, // bDescriptorType
        0,                          // bInterfaceNumber
        0,                          // bAlternateSetting
        1,                          // bNumEndpoints (1 interrupt IN endpoint)
        device_class::HID,          // bInterfaceClass (HID)
        1,                          // bInterfaceSubClass (Boot Interface)
        1,                          // bInterfaceProtocol (Keyboard)
        0,                          // iInterface (no string)
    ]);

    // HID descriptor (9 bytes)
    let report_desc = build_hid_keyboard_report_descriptor();
    let report_desc_len = report_desc.len() as u16;
    desc.extend_from_slice(&[
        9,                    // bLength
        descriptor_type::HID, // bDescriptorType (HID)
        0x11,
        0x01,                           // bcdHID (HID 1.11)
        0x00,                           // bCountryCode (not localized)
        0x01,                           // bNumDescriptors
        descriptor_type::HID_REPORT,    // bDescriptorType (Report)
        (report_desc_len & 0xff) as u8, // wDescriptorLength (low)
        (report_desc_len >> 8) as u8,   // wDescriptorLength (high)
    ]);

    // Endpoint descriptor (7 bytes) - Interrupt IN
    desc.extend_from_slice(&[
        7,                         // bLength
        descriptor_type::ENDPOINT, // bDescriptorType
        0x81,                      // bEndpointAddress (EP1 IN)
        transfer_type::INTERRUPT,  // bmAttributes (Interrupt)
        0x08,
        0x00, // wMaxPacketSize (8 bytes)
        10,   // bInterval (10ms polling interval)
    ]);

    // Update total length
    let total_len = desc.len() as u16;
    desc[2] = (total_len & 0xff) as u8;
    desc[3] = (total_len >> 8) as u8;

    desc
}

/// Build a USB string descriptor.
///
/// String descriptors are UTF-16LE with a 2-byte header, and `bLength` is a **single byte** —
/// so the whole descriptor cannot exceed 255 bytes, which is 126 UTF-16 code units of text.
/// This used to be `desc.push(len as u8)` with no check: a 127-character string produced
/// `bLength = 0` and a 128-character one produced 2, in both cases a descriptor whose declared
/// length contradicts its own contents. The string is truncated to what the field can describe
/// instead, on a code-unit boundary so a surrogate pair is never split in half.
pub fn build_string_descriptor(s: &str) -> Vec<u8> {
    /// UTF-16 code units that fit alongside the 2-byte header within a `u8` `bLength`.
    const MAX_CODE_UNITS: usize = (u8::MAX as usize - 2) / 2;

    let mut desc = Vec::new();

    // Encode string as UTF-16LE
    let mut utf16: Vec<u16> = s.encode_utf16().collect();
    if utf16.len() > MAX_CODE_UNITS {
        // Do not cut between the halves of a surrogate pair: a lone surrogate is not valid
        // UTF-16 and a host decoding it gets a replacement character rather than a short name.
        let mut keep = MAX_CODE_UNITS;
        if (0xD800..0xDC00).contains(&utf16[keep - 1]) {
            keep -= 1;
        }
        utf16.truncate(keep);
    }
    let len = 2 + utf16.len() * 2;

    desc.push(len as u8); // bLength
    desc.push(descriptor_type::STRING); // bDescriptorType

    // Add UTF-16LE encoded characters
    for ch in utf16 {
        desc.push((ch & 0xff) as u8);
        desc.push((ch >> 8) as u8);
    }

    desc
}

/// Build language ID string descriptor (string index 0)
/// US English (0x0409) is the most common
pub fn build_language_id_descriptor() -> Vec<u8> {
    vec![
        4,                       // bLength
        descriptor_type::STRING, // bDescriptorType
        0x09,
        0x04, // wLANGID[0] (US English)
    ]
}

/// HID keyboard input report builder
/// 8 bytes: [modifiers, reserved, key1, key2, key3, key4, key5, key6]
#[cfg(all(unix, feature = "libusb"))]
pub struct KeyboardReport {
    pub modifiers: u8, // Bit flags for Ctrl, Shift, Alt, GUI
    pub keys: [u8; 6], // Up to 6 simultaneous key presses
}

#[cfg(all(unix, feature = "libusb"))]
impl KeyboardReport {
    /// Create empty keyboard report (no keys pressed)
    pub fn new() -> Self {
        Self {
            modifiers: 0,
            keys: [0; 6],
        }
    }

    /// Convert to 8-byte array for USB transmission
    pub fn to_bytes(&self) -> [u8; 8] {
        [
            self.modifiers,
            0, // Reserved
            self.keys[0],
            self.keys[1],
            self.keys[2],
            self.keys[3],
            self.keys[4],
            self.keys[5],
        ]
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for KeyboardReport {
    fn default() -> Self {
        Self::new()
    }
}

/// HID keyboard modifier key bit positions
#[cfg(all(unix, feature = "libusb"))]
pub mod keyboard_modifiers {
    pub const LEFT_CTRL: u8 = 0x01;
    pub const LEFT_SHIFT: u8 = 0x02;
    pub const LEFT_ALT: u8 = 0x04;
    pub const LEFT_GUI: u8 = 0x08;
    pub const RIGHT_CTRL: u8 = 0x10;
    pub const RIGHT_SHIFT: u8 = 0x20;
    pub const RIGHT_ALT: u8 = 0x40;
    pub const RIGHT_GUI: u8 = 0x80;
}

/// HID keyboard usage codes (scan codes)
/// These are the values that go in the key array (bytes 2-7)
#[cfg(all(unix, feature = "libusb"))]
pub mod keyboard_usage {
    pub const NONE: u8 = 0x00;
    pub const ERROR_ROLLOVER: u8 = 0x01;
    pub const A: u8 = 0x04;
    pub const B: u8 = 0x05;
    pub const C: u8 = 0x06;
    pub const D: u8 = 0x07;
    pub const E: u8 = 0x08;
    pub const F: u8 = 0x09;
    pub const G: u8 = 0x0a;
    pub const H: u8 = 0x0b;
    pub const I: u8 = 0x0c;
    pub const J: u8 = 0x0d;
    pub const K: u8 = 0x0e;
    pub const L: u8 = 0x0f;
    pub const M: u8 = 0x10;
    pub const N: u8 = 0x11;
    pub const O: u8 = 0x12;
    pub const P: u8 = 0x13;
    pub const Q: u8 = 0x14;
    pub const R: u8 = 0x15;
    pub const S: u8 = 0x16;
    pub const T: u8 = 0x17;
    pub const U: u8 = 0x18;
    pub const V: u8 = 0x19;
    pub const W: u8 = 0x1a;
    pub const X: u8 = 0x1b;
    pub const Y: u8 = 0x1c;
    pub const Z: u8 = 0x1d;
    pub const NUM_1: u8 = 0x1e;
    pub const NUM_2: u8 = 0x1f;
    pub const NUM_3: u8 = 0x20;
    pub const NUM_4: u8 = 0x21;
    pub const NUM_5: u8 = 0x22;
    pub const NUM_6: u8 = 0x23;
    pub const NUM_7: u8 = 0x24;
    pub const NUM_8: u8 = 0x25;
    pub const NUM_9: u8 = 0x26;
    pub const NUM_0: u8 = 0x27;
    pub const ENTER: u8 = 0x28;
    pub const ESCAPE: u8 = 0x29;
    pub const BACKSPACE: u8 = 0x2a;
    pub const TAB: u8 = 0x2b;
    pub const SPACE: u8 = 0x2c;
    pub const MINUS: u8 = 0x2d;
    pub const EQUALS: u8 = 0x2e;
    pub const LEFT_BRACKET: u8 = 0x2f;
    pub const RIGHT_BRACKET: u8 = 0x30;
    pub const BACKSLASH: u8 = 0x31;
    pub const SEMICOLON: u8 = 0x33;
    pub const QUOTE: u8 = 0x34;
    pub const GRAVE: u8 = 0x35;
    pub const COMMA: u8 = 0x36;
    pub const PERIOD: u8 = 0x37;
    pub const SLASH: u8 = 0x38;
    pub const CAPS_LOCK: u8 = 0x39;
    pub const F1: u8 = 0x3a;
    pub const F2: u8 = 0x3b;
    pub const F3: u8 = 0x3c;
    pub const F4: u8 = 0x3d;
    pub const F5: u8 = 0x3e;
    pub const F6: u8 = 0x3f;
    pub const F7: u8 = 0x40;
    pub const F8: u8 = 0x41;
    pub const F9: u8 = 0x42;
    pub const F10: u8 = 0x43;
    pub const F11: u8 = 0x44;
    pub const F12: u8 = 0x45;
}

/// Helper to convert character to HID keyboard usage code and modifiers
/// Returns (usage_code, needs_shift)
#[cfg(all(unix, feature = "libusb"))]
pub fn char_to_usage(ch: char) -> Option<(u8, bool)> {
    match ch {
        'a'..='z' => Some((keyboard_usage::A + (ch as u8 - b'a'), false)),
        'A'..='Z' => Some((keyboard_usage::A + (ch as u8 - b'A'), true)),
        '1'..='9' => Some((keyboard_usage::NUM_1 + (ch as u8 - b'1'), false)),
        '0' => Some((keyboard_usage::NUM_0, false)),
        ' ' => Some((keyboard_usage::SPACE, false)),
        '\n' => Some((keyboard_usage::ENTER, false)),
        '\t' => Some((keyboard_usage::TAB, false)),
        '-' => Some((keyboard_usage::MINUS, false)),
        '_' => Some((keyboard_usage::MINUS, true)),
        '=' => Some((keyboard_usage::EQUALS, false)),
        '+' => Some((keyboard_usage::EQUALS, true)),
        '[' => Some((keyboard_usage::LEFT_BRACKET, false)),
        '{' => Some((keyboard_usage::LEFT_BRACKET, true)),
        ']' => Some((keyboard_usage::RIGHT_BRACKET, false)),
        '}' => Some((keyboard_usage::RIGHT_BRACKET, true)),
        '\\' => Some((keyboard_usage::BACKSLASH, false)),
        '|' => Some((keyboard_usage::BACKSLASH, true)),
        ';' => Some((keyboard_usage::SEMICOLON, false)),
        ':' => Some((keyboard_usage::SEMICOLON, true)),
        '\'' => Some((keyboard_usage::QUOTE, false)),
        '"' => Some((keyboard_usage::QUOTE, true)),
        '`' => Some((keyboard_usage::GRAVE, false)),
        '~' => Some((keyboard_usage::GRAVE, true)),
        ',' => Some((keyboard_usage::COMMA, false)),
        '<' => Some((keyboard_usage::COMMA, true)),
        '.' => Some((keyboard_usage::PERIOD, false)),
        '>' => Some((keyboard_usage::PERIOD, true)),
        '/' => Some((keyboard_usage::SLASH, false)),
        '?' => Some((keyboard_usage::SLASH, true)),
        '!' => Some((keyboard_usage::NUM_1, true)),
        '@' => Some((keyboard_usage::NUM_2, true)),
        '#' => Some((keyboard_usage::NUM_3, true)),
        '$' => Some((keyboard_usage::NUM_4, true)),
        '%' => Some((keyboard_usage::NUM_5, true)),
        '^' => Some((keyboard_usage::NUM_6, true)),
        '&' => Some((keyboard_usage::NUM_7, true)),
        '*' => Some((keyboard_usage::NUM_8, true)),
        '(' => Some((keyboard_usage::NUM_9, true)),
        ')' => Some((keyboard_usage::NUM_0, true)),
        _ => None,
    }
}

// ============================================================================
// HID Mouse Descriptors
// ============================================================================

/// HID mouse report descriptor (boot protocol compatible)
/// Defines the format of mouse input reports:
/// - Byte 0: Button states (left, right, middle)
/// - Byte 1: X movement (signed, relative)
/// - Byte 2: Y movement (signed, relative)
/// - Byte 3: Wheel movement (signed, vertical scroll)
#[cfg(all(unix, feature = "libusb"))]
pub fn build_hid_mouse_report_descriptor() -> Vec<u8> {
    vec![
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x02, // Usage (Mouse)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x01, //   Usage (Pointer)
        0xA1, 0x00, //   Collection (Physical)
        // Buttons (byte 0)
        0x05, 0x09, //     Usage Page (Button)
        0x19, 0x01, //     Usage Minimum (1) - Left button
        0x29, 0x03, //     Usage Maximum (3) - Middle button
        0x15, 0x00, //     Logical Minimum (0)
        0x25, 0x01, //     Logical Maximum (1)
        0x95, 0x03, //     Report Count (3 buttons)
        0x75, 0x01, //     Report Size (1 bit)
        0x81, 0x02, //     Input (Data, Variable, Absolute) - Button bits
        // Padding (5 bits to complete the byte)
        0x95, 0x01, //     Report Count (1)
        0x75, 0x05, //     Report Size (5 bits)
        0x81, 0x01, //     Input (Constant) - Padding
        // X and Y movement (bytes 1-2)
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x09, 0x31, //     Usage (Y)
        0x15, 0x81, //     Logical Minimum (-127)
        0x25, 0x7F, //     Logical Maximum (127)
        0x75, 0x08, //     Report Size (8 bits)
        0x95, 0x02, //     Report Count (2) - X and Y
        0x81, 0x06, //     Input (Data, Variable, Relative) - X,Y movement
        // Wheel (byte 3)
        0x09, 0x38, //     Usage (Wheel)
        0x15, 0x81, //     Logical Minimum (-127)
        0x25, 0x7F, //     Logical Maximum (127)
        0x75, 0x08, //     Report Size (8 bits)
        0x95, 0x01, //     Report Count (1)
        0x81, 0x06, //     Input (Data, Variable, Relative) - Wheel
        0xC0, //   End Collection (Physical)
        0xC0, // End Collection (Application)
    ]
}

/// Build a complete HID mouse configuration descriptor
/// Includes: Configuration, Interface, HID, and Endpoint descriptors
#[cfg(all(unix, feature = "libusb"))]
pub fn build_hid_mouse_config_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration descriptor (9 bytes)
    desc.extend_from_slice(&[
        9,                              // bLength
        descriptor_type::CONFIGURATION, // bDescriptorType
        34,
        0,    // wTotalLength (will be calculated)
        1,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration (no string)
        0xA0, // bmAttributes (bus powered, remote wakeup)
        50,   // bMaxPower (100mA)
    ]);

    // Interface descriptor (9 bytes)
    desc.extend_from_slice(&[
        9,                          // bLength
        descriptor_type::INTERFACE, // bDescriptorType
        0,                          // bInterfaceNumber
        0,                          // bAlternateSetting
        1,                          // bNumEndpoints (1 interrupt IN endpoint)
        device_class::HID,          // bInterfaceClass (HID)
        1,                          // bInterfaceSubClass (Boot Interface)
        2,                          // bInterfaceProtocol (Mouse)
        0,                          // iInterface (no string)
    ]);

    // HID descriptor (9 bytes)
    let report_desc = build_hid_mouse_report_descriptor();
    let report_desc_len = report_desc.len() as u16;
    desc.extend_from_slice(&[
        9,                    // bLength
        descriptor_type::HID, // bDescriptorType (HID)
        0x11,
        0x01,                           // bcdHID (HID 1.11)
        0x00,                           // bCountryCode (not localized)
        0x01,                           // bNumDescriptors
        descriptor_type::HID_REPORT,    // bDescriptorType (Report)
        (report_desc_len & 0xff) as u8, // wDescriptorLength (low)
        (report_desc_len >> 8) as u8,   // wDescriptorLength (high)
    ]);

    // Endpoint descriptor (7 bytes) - Interrupt IN
    desc.extend_from_slice(&[
        7,                         // bLength
        descriptor_type::ENDPOINT, // bDescriptorType
        0x81,                      // bEndpointAddress (EP1 IN)
        transfer_type::INTERRUPT,  // bmAttributes (Interrupt)
        0x04,
        0x00, // wMaxPacketSize (4 bytes)
        10,   // bInterval (10ms polling interval)
    ]);

    // Update total length
    let total_len = desc.len() as u16;
    desc[2] = (total_len & 0xff) as u8;
    desc[3] = (total_len >> 8) as u8;

    desc
}

/// HID mouse input report builder
/// 4 bytes: [buttons, x, y, wheel]
#[cfg(all(unix, feature = "libusb"))]
pub struct MouseReport {
    pub buttons: u8, // Bit 0: left, Bit 1: right, Bit 2: middle
    pub x: i8,       // X movement (-127 to 127)
    pub y: i8,       // Y movement (-127 to 127)
    pub wheel: i8,   // Wheel movement (-127 to 127)
}

#[cfg(all(unix, feature = "libusb"))]
impl MouseReport {
    /// Create empty mouse report (no movement, no buttons)
    pub fn new() -> Self {
        Self {
            buttons: 0,
            x: 0,
            y: 0,
            wheel: 0,
        }
    }

    /// Convert to 4-byte array for USB transmission
    pub fn to_bytes(&self) -> [u8; 4] {
        [self.buttons, self.x as u8, self.y as u8, self.wheel as u8]
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for MouseReport {
    fn default() -> Self {
        Self::new()
    }
}

/// HID mouse button bit positions
#[cfg(all(unix, feature = "libusb"))]
pub mod mouse_buttons {
    pub const LEFT: u8 = 0x01;
    pub const RIGHT: u8 = 0x02;
    pub const MIDDLE: u8 = 0x04;
}

// ============================================================================
// FIDO2 HID Descriptors
// ============================================================================

/// FIDO HID report descriptor (CTAPHID protocol)
/// Uses 64-byte input and output reports for CTAPHID transport
#[cfg(all(unix, feature = "libusb"))]
pub const FIDO_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    // Input report (device to host)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    // Output report (host to device)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// Build a complete FIDO2 HID configuration descriptor
/// Includes: Configuration, Interface, HID, and Endpoint descriptors
#[cfg(all(unix, feature = "libusb"))]
pub fn build_fido2_hid_config_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration descriptor (9 bytes)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::CONFIGURATION,
        34,
        0,    // wTotalLength (9 + 9 + 9 + 7 + 7 = 41, but we'll calculate)
        1,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration
        0xA0, // bmAttributes (bus-powered, remote wakeup)
        50,   // bMaxPower (100mA)
    ]);

    // Interface descriptor (9 bytes)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::INTERFACE,
        0,                 // bInterfaceNumber
        0,                 // bAlternateSetting
        2,                 // bNumEndpoints (IN and OUT)
        device_class::HID, // bInterfaceClass (HID)
        0,                 // bInterfaceSubClass (No subclass)
        0,                 // bInterfaceProtocol (None)
        0,                 // iInterface
    ]);

    // HID descriptor (9 bytes)
    desc.extend_from_slice(&[
        9,                    // bLength
        descriptor_type::HID, // bDescriptorType (HID)
        0x11,
        0x01,                        // bcdHID (HID 1.11)
        0,                           // bCountryCode (not localized)
        1,                           // bNumDescriptors (1 report descriptor)
        descriptor_type::HID_REPORT, // bDescriptorType (Report)
        (FIDO_HID_REPORT_DESCRIPTOR.len() & 0xFF) as u8,
        ((FIDO_HID_REPORT_DESCRIPTOR.len() >> 8) & 0xFF) as u8,
    ]);

    // Endpoint descriptor - IN (7 bytes)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x81, // bEndpointAddress (IN, endpoint 1)
        0x03, // bmAttributes (Interrupt)
        64,
        0, // wMaxPacketSize (64 bytes)
        5, // bInterval (5ms polling)
    ]);

    // Endpoint descriptor - OUT (7 bytes)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x01, // bEndpointAddress (OUT, endpoint 1)
        0x03, // bmAttributes (Interrupt)
        64,
        0, // wMaxPacketSize (64 bytes)
        5, // bInterval (5ms polling)
    ]);

    // Update total length
    let total_len = desc.len() as u16;
    desc[2] = (total_len & 0xFF) as u8;
    desc[3] = ((total_len >> 8) & 0xFF) as u8;

    desc
}

// ============================================================================
// CDC ACM (Serial) Descriptors
// ============================================================================

/// CDC ACM descriptor subtypes
#[cfg(all(unix, feature = "libusb"))]
pub mod cdc_descriptor_subtype {
    pub const HEADER: u8 = 0x00;
    pub const CALL_MANAGEMENT: u8 = 0x01;
    pub const ACM: u8 = 0x02;
    pub const UNION: u8 = 0x06;
}

/// Build CDC ACM configuration descriptor
/// CDC ACM uses two interfaces: Communication (control) and Data (bulk I/O)
#[cfg(all(unix, feature = "libusb"))]
pub fn build_cdc_acm_config_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration descriptor (9 bytes)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::CONFIGURATION,
        67,
        0,    // wTotalLength (will be calculated)
        2,    // bNumInterfaces (Communication + Data)
        1,    // bConfigurationValue
        0,    // iConfiguration
        0xC0, // bmAttributes (self-powered)
        50,   // bMaxPower (100mA)
    ]);

    // Interface 0: Communication Class Interface (control)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::INTERFACE,
        0,                  // bInterfaceNumber
        0,                  // bAlternateSetting
        1,                  // bNumEndpoints (1 interrupt endpoint)
        device_class::COMM, // bInterfaceClass (CDC)
        0x02,               // bInterfaceSubClass (ACM)
        0x01,               // bInterfaceProtocol (AT commands)
        0,                  // iInterface
    ]);

    // CDC Header Functional Descriptor (5 bytes)
    desc.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType (CS_INTERFACE)
        cdc_descriptor_subtype::HEADER,
        0x10,
        0x01, // bcdCDC (1.10)
    ]);

    // CDC Call Management Functional Descriptor (5 bytes)
    desc.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType (CS_INTERFACE)
        cdc_descriptor_subtype::CALL_MANAGEMENT,
        0x00, // bmCapabilities (no call management)
        0x01, // bDataInterface (interface 1)
    ]);

    // CDC ACM Functional Descriptor (4 bytes)
    desc.extend_from_slice(&[
        4,    // bLength
        0x24, // bDescriptorType (CS_INTERFACE)
        cdc_descriptor_subtype::ACM,
        0x02, // bmCapabilities (supports line coding)
    ]);

    // CDC Union Functional Descriptor (5 bytes)
    desc.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType (CS_INTERFACE)
        cdc_descriptor_subtype::UNION,
        0x00, // bMasterInterface (interface 0)
        0x01, // bSlaveInterface (interface 1)
    ]);

    // Endpoint descriptor: Interrupt IN (control)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x81, // bEndpointAddress (EP1 IN)
        transfer_type::INTERRUPT,
        0x08,
        0x00, // wMaxPacketSize (8 bytes)
        16,   // bInterval (16ms)
    ]);

    // Interface 1: Data Class Interface (bulk data)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::INTERFACE,
        1,                      // bInterfaceNumber
        0,                      // bAlternateSetting
        2,                      // bNumEndpoints (bulk IN + bulk OUT)
        device_class::CDC_DATA, // bInterfaceClass
        0x00,                   // bInterfaceSubClass
        0x00,                   // bInterfaceProtocol
        0,                      // iInterface
    ]);

    // Endpoint descriptor: Bulk OUT (host to device)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x02, // bEndpointAddress (EP2 OUT)
        transfer_type::BULK,
        0x40,
        0x00, // wMaxPacketSize (64 bytes)
        0,    // bInterval (ignored for bulk)
    ]);

    // Endpoint descriptor: Bulk IN (device to host)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x83, // bEndpointAddress (EP3 IN)
        transfer_type::BULK,
        0x40,
        0x00, // wMaxPacketSize (64 bytes)
        0,    // bInterval (ignored for bulk)
    ]);

    // Update total length
    let total_len = desc.len() as u16;
    desc[2] = (total_len & 0xff) as u8;
    desc[3] = (total_len >> 8) as u8;

    desc
}

/// CDC ACM Line Coding structure
/// Used in SET_LINE_CODING and GET_LINE_CODING requests
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy)]
pub struct LineCoding {
    pub baud_rate: u32, // Bits per second
    pub stop_bits: u8,  // 0=1 stop bit, 1=1.5, 2=2 stop bits
    pub parity: u8,     // 0=None, 1=Odd, 2=Even, 3=Mark, 4=Space
    pub data_bits: u8,  // 5, 6, 7, 8, or 16
}

#[cfg(all(unix, feature = "libusb"))]
impl LineCoding {
    /// Create default line coding (115200 8N1)
    pub fn default_115200_8n1() -> Self {
        Self {
            baud_rate: 115200,
            stop_bits: 0, // 1 stop bit
            parity: 0,    // No parity
            data_bits: 8,
        }
    }

    /// Convert to 7-byte array for USB transmission
    pub fn to_bytes(&self) -> [u8; 7] {
        [
            (self.baud_rate & 0xff) as u8,
            ((self.baud_rate >> 8) & 0xff) as u8,
            ((self.baud_rate >> 16) & 0xff) as u8,
            ((self.baud_rate >> 24) & 0xff) as u8,
            self.stop_bits,
            self.parity,
            self.data_bits,
        ]
    }

    /// How many octets a CDC ACM line-coding structure occupies (USB CDC 1.2 §6.3.11).
    pub const WIRE_LEN: usize = 7;

    /// Parse from the 7 octets of a SET_LINE_CODING payload, or `None` if there are fewer.
    ///
    /// **This is `pub` and takes an arbitrary slice, so the length check belongs here.** It
    /// used to index `bytes[0..6]` unchecked and rely on its one call site guarding with
    /// `req.len() >= 7` — a latent panic one new caller away, and one that would be easy to
    /// miss: a panic inside a `tokio::spawn`ed connection task is swallowed by the task, so
    /// the server stays `Running`, the log shows the transfer succeeding and the peer simply
    /// hangs. (`src/panic_log.rs` now writes such a panic to `netget.log`, which makes it
    /// findable rather than harmless.) The payload comes from the USB host, so its length is
    /// decided by the peer, not by us.
    ///
    /// A short payload is a malformed request, not a reason to guess: returning `None` leaves
    /// the caller's existing line coding in place, which is what a device does when it cannot
    /// honour a SET_LINE_CODING.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: &[u8; Self::WIRE_LEN] = bytes.get(..Self::WIRE_LEN)?.try_into().ok()?;
        Some(Self {
            baud_rate: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            stop_bits: b[4],
            parity: b[5],
            data_bits: b[6],
        })
    }
}

/// CDC ACM Control Line State
/// DTR (Data Terminal Ready) and RTS (Request To Send)
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy)]
pub struct ControlLineState {
    pub dtr: bool, // Data Terminal Ready
    pub rts: bool, // Request To Send
}

#[cfg(all(unix, feature = "libusb"))]
impl ControlLineState {
    pub fn from_value(value: u16) -> Self {
        Self {
            dtr: (value & 0x01) != 0,
            rts: (value & 0x02) != 0,
        }
    }

    pub fn to_value(&self) -> u16 {
        let mut value = 0u16;
        if self.dtr {
            value |= 0x01;
        }
        if self.rts {
            value |= 0x02;
        }
        value
    }
}

// ============================================================================
// USB Mass Storage Class (MSC) Descriptors
// ============================================================================

/// Build USB Mass Storage Class configuration descriptor
/// MSC uses Bulk-Only Transport (BOT) with two bulk endpoints (IN + OUT)
#[cfg(all(unix, feature = "libusb"))]
pub fn build_msc_config_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration descriptor (9 bytes)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::CONFIGURATION,
        32,
        0,    // wTotalLength (32 bytes total) - will be updated
        1,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration (no string)
        0xC0, // bmAttributes (self-powered)
        50,   // bMaxPower (100mA)
    ]);

    // Interface descriptor (9 bytes)
    desc.extend_from_slice(&[
        9, // bLength
        descriptor_type::INTERFACE,
        0,    // bInterfaceNumber
        0,    // bAlternateSetting
        2,    // bNumEndpoints (Bulk IN + Bulk OUT)
        0x08, // bInterfaceClass (Mass Storage)
        0x06, // bInterfaceSubClass (SCSI transparent command set)
        0x50, // bInterfaceProtocol (Bulk-Only Transport)
        0,    // iInterface (no string)
    ]);

    // Endpoint descriptor: Bulk IN (7 bytes)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x81,                // bEndpointAddress (EP1 IN)
        transfer_type::BULK, // bmAttributes (Bulk)
        0x00,
        0x02, // wMaxPacketSize (512 bytes for High Speed)
        0,    // bInterval (ignored for bulk)
    ]);

    // Endpoint descriptor: Bulk OUT (7 bytes)
    desc.extend_from_slice(&[
        7, // bLength
        descriptor_type::ENDPOINT,
        0x02,                // bEndpointAddress (EP2 OUT)
        transfer_type::BULK, // bmAttributes (Bulk)
        0x00,
        0x02, // wMaxPacketSize (512 bytes for High Speed)
        0,    // bInterval (ignored for bulk)
    ]);

    // Update total length
    let total_len = desc.len() as u16;
    desc[2] = (total_len & 0xff) as u8;
    desc[3] = (total_len >> 8) as u8;

    desc
}

/// Command Block Wrapper (CBW) for Bulk-Only Transport
/// Size: Exactly 31 bytes
#[cfg(all(unix, feature = "libusb"))]
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CommandBlockWrapper {
    pub signature: u32,            // 0x43425355 ("USBC")
    pub tag: u32,                  // Command tag (echo in CSW)
    pub data_transfer_length: u32, // Expected data transfer bytes
    pub flags: u8,                 // Direction: 0x80=IN, 0x00=OUT
    pub lun: u8,                   // Logical Unit Number (0-15)
    pub cb_length: u8,             // Command Block length (1-16)
    pub cb: [u8; 16],              // SCSI command block
}

#[cfg(all(unix, feature = "libusb"))]
impl CommandBlockWrapper {
    pub const SIGNATURE: u32 = 0x43425355; // "USBC" in little-endian
    pub const SIZE: usize = 31;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != Self::SIZE {
            return None;
        }

        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if signature != Self::SIGNATURE {
            return None;
        }

        let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let data_transfer_length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = data[12];
        let lun = data[13];
        let cb_length = data[14];

        let mut cb = [0u8; 16];
        cb.copy_from_slice(&data[15..31]);

        Some(Self {
            signature,
            tag,
            data_transfer_length,
            flags,
            lun,
            cb_length,
            cb,
        })
    }

    pub fn is_data_in(&self) -> bool {
        (self.flags & 0x80) != 0
    }

    pub fn scsi_command(&self) -> &[u8] {
        &self.cb[0..(self.cb_length as usize).min(16)]
    }
}

/// Command Status Wrapper (CSW) for Bulk-Only Transport
/// Size: Exactly 13 bytes
#[cfg(all(unix, feature = "libusb"))]
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CommandStatusWrapper {
    pub signature: u32,    // 0x53425355 ("USBS")
    pub tag: u32,          // Echo of CBW tag
    pub data_residue: u32, // Difference (expected - actual)
    pub status: u8,        // 0x00=success, 0x01=fail, 0x02=phase_error
}

#[cfg(all(unix, feature = "libusb"))]
impl CommandStatusWrapper {
    pub const SIGNATURE: u32 = 0x53425355; // "USBS" in little-endian
    pub const SIZE: usize = 13;

    pub const STATUS_PASSED: u8 = 0x00;
    pub const STATUS_FAILED: u8 = 0x01;
    pub const STATUS_PHASE_ERROR: u8 = 0x02;

    pub fn new(tag: u32, data_residue: u32, status: u8) -> Self {
        Self {
            signature: Self::SIGNATURE,
            tag,
            data_residue,
            status,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data_residue.to_le_bytes());
        bytes[12] = self.status;
        bytes
    }
}

/// SCSI command opcodes (subset)
#[cfg(all(unix, feature = "libusb"))]
pub mod scsi_opcode {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const INQUIRY: u8 = 0x12;
    pub const MODE_SENSE_6: u8 = 0x1A;
    pub const START_STOP_UNIT: u8 = 0x1B;
    pub const PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
    pub const READ_FORMAT_CAPACITIES: u8 = 0x23;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
}

/// SCSI sense key codes
#[cfg(all(unix, feature = "libusb"))]
pub mod scsi_sense_key {
    pub const NO_SENSE: u8 = 0x00;
    pub const RECOVERED_ERROR: u8 = 0x01;
    pub const NOT_READY: u8 = 0x02;
    pub const MEDIUM_ERROR: u8 = 0x03;
    pub const HARDWARE_ERROR: u8 = 0x04;
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    pub const UNIT_ATTENTION: u8 = 0x06;
    pub const DATA_PROTECT: u8 = 0x07;
    pub const ABORTED_COMMAND: u8 = 0x0B;
}
