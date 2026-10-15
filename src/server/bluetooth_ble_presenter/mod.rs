//! BLE Presenter Service — a presentation clicker over HID-over-GATT.
//!
//! A thin profile wrapper over the `bluetooth-ble` base stack: the base owns the radio, the
//! GATT table, the event loop and the LLM plumbing. What lives here is the *profile identity* —
//! the instruction preamble, and the HID report descriptor plus report layout the startup
//! examples in `actions.rs` publish.
//!
//! Those two constants are the single source of truth for the report map. Nothing inside
//! NetGet parses a report descriptor — the base stack carries it as an opaque byte string and
//! hands it to whichever central asks — so the first parser ever to see one is a host's HID
//! stack on someone else's machine. Keeping the bytes in one place, hex-encoded into the
//! examples rather than transcribed, is the only thing standing between a typo and a device
//! the host rejects.

pub mod actions;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct BluetoothBlePresenter;
impl BluetoothBlePresenter {
    #[cfg(all(unix, feature = "bluetooth"))]
    pub async fn spawn_with_llm_actions(
        device_name: String,
        llm: crate::llm::ollama_client::OllamaClient,
        state: Arc<crate::state::app_state::AppState>,
        tx: mpsc::UnboundedSender<String>,
        id: crate::state::ServerId,
        inst: String,
    ) -> Result<std::net::SocketAddr> {
        // The user's instruction is kept intact and wrapped, never replaced. The preamble
        // names the four characteristics and the report length because the model is the one
        // that builds the GATT table with `add_service`, and "Configure as BLE Presenter" on
        // its own tells it none of that.
        // Normalised before interpolation because it sits mid-sentence: an empty instruction
        // would otherwise leave a double space, and one that does not end in a full stop would
        // run into the sentence after it. This is the prompt the model actually reads.
        let inst = inst.trim();
        let inst = if inst.is_empty() {
            String::new()
        } else if inst.ends_with(['.', '!', '?']) {
            format!("{inst} ")
        } else {
            format!("{inst}. ")
        };
        let presenter_instruction = format!(
            "Configure as a BLE HID presentation clicker with HID Service (UUID: 0x1812). {}\
             Add HID Information, HID Report Map, HID Report (input, notify) and HID Control \
             Point characteristics. The input report is a {}-byte boot-keyboard report \
             (modifier byte, reserved byte, then a six-slot key array); a slide advance is \
             Keyboard PageDown (0x{:02X}) in the first key slot, followed by an all-zero \
             report to release it.",
            inst,
            HID_PRESENTER_INPUT_REPORT_LEN,
            presenter_keys::NEXT_SLIDE,
        );

        crate::server::bluetooth_ble::BluetoothBle::spawn_with_llm_actions(
            device_name,
            llm,
            state,
            tx,
            id,
            presenter_instruction,
        )
        .await
    }
}
#[cfg(any(all(unix, not(feature = "bluetooth")), not(unix)))]
impl BluetoothBlePresenter {
    pub async fn spawn_with_llm_actions(
        _: String,
        _: crate::llm::ollama_client::OllamaClient,
        _: Arc<crate::state::app_state::AppState>,
        _: mpsc::UnboundedSender<String>,
        _: crate::state::ServerId,
        _: String,
    ) -> Result<std::net::SocketAddr> {
        anyhow::bail!("BLE presenter not enabled")
    }
}

/// The Keyboard/Keypad page usages a presentation clicker sends.
///
/// A real presenter enumerates as an ordinary keyboard — this is what a Logitech R400 and
/// friends put on the wire — because every presentation application already binds these keys.
/// There is no "next slide" usage anywhere in the HID usage tables.
///
/// Every value here is inside the `Logical Minimum`/`Logical Maximum` and `Usage
/// Minimum`/`Usage Maximum` range [`HID_PRESENTER_REPORT_DESCRIPTOR`] declares for the key
/// array, and `tests/server/bluetooth_ble_presenter/report_descriptor_test.rs` asserts that
/// by reading the bounds back out of the walked descriptor rather than by restating them.
pub mod presenter_keys {
    /// Keyboard PageDown — advance one slide.
    pub const NEXT_SLIDE: u8 = 0x4E;
    /// Keyboard PageUp — go back one slide.
    pub const PREVIOUS_SLIDE: u8 = 0x4B;
    /// Keyboard F5 — start the slideshow from the beginning.
    pub const START_PRESENTATION: u8 = 0x3E;
    /// Keyboard Escape — leave the slideshow.
    pub const END_PRESENTATION: u8 = 0x29;
    /// Keyboard `.` — black the screen (PowerPoint and Keynote both bind it).
    pub const BLANK_SCREEN: u8 = 0x37;
}

/// Length in bytes of the input report [`HID_PRESENTER_REPORT_DESCRIPTOR`] describes.
///
/// One modifier byte, one reserved byte and a six-slot key array: the standard boot keyboard
/// input report. A presenter has to work at a lock screen and in a BIOS-style boot-protocol
/// host, which is exactly what the boot report is for, so the profile does not invent a
/// shorter one. [`build_presenter_report`] returns this many bytes and the startup examples
/// in `actions.rs` size the input report characteristic's initial value from it.
pub const HID_PRESENTER_INPUT_REPORT_LEN: usize = 8;

/// HID Report Descriptor for the presentation clicker.
///
/// This is the single source of truth for the report map: `actions.rs` hex-encodes these bytes
/// into its startup examples rather than carrying a second copy, and
/// `tests/server/bluetooth_ble_presenter/report_descriptor_test.rs` walks every item and
/// asserts the total is [`HID_PRESENTER_INPUT_REPORT_LEN`] bytes.
///
/// Input-only: there is no LED Output block, because nothing in this profile consumes an
/// output report and a clicker has no Caps/Num Lock to drive.
///
/// The literal that used to stand in `actions.rs` in place of this const was malformed in two
/// independent ways and no test could have caught either, because nothing in the tree parses a
/// report map. Its padding item was written `0x05, 0x75` — `Usage Page (0x75)`, a page the
/// specification reserves — where `0x75, 0x05` (`Report Size (5)`) was meant, so the two bytes
/// were simply transposed. `Report Size` therefore stayed at 1 from the button block above it
/// and the padding contributed a single bit, leaving a **ten-bit** report: not a whole number
/// of bytes, so a host would round it to two — against an eight-byte value published on the
/// very same characteristic.
pub const HID_PRESENTER_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (224 = LeftControl)
    0x29, 0xE7, //   Usage Maximum (231 = RightGUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute) - modifier byte, report byte 0
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Constant) - reserved byte, report byte 1
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array) - six key slots, report bytes 2-7
    0xC0, // End Collection
];

/// Build the input report for one named presenter control.
///
/// The report is [`HID_PRESENTER_INPUT_REPORT_LEN`] bytes in the layout
/// [`HID_PRESENTER_REPORT_DESCRIPTOR`] declares: byte 0 is the modifier bitmap, byte 1 is the
/// descriptor's constant reserved byte, and bytes 2-7 are the key array. None of this
/// profile's controls needs a modifier, so byte 0 is always zero; the keycode goes in the
/// first key slot and the remaining five stay empty.
///
/// Returns `None` for a name this profile does not define. That is deliberate, and is why the
/// return type is not a bare array: an all-zero report is a *valid* report meaning "no key is
/// held", so handing one back for an unrecognised name would turn a caller's typo into an
/// affirmative statement on the wire that every key had just been released. The caller decides
/// what an unknown name means; this function will not decide for it. The same reasoning is why
/// the BLE profiles are on `CLAUDE.md`'s deliberately-silent list — a fabricated HID report
/// asserts a keypress, so saying nothing is the only safe failure.
pub fn build_presenter_report(control: &str) -> Option<[u8; HID_PRESENTER_INPUT_REPORT_LEN]> {
    let keycode = match control {
        "next_slide" => presenter_keys::NEXT_SLIDE,
        "previous_slide" => presenter_keys::PREVIOUS_SLIDE,
        "start_presentation" => presenter_keys::START_PRESENTATION,
        "end_presentation" => presenter_keys::END_PRESENTATION,
        "blank_screen" => presenter_keys::BLANK_SCREEN,
        _ => return None,
    };

    let mut report = [0u8; HID_PRESENTER_INPUT_REPORT_LEN];
    report[2] = keycode;
    Some(report)
}
