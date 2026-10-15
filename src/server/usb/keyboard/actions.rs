//! USB HID Keyboard protocol actions implementation

#[cfg(all(unix, feature = "libusb"))]
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::log_template::LogTemplate;
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::EventType;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::connection::ConnectionId;
#[cfg(all(unix, feature = "libusb"))]
use crate::state::app_state::AppState;
#[cfg(all(unix, feature = "libusb"))]
use anyhow::{Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use serde_json::json;
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::{Arc, LazyLock};
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::Mutex;

// Event type definitions (static for efficient reuse)
#[cfg(all(unix, feature = "libusb"))]
pub static USB_KEYBOARD_ATTACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_keyboard_attached",
        "A USB/IP host attached to this virtual keyboard and will now accept HID reports. Type \
         text, press a key or a combination, or wait_for_more to stay idle.",
        json!({
            "type": "type_text",
            "text": "Hello, World!",
            "typing_speed_ms": 50
        }),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID of the USB/IP session. Actions may quote it back, but it \
                      is optional: with one host attached it is inferred."
            .to_string(),
        required: true,
    }])
    .with_actions(vec![
        type_text_action(),
        press_key_action(),
        press_key_combo_action(),
        release_all_keys_action(),
        wait_for_more_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_more"}))
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_KEYBOARD_DETACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_keyboard_detached",
        "The host detached from this virtual keyboard. Purely informational - the USB/IP \
         session is gone, so a HID report has nowhere to go.",
        json!({"type": "show_message", "message": "USB keyboard host detached"}),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID of the USB/IP session. Actions may quote it back, but it \
                      is optional: with one host attached it is inferred."
            .to_string(),
        required: true,
    }])
    .with_no_actions()
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_KEYBOARD_LED_STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_keyboard_led_status",
        "The host changed the keyboard LEDs (Num Lock, Caps Lock, Scroll Lock). This is how the \
         host reports lock state back to a keyboard - use it to tell whether Caps Lock is on \
         before typing, and correct it with press_key if it is not what you want.",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID of the USB/IP session. Actions may quote it back, but it \
                      is optional: with one host attached it is inferred."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "num_lock".to_string(),
            type_hint: "boolean".to_string(),
            description: "Num Lock LED state".to_string(),
            required: true,
        },
        Parameter {
            name: "caps_lock".to_string(),
            type_hint: "boolean".to_string(),
            description: "Caps Lock LED state".to_string(),
            required: true,
        },
        Parameter {
            name: "scroll_lock".to_string(),
            type_hint: "boolean".to_string(),
            description: "Scroll Lock LED state".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        type_text_action(),
        press_key_action(),
        press_key_combo_action(),
        release_all_keys_action(),
        wait_for_more_action(),
    ])
    .with_alternative_example(json!({"type": "press_key", "key": "capslock"}))
});

/// USB HID Keyboard protocol action handler
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbKeyboardProtocol {
    /// Map of active connections (for async actions)
    #[allow(dead_code)]
    connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    /// Map of USB/IP keyboard handlers for each connection
    ///
    /// A `std::sync::Mutex`, deliberately: `execute_action` is a *sync* trait method that is
    /// called from inside the tokio runtime, and `tokio::sync::Mutex::blocking_lock` panics
    /// with "Cannot block the current thread from within a runtime" when it is. The guard is
    /// only ever held across a `HashMap` lookup, never across an `.await`.
    handlers: Arc<std::sync::Mutex<HashMap<ConnectionId, SharedHandler>>>,
}

/// The handler `usbip` holds for one attached host, as this module shares it.
#[cfg(all(unix, feature = "libusb"))]
type SharedHandler = Arc<std::sync::Mutex<Box<dyn usbip::UsbInterfaceHandler + Send>>>;

#[cfg(all(unix, feature = "libusb"))]
#[derive(Clone)]
pub struct ConnectionData {
    // Placeholder for keyboard-specific connection data
    // Will be populated during USB/IP implementation
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for UsbKeyboardProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbKeyboardProtocol {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Store the USB/IP keyboard handler for a connection
    pub fn set_handler(&self, connection_id: ConnectionId, handler: SharedHandler) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(connection_id, handler);
        }
    }

    /// Drop the USB/IP keyboard handler for a connection that has detached
    pub fn remove_handler(&self, connection_id: ConnectionId) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.remove(&connection_id);
        }
    }

    /// Find the handler an action refers to.
    ///
    /// `connection_id` is **optional**, and all three forms a model can produce are accepted:
    /// the number, the number as a string, and the `conn-N` form the events themselves carry.
    ///
    /// That last one is why this exists. Actions used to demand
    /// `action["connection_id"].as_u64()`, while every event reports
    /// `connection_id.to_string()` — which is `"conn-2"`, not `2`. A model quoting the event's
    /// own field back therefore *always* failed with "USB keyboard actions require
    /// connection_id field in action", and there was no value it could have sent instead.
    /// Every keystroke this protocol was asked for was dropped.
    fn resolve_handler(&self, action: &serde_json::Value) -> Result<SharedHandler> {
        let handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let requested = action["connection_id"].as_u64().or_else(|| {
            action["connection_id"].as_str().and_then(|s| {
                let s = s.trim();
                s.strip_prefix("conn-").unwrap_or(s).parse::<u64>().ok()
            })
        });

        if let Some(id) = requested {
            // `id as u32` silently aliased: `connection_id: 4294967298` resolved to connection
            // 2 and typed into somebody else's session.
            let connection_id = u32::try_from(id).map(ConnectionId::new).map_err(|_| {
                anyhow::anyhow!("connection_id {} is not a valid connection number", id)
            })?;
            return handlers.get(&connection_id).cloned().ok_or_else(|| {
                anyhow::anyhow!("No USB keyboard attached on connection {}", connection_id)
            });
        }

        match handlers.len() {
            0 => Err(anyhow::anyhow!(
                "No USB/IP host is attached to this keyboard, so a keystroke has nowhere to go"
            )),
            1 => Ok(handlers.values().next().cloned().expect("len checked")),
            _ => {
                let mut ids: Vec<u32> = handlers.keys().map(|c| c.as_u32()).collect();
                ids.sort_unstable();
                Err(anyhow::anyhow!(
                    "{} USB/IP hosts are attached ({:?}); the action must name one with \
                     'connection_id'",
                    ids.len(),
                    ids
                ))
            }
        }
    }

    /// Queue a HID report on the connection's keyboard handler.
    ///
    /// Returns an error if the connection has no live USB/IP session.
    fn queue_reports(
        &self,
        handler: SharedHandler,
        reports: Vec<usbip::hid::UsbHidKeyboardReport>,
    ) -> Result<()> {
        let mut handler_guard = handler
            .lock()
            .map_err(|_| anyhow::anyhow!("USB keyboard handler mutex poisoned"))?;
        let hid = handler_guard
            .as_any()
            .downcast_mut::<crate::server::usb::keyboard::handler::NetGetKeyboardHandler>()
            .context("Handler is not a USB HID keyboard handler")?;
        for report in reports {
            hid.queue(report);
        }
        Ok(())
    }
}

// Implement Protocol trait
#[cfg(all(unix, feature = "libusb"))]
impl Protocol for UsbKeyboardProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a peer that has only connected may send no USB/IP message \
                              at all before the server closes it. Default 30. USB/IP is \
                              client-speaks-first and nothing here answers a peer that has not \
                              asked - `usbip attach` and `usbip list -r` both write their \
                              request as soon as the socket is up - so a short bound is the \
                              honest one. Raise it only if your host is reached over a link \
                              where a handshake can take that long."
                    .to_string(),
                required: false,
                example: serde_json::json!(30),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_FIRST_MESSAGE_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an attached host may go without sending a further USB/IP \
                              message before the server closes the session. Default 1800. \
                              USB/IP has no keepalive and nothing obliges an attached host to \
                              speak - a keyboard a host has imported and is asking nothing of \
                              is idle by design - so this is deliberately long and exists to \
                              reap a peer that is gone rather than to police one that is here. \
                              Lower it if you are exporting to strangers."
                    .to_string(),
                required: false,
                example: serde_json::json!(1800),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_IDLE_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            type_text_action(),
            press_key_action(),
            press_key_combo_action(),
            release_all_keys_action(),
            wait_for_more_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "USB-Keyboard"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            USB_KEYBOARD_ATTACHED_EVENT.clone(),
            USB_KEYBOARD_DETACHED_EVENT.clone(),
            USB_KEYBOARD_LED_STATUS_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "USB>HID>Keyboard"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["usb", "keyboard", "hid", "input", "typing"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        crate::protocol::metadata::ProtocolMetadataV2::builder()
            .state(crate::protocol::metadata::DevelopmentState::Experimental)
            // Deliberately silent: every HID input report asserts a key press. A keyboard with
            // nothing to report is NAKed on the interrupt endpoint, which is the normal state, and
            // STALL would make the host reset the device. So a failure types nothing.
            .deliberately_silent()
            .implementation("Virtual USB HID keyboard device using USB/IP protocol")
            .llm_control("LLM controls keyboard input (typing, key presses, combinations)")
            .e2e_testing("Mocked E2E over the USB/IP socket; real HID typing needs a Linux usbip client")
            .privilege_requirement(crate::protocol::metadata::PrivilegeRequirement::None)
            .notes("USB/IP runs on the accepted socket via usbip::handler (usbip 0.9, tokio 1.x), so the listen port is whatever the caller asks for and multiple instances can coexist. All three events are emitted: attached, detached, and led_status. led_status became reachable when the crate's UsbHidKeyboardHandler was wrapped by handler.rs -- the crate discards HID output reports, so a declared event could never fire; the wrapper also stops a control request the crate does not know (GET_PROTOCOL, GET_REPORT, and SET_REPORT itself) from hitting its unimplemented!() and panicking the session task. press_key_combo folds modifiers and up to six keys into one report. type_text/press_key cover the characters key_name_to_hid maps and refuse the rest rather than typing a different string. Exercised against an in-test USB/IP client that reads HID reports off the interrupt endpoint and writes LED reports; never against a real Linux usbip host, so nothing here has been seen by a kernel HID driver.")
            // The USB/IP screen in `src/server/usb/guard.rs` refuses a `USBIP_CMD_SUBMIT`
            // declaring more than this, before the crate allocates from the number.
            .max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)
            .build()
    }

    fn description(&self) -> &'static str {
        "Virtual USB HID keyboard device"
    }

    fn example_prompt(&self) -> &'static str {
        "Create a USB keyboard device and type 'hello world' when attached"
    }

    fn group_name(&self) -> &'static str {
        "USB Devices"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: type a fixed string once the emulated keyboard is
        // attached, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "usb_keyboard_attached":
    actions = [{"type": "type_text", "text": "hello from netget"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles USB keyboard device
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-keyboard",
                "instruction": "Create a USB keyboard device and type 'hello world' when attached"
            }),
            // Script mode: Code-based keyboard handling
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-keyboard",
                "event_handlers": [{
                    "event_pattern": "usb_keyboard_attached",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed keyboard action
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-keyboard",
                "event_handlers": [{
                    "event_pattern": "usb_keyboard_attached",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "type_text",
                            "text": "Hello from NetGet!",
                            "typing_speed_ms": 50
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait
#[cfg(all(unix, feature = "libusb"))]
impl Server for UsbKeyboardProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            // Read here rather than through a shared helper so the parameter names appear
            // in this protocol's own source: `tests/startup_param_drift_test.rs` proves a
            // declared knob is wired by finding its name outside the declaration, and a read
            // one directory up is invisible to it — and to the next person reading this file.
            // The numbers and the argument for them are in `src/server/usb/guard.rs`.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;
            crate::server::usb::keyboard::UsbKeyboardServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action["type"]
            .as_str()
            .context("Action must have 'type' field")?;

        if action_type == "wait_for_more" {
            return Ok(ActionResult::WaitForMore);
        }

        // Resolve the device once, up front, so a detached host is one clear error rather
        // than a per-action surprise. `connection_id` is optional; see `resolve_handler`.
        let handler = self.resolve_handler(&action)?;

        match action_type {
            "type_text" => {
                let text = action["text"]
                    .as_str()
                    .context("type_text requires 'text' field")?;

                let mut reports = Vec::with_capacity(text.len());
                let mut unsupported: Vec<char> = Vec::new();
                for ch in text.chars() {
                    match ascii_to_hid(ch) {
                        Some((modifier, key)) => reports.push(usbip::hid::UsbHidKeyboardReport {
                            modifier,
                            keys: [key, 0, 0, 0, 0, 0],
                        }),
                        None => unsupported.push(ch),
                    }
                }

                if !unsupported.is_empty() {
                    // Refuse rather than silently type a different string. The model asked
                    // for characters this HID report layout (US, unshifted+shift only)
                    // cannot produce, and a partial send is indistinguishable from success.
                    return Err(anyhow::anyhow!(
                        "type_text cannot produce these characters on a US HID keyboard: {:?}",
                        unsupported
                    ));
                }

                let count = reports.len();
                // Bounded: the pacing task below sleeps `typing_speed_ms` between every
                // report and is not registered with `register_server_task`, so an
                // unbounded value left a task alive long past the server it belongs to.
                // 5 seconds a keystroke is already slower than any human.
                let typing_speed_ms = action["typing_speed_ms"].as_u64().unwrap_or(0).min(5_000);

                if count == 0 {
                    return Err(anyhow::anyhow!("type_text requires non-empty 'text'"));
                }

                if typing_speed_ms == 0 {
                    self.queue_reports(handler, reports)?;
                } else {
                    // Pace the reports on a task rather than sleeping here: `execute_action`
                    // is sync and runs on a runtime worker, so a `thread::sleep` (what this
                    // used to do) blocks that worker for text.len() * typing_speed_ms.
                    // Queue the first report synchronously so a missing handler is still
                    // reported as an error to the model.
                    let mut rest = reports;
                    let first = rest.remove(0);
                    self.queue_reports(handler.clone(), vec![first])?;

                    tokio::runtime::Handle::current().spawn(async move {
                        for report in rest {
                            tokio::time::sleep(std::time::Duration::from_millis(typing_speed_ms))
                                .await;
                            let mut guard = handler
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(hid) = guard.as_any().downcast_mut::<
                                crate::server::usb::keyboard::handler::NetGetKeyboardHandler,
                            >() {
                                hid.queue(report);
                            }
                        }
                    });
                }

                tracing::info!(
                    "Queued {} keyboard reports (speed {}ms)",
                    count,
                    typing_speed_ms
                );
                Ok(ActionResult::NoAction)
            }
            "press_key" => {
                let key = action["key"]
                    .as_str()
                    .context("press_key requires 'key' field")?;

                let (mut modifier, keycode) =
                    key_name_to_hid(key).with_context(|| format!("Unsupported key: {}", key))?;

                if let Some(arr) = action["modifiers"].as_array() {
                    for m in arr.iter().filter_map(|v| v.as_str()) {
                        modifier |= modifier_name_to_bit(m)
                            .with_context(|| format!("Unsupported modifier: {}", m))?;
                    }
                }

                self.queue_reports(
                    handler,
                    vec![usbip::hid::UsbHidKeyboardReport {
                        modifier,
                        keys: [keycode, 0, 0, 0, 0, 0],
                    }],
                )?;
                tracing::info!("Queued key press '{}' (modifier={:#04x})", key, modifier);
                Ok(ActionResult::NoAction)
            }
            "press_key_combo" => {
                let names = action["keys"]
                    .as_array()
                    .context("press_key_combo requires 'keys' array")?
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>();

                // Split the list into modifiers (folded into the report's modifier byte) and
                // ordinary keys (up to the 6 slots a boot-protocol report carries).
                let mut modifier = 0u8;
                let mut keys = [0u8; 6];
                let mut n = 0usize;
                for name in &names {
                    if let Some(bit) = modifier_name_to_bit(name) {
                        modifier |= bit;
                        continue;
                    }
                    let (extra_mod, keycode) = key_name_to_hid(name)
                        .with_context(|| format!("Unsupported key in combo: {}", name))?;
                    if n >= keys.len() {
                        return Err(anyhow::anyhow!(
                            "press_key_combo supports at most {} non-modifier keys, got {}",
                            keys.len(),
                            names.len()
                        ));
                    }
                    modifier |= extra_mod;
                    keys[n] = keycode;
                    n += 1;
                }

                if modifier == 0 && n == 0 {
                    return Err(anyhow::anyhow!("press_key_combo requires at least one key"));
                }

                self.queue_reports(
                    handler,
                    vec![usbip::hid::UsbHidKeyboardReport { modifier, keys }],
                )?;
                tracing::info!("Queued key combo {:?} (modifier={:#04x})", names, modifier);
                Ok(ActionResult::NoAction)
            }
            "release_all_keys" => {
                // An all-zero report is the HID "nothing is pressed" state.
                self.queue_reports(
                    handler,
                    vec![usbip::hid::UsbHidKeyboardReport {
                        modifier: 0,
                        keys: [0; 6],
                    }],
                )?;
                tracing::info!("Released all keys");
                Ok(ActionResult::NoAction)
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}

// HID keycode mapping (USB HID Usage Tables 1.12, Keyboard/Keypad page 0x07)
//
// This deliberately does not use `usbip::hid::UsbHidKeyboardReport::from_ascii`: that helper
// calls `unimplemented!()` for any character outside a-z/A-Z/0-9/space/newline, so a single
// '!' in `type_text` -- or `release_all_keys`, which used to pass 0 -- panicked the action
// executor.

/// Modifier bits in byte 0 of a boot-protocol keyboard report.
#[cfg(all(unix, feature = "libusb"))]
mod modifier_bit {
    pub const LEFT_CTRL: u8 = 0x01;
    pub const LEFT_SHIFT: u8 = 0x02;
    pub const LEFT_ALT: u8 = 0x04;
    pub const LEFT_GUI: u8 = 0x08;
}

/// Map a modifier name the LLM may use to its report bit.
#[cfg(all(unix, feature = "libusb"))]
fn modifier_name_to_bit(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "ctrl" | "control" => Some(modifier_bit::LEFT_CTRL),
        "shift" => Some(modifier_bit::LEFT_SHIFT),
        "alt" | "option" => Some(modifier_bit::LEFT_ALT),
        "gui" | "meta" | "super" | "win" | "windows" | "cmd" | "command" => {
            Some(modifier_bit::LEFT_GUI)
        }
        _ => None,
    }
}

/// Map a printable ASCII character to `(modifier, keycode)`.
#[cfg(all(unix, feature = "libusb"))]
fn ascii_to_hid(c: char) -> Option<(u8, u8)> {
    const SHIFT: u8 = modifier_bit::LEFT_SHIFT;
    Some(match c {
        'a'..='z' => (0, c as u8 - b'a' + 0x04),
        'A'..='Z' => (SHIFT, c as u8 - b'A' + 0x04),
        '1'..='9' => (0, c as u8 - b'1' + 0x1E),
        '0' => (0, 0x27),
        '\n' | '\r' => (0, 0x28),
        '\t' => (0, 0x2B),
        ' ' => (0, 0x2C),
        '-' => (0, 0x2D),
        '=' => (0, 0x2E),
        '[' => (0, 0x2F),
        ']' => (0, 0x30),
        '\\' => (0, 0x31),
        ';' => (0, 0x33),
        '\'' => (0, 0x34),
        '`' => (0, 0x35),
        ',' => (0, 0x36),
        '.' => (0, 0x37),
        '/' => (0, 0x38),
        '!' => (SHIFT, 0x1E),
        '@' => (SHIFT, 0x1F),
        '#' => (SHIFT, 0x20),
        '$' => (SHIFT, 0x21),
        '%' => (SHIFT, 0x22),
        '^' => (SHIFT, 0x23),
        '&' => (SHIFT, 0x24),
        '*' => (SHIFT, 0x25),
        '(' => (SHIFT, 0x26),
        ')' => (SHIFT, 0x27),
        '_' => (SHIFT, 0x2D),
        '+' => (SHIFT, 0x2E),
        '{' => (SHIFT, 0x2F),
        '}' => (SHIFT, 0x30),
        '|' => (SHIFT, 0x31),
        ':' => (SHIFT, 0x33),
        '"' => (SHIFT, 0x34),
        '~' => (SHIFT, 0x35),
        '<' => (SHIFT, 0x36),
        '>' => (SHIFT, 0x37),
        '?' => (SHIFT, 0x38),
        _ => return None,
    })
}

/// Map a key name (a single character, or a named key like `enter` / `f5` / `up`) to
/// `(modifier, keycode)`.
#[cfg(all(unix, feature = "libusb"))]
fn key_name_to_hid(name: &str) -> Option<(u8, u8)> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if let Some(mapped) = ascii_to_hid(c) {
            return Some(mapped);
        }
    }

    let keycode = match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => 0x28,
        "esc" | "escape" => 0x29,
        "backspace" => 0x2A,
        "tab" => 0x2B,
        "space" | "spacebar" => 0x2C,
        "capslock" | "caps_lock" => 0x39,
        "f1" => 0x3A,
        "f2" => 0x3B,
        "f3" => 0x3C,
        "f4" => 0x3D,
        "f5" => 0x3E,
        "f6" => 0x3F,
        "f7" => 0x40,
        "f8" => 0x41,
        "f9" => 0x42,
        "f10" => 0x43,
        "f11" => 0x44,
        "f12" => 0x45,
        "printscreen" | "print_screen" => 0x46,
        "scrolllock" | "scroll_lock" => 0x47,
        "pause" => 0x48,
        "insert" => 0x49,
        "home" => 0x4A,
        "pageup" | "page_up" => 0x4B,
        "delete" | "del" => 0x4C,
        "end" => 0x4D,
        "pagedown" | "page_down" => 0x4E,
        "right" | "rightarrow" | "arrow_right" => 0x4F,
        "left" | "leftarrow" | "arrow_left" => 0x50,
        "down" | "downarrow" | "arrow_down" => 0x51,
        "up" | "uparrow" | "arrow_up" => 0x52,
        "numlock" | "num_lock" => 0x53,
        _ => return None,
    };
    Some((0, keycode))
}

// Action definitions

/// Optional connection selector shared by every action.
///
/// It was accepted by `resolve_handler` and demanded by name in the multi-host error
/// ("the action must name one with 'connection_id'"), and this protocol's CLAUDE.md
/// documented it — but no action declared it, so the model was never told it existed and
/// could not address a specific host when more than one was attached.
///
/// Three forms are accepted: the number, the number as a string, and the `conn-N` form the
/// events themselves carry. Declared "string" because that last one is what events emit.
#[cfg(all(unix, feature = "libusb"))]
fn connection_id_parameter() -> Parameter {
    Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Which attached host to act on, as the event reports it (e.g. \"conn-2\"). \
            Omit it when only one host is attached; required when there are several."
            .to_string(),
        required: false,
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn type_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "type_text".to_string(),
        description: "Type text on the USB keyboard as if a user typed it".to_string(),
        parameters: vec![
            Parameter {
                name: "text".to_string(),
                type_hint: "string".to_string(),
                description: "Text to type".to_string(),
                required: true,
            },
            Parameter {
                name: "typing_speed_ms".to_string(),
                type_hint: "number".to_string(),
                description: "Delay between keypresses in milliseconds (default: 0, meaning all \
                              keystrokes are queued at once)"
                    .to_string(),
                required: false,
            },
            connection_id_parameter(),
        ],
        example: json!({
            "type": "type_text",
            "text": "Hello, World!",
            "typing_speed_ms": 50
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB keyboard type '{text}'")
                .with_debug("USB-Keyboard type_text: text='{text}' speed={typing_speed_ms}ms"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn press_key_action() -> ActionDefinition {
    ActionDefinition {
        name: "press_key".to_string(),
        description: "Press a single key with optional modifier keys (Ctrl, Shift, Alt, GUI)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "key".to_string(),
                type_hint: "string".to_string(),
                description: "Key to press (e.g., 'a', 'enter', 'f1')".to_string(),
                required: true,
            },
            Parameter {
                name: "modifiers".to_string(),
                type_hint: "array".to_string(),
                description: "Modifier keys: 'ctrl', 'shift', 'alt', 'gui' (Windows/Command key)"
                    .to_string(),
                required: false,
            },
            connection_id_parameter(),
        ],
        example: json!({
            "type": "press_key",
            "key": "c",
            "modifiers": ["ctrl"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB keyboard press '{key}'")
                .with_debug("USB-Keyboard press_key: key='{key}' modifiers={modifiers}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn press_key_combo_action() -> ActionDefinition {
    ActionDefinition {
        name: "press_key_combo".to_string(),
        description: "Press multiple keys simultaneously (e.g., Ctrl+Alt+Delete)".to_string(),
        parameters: vec![
            Parameter {
                name: "keys".to_string(),
                type_hint: "array".to_string(),
                description: "Keys to press together: 'ctrl', 'alt', 'delete', etc.".to_string(),
                required: true,
            },
            connection_id_parameter(),
        ],
        example: json!({
            "type": "press_key_combo",
            "keys": ["ctrl", "alt", "delete"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB keyboard combo {keys}")
                .with_debug("USB-Keyboard press_key_combo: keys={keys}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn release_all_keys_action() -> ActionDefinition {
    ActionDefinition {
        name: "release_all_keys".to_string(),
        description: "Release all currently pressed keys (useful if stuck)".to_string(),
        parameters: vec![connection_id_parameter()],
        example: json!({
            "type": "release_all_keys"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB keyboard release all keys")
                .with_debug("USB-Keyboard release_all_keys"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more input from the host (do nothing for now)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB keyboard wait for more")
                .with_debug("USB-Keyboard wait_for_more"),
        ),
    }
}
