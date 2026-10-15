//! USB CDC ACM Serial protocol actions

#[cfg(all(unix, feature = "libusb"))]
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::log_template::LogTemplate;
#[cfg(all(unix, feature = "libusb"))]
use crate::{protocol::EventType, server::connection::ConnectionId, state::app_state::AppState};
#[cfg(all(unix, feature = "libusb"))]
use anyhow::{Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use serde_json::json;
#[cfg(all(unix, feature = "libusb"))]
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

// Action constructors. Free functions rather than inline definitions so each event type can
// declare the actions that answer it - an event listing none leaves the model with only the
// common actions and every USB-Serial action it returns is rejected as unknown.
/// Optional connection selector shared by both wire actions.
///
/// It is optional on purpose. A virtual serial port normally has exactly one host attached, and
/// asking a model to copy an id back is a reliable source of wrong answers. When exactly one
/// port is attached the action needs no id; when several are, an omitted id is an error naming
/// the candidates rather than a guess.
#[cfg(all(unix, feature = "libusb"))]
fn connection_id_parameter() -> Parameter {
    Parameter {
        name: "connection_id".to_string(),
        // "string", matching what the events emit (`"conn-7"`). Declaring "integer" while the
        // event parameters declare "string" told the model to transform the one value it can
        // copy, and the executor then rejected the transformed form.
        type_hint: "string".to_string(),
        description: "Which attached port to act on, as the event reports it (e.g. \"conn-7\"). \
            Omit it when only one host is attached; required (copy it from the event) when \
            there are several."
            .to_string(),
        required: false,
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn send_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_data".to_string(),
        description: "Send data to the host over the virtual serial port, as if a device had \
            written it to the wire."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Text to send. Include an explicit \"\\n\" or \"\\r\\n\" if the host \
                    expects line-terminated output"
                    .to_string(),
                required: true,
            },
            connection_id_parameter(),
        ],
        example: json!({"type": "send_data", "data": "Hello\n"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB serial send {data_len}B")
                .with_debug("USB-Serial send_data: data='{data}'"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn set_line_coding_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_line_coding".to_string(),
        description: "Set the baud rate and line parameters this virtual port reports. Defaults \
            to 115200 8N1."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "baud_rate".to_string(),
                type_hint: "number".to_string(),
                description: "Bits per second (e.g., 115200)".to_string(),
                required: true,
            },
            Parameter {
                name: "data_bits".to_string(),
                type_hint: "number".to_string(),
                description: "5, 6, 7, 8, or 16".to_string(),
                required: false,
            },
            Parameter {
                name: "parity".to_string(),
                type_hint: "string".to_string(),
                description: "'none', 'odd', 'even', 'mark', 'space'".to_string(),
                required: false,
            },
            Parameter {
                name: "stop_bits".to_string(),
                type_hint: "number".to_string(),
                description: "1, 1.5, or 2".to_string(),
                required: false,
            },
            connection_id_parameter(),
        ],
        example: json!({"type": "set_line_coding", "baud_rate": 9600}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB serial line coding {baud_rate} baud")
                .with_debug("USB-Serial set_line_coding: baud={baud_rate} data_bits={data_bits} parity={parity} stop_bits={stop_bits}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and wait for the host to write more. Correct whenever the \
            input so far is incomplete - a partial line, for instance."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB serial wait for more")
                .with_debug("USB-Serial wait_for_more"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
pub static USB_SERIAL_ATTACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_serial_attached",
        "A host opened this virtual serial port (it appears as /dev/ttyACM0 on Linux). Send a \
         banner or prompt if the device should greet the host, adjust the line coding, or \
         wait_for_more to stay silent until the host writes.",
        json!({"type": "send_data", "data": "READY\r\n"}),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID".to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_data_action(),
        set_line_coding_action(),
        wait_for_more_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_more"}))
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_SERIAL_DETACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_serial_detached",
        "The host closed this virtual serial port. Purely informational - the port is gone, so \
         written data has nowhere to go.",
        json!({"type": "show_message", "message": "USB serial host detached"}),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID".to_string(),
        required: true,
    }])
    .with_no_actions()
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_SERIAL_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_serial_data_received",
        "The host wrote data to the virtual serial port. Reply with send_data, or wait_for_more \
         if what arrived is only part of a command.",
        json!({"type": "send_data", "data": "OK\r\n"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Received data as string".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_data_action(),
        set_line_coding_action(),
        wait_for_more_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_more"}))
});

/// The per-connection CDC ACM handlers, keyed by connection.
///
/// A `std::sync::Mutex` rather than a tokio one because `usbip` requires
/// `Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>` from `std`, and because `execute_action`
/// is synchronous. The guard is never held across an `.await`.
#[cfg(all(unix, feature = "libusb"))]
type SharedHandler = Arc<std::sync::Mutex<Box<dyn usbip::UsbInterfaceHandler + Send>>>;

#[cfg(all(unix, feature = "libusb"))]
pub struct UsbSerialProtocol {
    handlers: Arc<std::sync::Mutex<HashMap<ConnectionId, SharedHandler>>>,
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbSerialProtocol {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Register the handler that drives one attached port.
    pub fn set_handler(&self, connection_id: ConnectionId, handler: SharedHandler) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(connection_id, handler);
        }
    }

    /// Drop the handler for a port whose host has detached, so a later action cannot reach a
    /// device that is gone.
    pub fn remove_handler(&self, connection_id: ConnectionId) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.remove(&connection_id);
        }
    }

    /// Resolve which port an action refers to.
    ///
    /// An explicit `connection_id` wins. Otherwise the single attached port is used — and if
    /// there is not exactly one, this is an error rather than a guess: writing to the wrong
    /// serial port is indistinguishable from writing to the right one from the model's side.
    fn resolve_handler(&self, action: &serde_json::Value) -> Result<SharedHandler> {
        let handlers = self
            .handlers
            .lock()
            .map_err(|_| anyhow::anyhow!("USB serial handler registry poisoned"))?;

        // Accept both spellings. Events report `connection_id` as the *string* `"conn-7"`
        // (`mod.rs` formats it with `to_string()`), so an `as_u64()`-only read rejected the
        // one value the model has any reason to send - it can only echo back what the event
        // gave it. With one port attached that silently fell through to the inference path
        // and looked like it worked; with two or more, every action failed with "the action
        // must name one with 'connection_id'" and no value the model could send would work.
        // Same repair as usb-keyboard, usb-mouse and usb-msc.
        // `id as u32` silently aliased: `connection_id: 4294967298` resolved to connection 2.
        let requested = action["connection_id"]
            .as_u64()
            .and_then(|id| u32::try_from(id).ok())
            .map(ConnectionId::new)
            .or_else(|| {
                action["connection_id"]
                    .as_str()
                    .and_then(ConnectionId::from_string)
            });

        if let Some(connection_id) = requested {
            return handlers.get(&connection_id).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "No USB serial port attached on connection {}",
                    connection_id
                )
            });
        }

        match handlers.len() {
            0 => Err(anyhow::anyhow!(
                "No USB serial port is attached, so there is nothing to write to"
            )),
            1 => Ok(handlers.values().next().cloned().expect("len checked")),
            _ => {
                let mut ids: Vec<u32> = handlers.keys().map(|c| c.as_u32()).collect();
                ids.sort_unstable();
                Err(anyhow::anyhow!(
                    "{} USB serial ports are attached ({:?}); the action must name one with \
                     'connection_id'",
                    ids.len(),
                    ids
                ))
            }
        }
    }

    /// Tell the host its bytes were dropped, because the model could not be reached.
    ///
    /// Queues a CDC `SERIAL_STATE` notification with `bOverRun` set on the port's interrupt IN
    /// endpoint. Returns whether a handler was found; the session may already have ended.
    pub fn signal_overrun(&self, connection_id: ConnectionId) -> bool {
        let handler = match self.handlers.lock() {
            Ok(handlers) => handlers.get(&connection_id).cloned(),
            Err(_) => None,
        };
        let Some(handler) = handler else {
            return false;
        };
        let Ok(mut guard) = handler.lock() else {
            return false;
        };
        match guard
            .as_any()
            .downcast_mut::<crate::server::usb::serial::handler::UsbCdcAcmSerialHandler>()
        {
            Some(serial) => {
                serial.queue_serial_state_overrun();
                true
            }
            None => false,
        }
    }

    /// Run `f` against the CDC ACM handler an action refers to.
    fn with_serial_handler<T>(
        &self,
        action: &serde_json::Value,
        f: impl FnOnce(&mut crate::server::usb::serial::handler::UsbCdcAcmSerialHandler) -> T,
    ) -> Result<T> {
        let handler = self.resolve_handler(action)?;
        let mut guard = handler
            .lock()
            .map_err(|_| anyhow::anyhow!("USB serial handler mutex poisoned"))?;
        let serial = guard
            .as_any()
            .downcast_mut::<crate::server::usb::serial::handler::UsbCdcAcmSerialHandler>()
            .context("Handler is not a USB CDC ACM serial handler")?;
        Ok(f(serial))
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Protocol for UsbSerialProtocol {
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
                              speak - a serial port a host has imported and is asking nothing of \
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
            send_data_action(),
            set_line_coding_action(),
            wait_for_more_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "USB-Serial"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            USB_SERIAL_ATTACHED_EVENT.clone(),
            USB_SERIAL_DETACHED_EVENT.clone(),
            USB_SERIAL_DATA_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "USB>CDC>ACM"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["usb", "serial", "cdc", "acm", "uart", "tty"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        crate::protocol::metadata::ProtocolMetadataV2::builder()
            .state(crate::protocol::metadata::DevelopmentState::Experimental)
            .implementation(
                "Virtual USB CDC ACM serial port over USB/IP. usbip::handler runs on the \
                 accepted socket, so the listen port is whatever the caller asks for. The CDC \
                 interface handler is hand-written (src/server/usb/serial/handler.rs) because \
                 usbip's own UsbCdcAcmHandler discards host writes and handles no class \
                 requests; the CDC functional descriptors and endpoint layout still come from \
                 the crate.",
            )
            .llm_control(
                "send_data queues bytes for the host's next bulk IN transfer; set_line_coding \
                 changes what GET_LINE_CODING reports. All three events are emitted: \
                 usb_serial_attached on connect, usb_serial_data_received on every host write, \
                 usb_serial_detached when the USB/IP session ends.",
            )
            .e2e_testing(
                "E2E drives a real USB/IP client over TCP: OP_REQ_IMPORT, then bulk OUT and \
                 bulk IN URBs, asserting the bytes the host would read. No usbip kernel module \
                 or root is needed.",
            )
            .privilege_requirement(crate::protocol::metadata::PrivilegeRequirement::None)
            .notes(
                "Attaching from a real Linux host still needs the vhci-hcd module and root on \
                 the client side; that path is untested. SET_LINE_CODING from the host is \
                 recorded but raises no event, so a handler cannot react to the host changing \
                 the baud rate. There is no flow control and no serial-state notification on \
                 the interrupt endpoint (break, DCD, framing errors are never reported).",
            )
            // The USB/IP screen in `src/server/usb/guard.rs` refuses a `USBIP_CMD_SUBMIT`
            // declaring more than this, before the crate allocates from the number.
            .max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)
            .build()
    }
    fn description(&self) -> &'static str {
        "Virtual USB serial port (CDC ACM)"
    }
    fn example_prompt(&self) -> &'static str {
        "Create a USB serial port and echo back any data received"
    }
    fn group_name(&self) -> &'static str {
        "USB Devices"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: echo received serial data back to the host, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "usb_serial_data_received":
    actions = [{"type": "send_data", "data": str(event.get("data", ""))}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles USB serial device
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-serial",
                "instruction": "Create a USB serial port and echo back any data received"
            }),
            // Script mode: Code-based serial handling
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-serial",
                "event_handlers": [{
                    "event_pattern": "usb_serial_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed serial response
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "usb-serial",
                "event_handlers": [{
                    "event_pattern": "usb_serial_attached",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_data",
                            "data": "Welcome to NetGet USB Serial!\r\n"
                        }]
                    }
                }]
            }),
        )
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Server for UsbSerialProtocol {
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
            crate::server::usb::serial::UsbSerialServer::spawn_with_llm_actions(
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
        match action_type {
            "send_data" => {
                let data = action["data"]
                    .as_str()
                    .context("send_data requires 'data' field")?;
                if data.is_empty() {
                    return Err(anyhow::anyhow!("send_data requires non-empty 'data'"));
                }
                let bytes = data.as_bytes().to_vec();
                let dropped =
                    self.with_serial_handler(&action, |serial| serial.queue_tx(&bytes))?;
                if dropped > 0 {
                    // The transmit buffer is bounded, so a host that is not draining it makes
                    // this a real refusal. Saying so is the point: the alternative is the model
                    // believing it sent bytes that were thrown away.
                    return Err(anyhow::anyhow!(
                        "send_data queued {} of {} byte(s); the transmit buffer is full because \
                         the host is not reading. Wait for it to drain before sending more.",
                        bytes.len() - dropped,
                        bytes.len()
                    ));
                }
                Ok(ActionResult::NoAction)
            }
            "set_line_coding" => {
                // Range-checked before the cast, not after. `as u32` and `as u8` wrap
                // silently, so `baud_rate: 5000000000` became 705032704 and `data_bits: 264`
                // became 8 -- the port then reported a line configuration to the host that
                // nobody had asked for, and GET_LINE_CODING handed the wrong one back.
                let baud_raw = action["baud_rate"]
                    .as_u64()
                    .context("set_line_coding requires 'baud_rate'")?;
                let baud_rate = u32::try_from(baud_raw).ok().filter(|b| *b > 0).context(
                    "set_line_coding 'baud_rate' must be between 1 and 4294967295 (CDC PSTN 1.2 \
                     encodes dwDTERate as 32 bits)",
                )?;

                let data_bits_raw = action["data_bits"].as_u64().unwrap_or(8);
                if !matches!(data_bits_raw, 5 | 6 | 7 | 8 | 16) {
                    return Err(anyhow::anyhow!(
                        "set_line_coding 'data_bits' is {}; CDC PSTN 1.2 table 17 allows only \
                         5, 6, 7, 8 or 16",
                        data_bits_raw
                    ));
                }
                let data_bits = data_bits_raw as u8;

                // The wire encodes parity and stop bits as small integers (CDC PSTN 1.2,
                // table 17); the model speaks names.
                let parity = match action["parity"].as_str().unwrap_or("none") {
                    "none" => 0,
                    "odd" => 1,
                    "even" => 2,
                    "mark" => 3,
                    "space" => 4,
                    other => {
                        return Err(anyhow::anyhow!(
                            "set_line_coding: unknown parity '{}' (expected none, odd, even, \
                             mark or space)",
                            other
                        ))
                    }
                };
                let stop_bits = match action["stop_bits"].as_f64().unwrap_or(1.0) {
                    v if (v - 1.0).abs() < f64::EPSILON => 0,
                    v if (v - 1.5).abs() < f64::EPSILON => 1,
                    v if (v - 2.0).abs() < f64::EPSILON => 2,
                    other => {
                        return Err(anyhow::anyhow!(
                            "set_line_coding: unknown stop_bits {} (expected 1, 1.5 or 2)",
                            other
                        ))
                    }
                };

                let line_coding = crate::server::usb::descriptors::LineCoding {
                    baud_rate,
                    stop_bits,
                    parity,
                    data_bits,
                };
                self.with_serial_handler(&action, |serial| serial.set_line_coding(line_coding))?;
                Ok(ActionResult::NoAction)
            }
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
