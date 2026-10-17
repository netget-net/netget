//! USB client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Most bytes one transfer may carry in either direction.
///
/// `length` is handed straight to `nusb::transfer::RequestBuffer::new`, which allocates it up
/// front, and it was read as `as_u64().unwrap() as usize` with nothing between the model and
/// the allocator: `{"type": "bulk_transfer_in", "length": 4000000000}` asked for four gigabytes
/// per call. 64 KiB is larger than any single USB transfer a device will complete in one go
/// and leaves a wrong answer costing nothing.
pub const MAX_TRANSFER_BYTES: usize = 64 * 1024;

/// Read a field that becomes a single byte on the wire, refusing a value that would wrap.
///
/// Each of these used to be `as_u64()? as u8`, which is silent: `request_type: 384` reached the
/// device as 128 -- a device-to-host standard request, a different transfer entirely from what
/// the model asked for -- and no error said so.
fn byte_field(action: &serde_json::Value, field: &str, action_type: &str) -> Result<u8> {
    let value = action
        .get(field)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Missing '{field}' field"))?;
    u8::try_from(value).map_err(|_| {
        anyhow::anyhow!("{action_type} '{field}' is {value}, outside the 0..=255 a USB byte holds")
    })
}

/// Read a field that becomes a 16-bit wire value, refusing a value that would wrap.
fn word_field(action: &serde_json::Value, field: &str, action_type: &str) -> Result<u16> {
    let value = action
        .get(field)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Missing '{field}' field"))?;
    u16::try_from(value).map_err(|_| {
        anyhow::anyhow!(
            "{action_type} '{field}' is {value}, outside the 0..=65535 a USB 16-bit field holds"
        )
    })
}

/// Read a transfer length, bounded by [`MAX_TRANSFER_BYTES`].
///
/// `required_default` is used when the field is absent; pass 0 where the field is optional.
fn transfer_length(action: &serde_json::Value, action_type: &str, default: u64) -> Result<usize> {
    let value = action
        .get("length")
        .and_then(|v| v.as_u64())
        .unwrap_or(default);
    if value as u128 > MAX_TRANSFER_BYTES as u128 {
        return Err(anyhow::anyhow!(
            "{action_type} 'length' is {value}; at most {MAX_TRANSFER_BYTES} bytes may be \
             requested in one transfer"
        ));
    }
    Ok(value as usize)
}

/// USB device opened event
pub static USB_DEVICE_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_device_opened",
        "USB device successfully opened and interface claimed",
        json!({
            "type": "control_transfer",
            "request_type": 0x80,
            "request": 0x06,
            "value": 0x0100,
            "index": 0,
            "length": 18
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "vendor_id".to_string(),
            type_hint: "string".to_string(),
            description: "USB vendor ID (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "product_id".to_string(),
            type_hint: "string".to_string(),
            description: "USB product ID (hex)".to_string(),
            required: true,
        },
        Parameter {
            name: "manufacturer".to_string(),
            type_hint: "string".to_string(),
            description: "Device manufacturer string".to_string(),
            required: false,
        },
        Parameter {
            name: "product".to_string(),
            type_hint: "string".to_string(),
            description: "Device product string".to_string(),
            required: false,
        },
    ])
});

/// USB control transfer response event
pub static USB_CONTROL_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_control_response",
        "Response received from USB control transfer",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Response data (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of response in bytes".to_string(),
            required: true,
        },
    ])
});

/// USB bulk data received event
pub static USB_BULK_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_bulk_data_received",
        "Data received from USB bulk endpoint",
        json!({
            "type": "bulk_transfer_out",
            "endpoint": 0x02,
            "data_hex": "48656c6c6f"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The data received (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of data in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "endpoint".to_string(),
            type_hint: "number".to_string(),
            description: "Endpoint address".to_string(),
            required: true,
        },
    ])
});

/// USB interrupt data received event
pub static USB_INTERRUPT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_interrupt_data_received",
        "Data received from USB interrupt endpoint",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The data received (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of data in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "endpoint".to_string(),
            type_hint: "number".to_string(),
            description: "Endpoint address".to_string(),
            required: true,
        },
    ])
});

/// USB client protocol action handler
pub struct UsbClientProtocol;

impl UsbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for UsbClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // `list_usb_devices` used to be advertised here and could not run: `execute_action`
        // below has no arm for it, so it came back "Unknown action" and cost the model a
        // retry. Device enumeration is a real capability worth adding, but it needs rusb work
        // in `mod.rs`, not an action declaration on its own.
        vec![ActionDefinition {
            name: "detach_device".to_string(),
            description: "Detach from the USB device and close connection".to_string(),
            parameters: vec![],
            example: json!({
                "type": "detach_device"
            }),
            log_template: None,
        }]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "control_transfer".to_string(),
                description: "Send a USB control transfer request".to_string(),
                parameters: vec![
                    Parameter {
                        name: "request_type".to_string(),
                        type_hint: "number".to_string(),
                        description: "Request type byte (bmRequestType)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "request".to_string(),
                        type_hint: "number".to_string(),
                        description: "Request byte (bRequest)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "value".to_string(),
                        type_hint: "number".to_string(),
                        description: "Value word (wValue)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "index".to_string(),
                        type_hint: "number".to_string(),
                        description: "Index word (wIndex)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Data to send (hex encoded, empty for IN transfers)"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "length".to_string(),
                        type_hint: "number".to_string(),
                        description: "Expected response length (for IN transfers)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "control_transfer",
                    "request_type": 0x80,
                    "request": 0x06,
                    "value": 0x0100,
                    "index": 0,
                    "length": 18
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "bulk_transfer_out".to_string(),
                description: "Send data via USB bulk OUT endpoint".to_string(),
                parameters: vec![
                    Parameter {
                        name: "endpoint".to_string(),
                        type_hint: "number".to_string(),
                        description: "Bulk OUT endpoint address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Data to send (hex encoded)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "bulk_transfer_out",
                    "endpoint": 0x02,
                    "data_hex": "48656c6c6f"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "bulk_transfer_in".to_string(),
                description: "Read data from USB bulk IN endpoint".to_string(),
                parameters: vec![
                    Parameter {
                        name: "endpoint".to_string(),
                        type_hint: "number".to_string(),
                        description: "Bulk IN endpoint address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "length".to_string(),
                        type_hint: "number".to_string(),
                        description: "Number of bytes to read".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "bulk_transfer_in",
                    "endpoint": 0x81,
                    "length": 64
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "interrupt_transfer_in".to_string(),
                description: "Read data from USB interrupt IN endpoint".to_string(),
                parameters: vec![
                    Parameter {
                        name: "endpoint".to_string(),
                        type_hint: "number".to_string(),
                        description: "Interrupt IN endpoint address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "length".to_string(),
                        type_hint: "number".to_string(),
                        description: "Number of bytes to read".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "interrupt_transfer_in",
                    "endpoint": 0x83,
                    "length": 8
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "claim_interface".to_string(),
                description: "Claim a USB interface for exclusive access".to_string(),
                parameters: vec![Parameter {
                    name: "interface_number".to_string(),
                    type_hint: "number".to_string(),
                    description: "Interface number to claim".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "claim_interface",
                    "interface_number": 0
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "USB"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "usb_device_opened",
                "Triggered when USB device is opened and interface claimed",
                json!({"type": "placeholder", "event_id": "usb_device_opened"}),
            ),
            EventType::new(
                "usb_control_response",
                "Triggered when USB control transfer completes",
                json!({"type": "placeholder", "event_id": "usb_control_response"}),
            ),
            EventType::new(
                "usb_bulk_data_received",
                "Triggered when data is received from bulk endpoint",
                json!({"type": "placeholder", "event_id": "usb_bulk_data_received"}),
            ),
            EventType::new(
                "usb_interrupt_data_received",
                "Triggered when data is received from interrupt endpoint",
                json!({"type": "placeholder", "event_id": "usb_interrupt_data_received"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "USB"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["usb", "usb device", "usb client", "connect to usb"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("nusb pure-Rust USB library for device access")
            .llm_control("Full control over USB transfers (control, bulk, interrupt)")
            .e2e_testing("Requires actual USB device for testing")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "USB client for low-level USB device interaction"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to USB device with vendor ID 0x1234, product ID 0x5678"
    }

    fn group_name(&self) -> &'static str {
        "Hardware"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles USB device operations
            json!({
                "type": "open_client",
                "remote_addr": "usb:1234:5678",
                "base_stack": "usb",
                "instruction": "Connect to USB device and get device descriptor"
            }),
            // Script mode: Code-based USB handling
            json!({
                "type": "open_client",
                "remote_addr": "usb:1234:5678",
                "base_stack": "usb",
                "event_handlers": [{
                    "event_pattern": "usb_device_opened",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<usb_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed USB action
            json!({
                "type": "open_client",
                "remote_addr": "usb:1234:5678",
                "base_stack": "usb",
                "event_handlers": [{
                    "event_pattern": "usb_device_opened",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "control_transfer",
                            "request_type": 128,
                            "request": 6,
                            "value": 256,
                            "index": 0,
                            "length": 18
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for UsbClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::usb::UsbClient;
            UsbClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "control_transfer" => {
                let request_type = byte_field(&action, "request_type", action_type)?;
                let request = byte_field(&action, "request", action_type)?;
                let value = word_field(&action, "value", action_type)?;
                let index = word_field(&action, "index", action_type)?;

                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let length = transfer_length(&action, action_type, 0)?;

                let data = if !data_hex.is_empty() {
                    let bytes = hex::decode(data_hex).context("Invalid hex data")?;
                    if bytes.len() > MAX_TRANSFER_BYTES {
                        return Err(anyhow::anyhow!(
                            "control_transfer 'data_hex' decodes to {} bytes; at most {} are \
                             accepted",
                            bytes.len(),
                            MAX_TRANSFER_BYTES
                        ));
                    }
                    bytes
                } else {
                    Vec::new()
                };

                Ok(ClientActionResult::Custom {
                    name: "control_transfer".to_string(),
                    data: json!({
                        "request_type": request_type,
                        "request": request,
                        "value": value,
                        "index": index,
                        "data": data,
                        "length": length,
                    }),
                })
            }
            "bulk_transfer_out" => {
                let endpoint = byte_field(&action, "endpoint", action_type)?;

                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data_hex' field")?;

                let data = hex::decode(data_hex).context("Invalid hex data")?;
                if data.len() > MAX_TRANSFER_BYTES {
                    return Err(anyhow::anyhow!(
                        "bulk_transfer_out 'data_hex' decodes to {} bytes; at most {} are \
                         accepted",
                        data.len(),
                        MAX_TRANSFER_BYTES
                    ));
                }

                Ok(ClientActionResult::Custom {
                    name: "bulk_transfer_out".to_string(),
                    data: json!({
                        "endpoint": endpoint,
                        "data": data,
                    }),
                })
            }
            "bulk_transfer_in" => {
                let endpoint = byte_field(&action, "endpoint", action_type)?;
                let length = transfer_length(&action, action_type, 64)?;

                Ok(ClientActionResult::Custom {
                    name: "bulk_transfer_in".to_string(),
                    data: json!({
                        "endpoint": endpoint,
                        "length": length,
                    }),
                })
            }
            "interrupt_transfer_in" => {
                let endpoint = byte_field(&action, "endpoint", action_type)?;
                let length = transfer_length(&action, action_type, 64)?;

                Ok(ClientActionResult::Custom {
                    name: "interrupt_transfer_in".to_string(),
                    data: json!({
                        "endpoint": endpoint,
                        "length": length,
                    }),
                })
            }
            "claim_interface" => {
                let interface_number = byte_field(&action, "interface_number", action_type)?;

                Ok(ClientActionResult::Custom {
                    name: "claim_interface".to_string(),
                    data: json!({
                        "interface_number": interface_number,
                    }),
                })
            }
            "detach_device" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown USB client action: {}",
                action_type
            )),
        }
    }
}
