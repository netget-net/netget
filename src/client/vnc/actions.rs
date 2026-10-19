//! VNC client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// VNC client connected event
pub static VNC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_connected",
        "VNC client successfully connected and authenticated",
        json!({
            "type": "request_framebuffer_update",
            "incremental": true
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote VNC server address".to_string(),
            required: true,
        },
        Parameter {
            name: "width".to_string(),
            type_hint: "number".to_string(),
            description: "Framebuffer width in pixels".to_string(),
            required: true,
        },
        Parameter {
            name: "height".to_string(),
            type_hint: "number".to_string(),
            description: "Framebuffer height in pixels".to_string(),
            required: true,
        },
        Parameter {
            name: "server_name".to_string(),
            type_hint: "string".to_string(),
            description: "VNC server name/description".to_string(),
            required: true,
        },
    ])
});

/// VNC framebuffer update received event
pub static VNC_CLIENT_FRAMEBUFFER_UPDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_framebuffer_update",
        "Framebuffer update received from VNC server",
        json!({
            "type": "send_pointer_event",
            "x": 100,
            "y": 200,
            "button_mask": 1
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "rectangles".to_string(),
            type_hint: "number".to_string(),
            description: "Number of rectangles in this update".to_string(),
            required: true,
        },
        Parameter {
            name: "update_summary".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable summary of the update".to_string(),
            required: true,
        },
    ])
});

/// VNC server clipboard text event
pub static VNC_CLIENT_SERVER_CUT_TEXT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "vnc_server_cut_text",
        "Server sent clipboard text",
        json!({"type": "placeholder", "event_id": "vnc_server_cut_text"}),
    )
    .with_parameters(vec![Parameter {
        name: "text".to_string(),
        type_hint: "string".to_string(),
        description: "Clipboard text from server".to_string(),
        required: true,
    }])
});

/// VNC client protocol action handler
pub struct VncClientProtocol;

impl VncClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for VncClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "request_framebuffer_update".to_string(),
                description: "Request a framebuffer update from the VNC server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "incremental".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "If true, only send changes since last update".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "x".to_string(),
                        type_hint: "number".to_string(),
                        description: "X coordinate of update region (default: 0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "y".to_string(),
                        type_hint: "number".to_string(),
                        description: "Y coordinate of update region (default: 0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "width".to_string(),
                        type_hint: "number".to_string(),
                        description: "Width of update region (default: full width)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "height".to_string(),
                        type_hint: "number".to_string(),
                        description: "Height of update region (default: full height)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "request_framebuffer_update",
                    "incremental": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_pointer_event".to_string(),
                description: "Send a mouse pointer event (move, click, release)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "x".to_string(),
                        type_hint: "number".to_string(),
                        description: "X coordinate of pointer".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "y".to_string(),
                        type_hint: "number".to_string(),
                        description: "Y coordinate of pointer".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "button_mask".to_string(),
                        type_hint: "number".to_string(),
                        description: "Button mask (0=no buttons, 1=left, 2=middle, 4=right)"
                            .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_pointer_event",
                    "x": 100,
                    "y": 200,
                    "button_mask": 1
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_key_event".to_string(),
                description: "Send a keyboard event (key press or release)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "string".to_string(),
                        description: "The key to send: a single character such as \"a\" or \"A\",                             a named key such as \"Enter\", \"Escape\", \"Tab\", \"Backspace\", an                             arrow (\"Left\"/\"Up\"/\"Right\"/\"Down\"), a modifier (\"Shift\",                             \"Control\", \"Alt\", \"Meta\") or a function key (\"F1\"..\"F35\"). An                             X11 keysym number is also accepted. An unrecognised value is an                             error rather than a silently-sent keysym 0"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "down".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "True for key press, false for key release".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_key_event",
                    "key": "a",
                    "down": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_client_cut_text".to_string(),
                description: "Send clipboard text to the server".to_string(),
                parameters: vec![Parameter {
                    name: "text".to_string(),
                    type_hint: "string".to_string(),
                    description: "Text to send to clipboard".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_client_cut_text",
                    "text": "Hello, VNC!"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the VNC server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "request_framebuffer_update".to_string(),
                description: "Request a framebuffer update in response to server event".to_string(),
                parameters: vec![Parameter {
                    name: "incremental".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "If true, only send changes since last update".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "request_framebuffer_update",
                    "incremental": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_pointer_event".to_string(),
                description: "Send pointer event in response to framebuffer update".to_string(),
                parameters: vec![
                    Parameter {
                        name: "x".to_string(),
                        type_hint: "number".to_string(),
                        description: "X coordinate".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "y".to_string(),
                        type_hint: "number".to_string(),
                        description: "Y coordinate".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "button_mask".to_string(),
                        type_hint: "number".to_string(),
                        description: "Button mask".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_pointer_event",
                    "x": 100,
                    "y": 200,
                    "button_mask": 1
                }),
                log_template: None,
            },
            // send_key_event and send_client_cut_text were declared ONLY as async actions, so
            // answering a network event the model could move the pointer but could not press a
            // key or set the clipboard — the executor rejects an action the event never
            // advertised. Both have working sync executors, so the gap was purely in what was
            // offered. Found by a test whose key press never reached the server.
            ActionDefinition {
                name: "send_key_event".to_string(),
                description: "Send a key press or release to the VNC server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "string".to_string(),
                        description: "The key: a single character such as \"a\", a named key                             such as \"Enter\"/\"Escape\"/\"Tab\", an arrow, a modifier, or                             \"F1\"..\"F35\". An X11 keysym number is also accepted"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "down".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "True for key press, false for key release".to_string(),
                        required: true,
                    },
                ],
                example: json!({"type": "send_key_event", "key": "a", "down": true}),
                log_template: None,
            },
            ActionDefinition {
                name: "send_client_cut_text".to_string(),
                description: "Set the VNC server's clipboard to this text".to_string(),
                parameters: vec![Parameter {
                    name: "text".to_string(),
                    type_hint: "string".to_string(),
                    description: "Clipboard contents to send".to_string(),
                    required: true,
                }],
                example: json!({"type": "send_client_cut_text", "text": "hello"}),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more updates before taking action".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "VNC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "vnc_connected",
                "Triggered when VNC client connects and authenticates",
                json!({"type": "placeholder", "event_id": "vnc_connected"}),
            ),
            EventType::new(
                "vnc_framebuffer_update",
                "Triggered when framebuffer update is received",
                json!({"type": "placeholder", "event_id": "vnc_framebuffer_update"}),
            ),
            EventType::new(
                "vnc_server_cut_text",
                "Triggered when server sends clipboard text",
                json!({"type": "placeholder", "event_id": "vnc_server_cut_text"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RFB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["vnc", "vnc client", "remote desktop", "rfb"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Custom RFB protocol implementation")
            .llm_control("Control mouse, keyboard, and screen updates")
            .e2e_testing("x11vnc or TigerVNC server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Framebuffer updates and clipboard text are pushed by the server; a reader task
            // queues them as whole messages and the answering loop drains what waited.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "VNC (Remote Framebuffer) client for remote desktop control"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to VNC at localhost:5900 and click at position (100, 200)"
    }
    fn group_name(&self) -> &'static str {
        "Specialized"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "VNC password (optional, for VNC authentication)".to_string(),
            required: false,
            example: json!("mypassword"),
            default: None,
        }]
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls VNC interaction
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5900",
                "base_stack": "vnc",
                "instruction": "Click at position (100, 200) and type 'Hello'"
            }),
            // Script mode: Code-based VNC control
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5900",
                "base_stack": "vnc",
                "event_handlers": [{
                    "event_pattern": "vnc_framebuffer_update",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<vnc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed pointer event
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5900",
                "base_stack": "vnc",
                "event_handlers": [
                    {
                        "event_pattern": "vnc_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "request_framebuffer_update",
                                "incremental": true
                            }]
                        }
                    },
                    {
                        "event_pattern": "vnc_framebuffer_update",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_pointer_event",
                                "x": 100,
                                "y": 200,
                                "button_mask": 1
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for VncClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::vnc::VncClient;
            VncClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
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
            "request_framebuffer_update" => {
                let incremental = action
                    .get("incremental")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let x = super::rfb_u16(&action, "x", 0)?;
                let y = super::rfb_u16(&action, "y", 0)?;
                let width = super::rfb_u16(&action, "width", u16::MAX)?;
                let height = super::rfb_u16(&action, "height", u16::MAX)?;

                Ok(ClientActionResult::Custom {
                    name: "request_framebuffer_update".to_string(),
                    data: json!({
                        "incremental": incremental,
                        "x": x,
                        "y": y,
                        "width": width,
                        "height": height,
                    }),
                })
            }
            "send_pointer_event" => {
                for key in ["x", "y", "button_mask"] {
                    if action.get(key).is_none_or(serde_json::Value::is_null) {
                        anyhow::bail!("Missing '{key}' field");
                    }
                }
                let x = super::rfb_u16(&action, "x", 0)?;
                let y = super::rfb_u16(&action, "y", 0)?;
                let button_mask = super::rfb_u8(&action, "button_mask", 0)?;

                Ok(ClientActionResult::Custom {
                    name: "send_pointer_event".to_string(),
                    data: json!({
                        "x": x,
                        "y": y,
                        "button_mask": button_mask,
                    }),
                })
            }
            "send_key_event" => {
                // Accepts a name ("a", "Enter", "F1") or a keysym number. This is where the
                // action is validated before dispatch, so requiring as_u64() here rejected
                // every named key regardless of what the executor could handle.
                let key = crate::client::vnc::resolve_keysym(
                    action.get("key").unwrap_or(&serde_json::Value::Null),
                )
                .context(
                    "Missing or invalid 'key' field: use a single character like \"a\", a name                      like \"Enter\"/\"Escape\"/\"F1\", or an X11 keysym number",
                )?;
                let down = action
                    .get("down")
                    .and_then(|v| v.as_bool())
                    .context("Missing or invalid 'down' field")?;

                Ok(ClientActionResult::Custom {
                    name: "send_key_event".to_string(),
                    data: json!({
                        "key": key,
                        "down": down,
                    }),
                })
            }
            "send_client_cut_text" => {
                let text = action
                    .get("text")
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid 'text' field")?;

                Ok(ClientActionResult::Custom {
                    name: "send_client_cut_text".to_string(),
                    data: json!({
                        "text": text,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown VNC client action: {}",
                action_type
            )),
        }
    }
}
