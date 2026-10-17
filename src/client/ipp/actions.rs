//! IPP client protocol actions implementation

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

/// IPP client connected event
pub static IPP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipp_connected",
        "IPP client initialized and ready to send print operations",
        json!({"type": "get_printer_attributes"}),
    )
    .with_parameters(vec![Parameter {
        name: "printer_uri".to_string(),
        type_hint: "string".to_string(),
        description: "IPP printer URI".to_string(),
        required: true,
    }])
});

/// IPP client response received event
pub static IPP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipp_response_received",
        "IPP operation response received from printer",
        json!({"type": "get_job_attributes", "job_id": 123}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description:
                "IPP operation name (get_printer_attributes, print_job, get_job_attributes)"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "success".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the operation succeeded".to_string(),
            required: true,
        },
        Parameter {
            name: "response".to_string(),
            type_hint: "object".to_string(),
            description: "Response data from the printer".to_string(),
            required: true,
        },
    ])
});

/// IPP client protocol action handler
pub struct IppClientProtocol;

impl IppClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IppClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "printer_path".to_string(),
            description: "Path to the printer on the server (e.g., /printers/test-printer)"
                .to_string(),
            type_hint: "string".to_string(),
            required: false,
            example: json!("/printers/test-printer"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "get_printer_attributes".to_string(),
                description: "Query printer capabilities and status".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_printer_attributes"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "print_job".to_string(),
                description: "Submit a print job to the printer".to_string(),
                parameters: vec![
                    Parameter {
                        name: "job_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name/title for the print job".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "document_format".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "MIME type of the document (e.g., application/pdf, text/plain)"
                                .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "document_data".to_string(),
                        type_hint: "string".to_string(),
                        description: "Document content. Plain text unless you set \
                                      encoding=\"base64\", which is how you send a PDF or any \
                                      other binary document. It is never guessed."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "encoding".to_string(),
                        type_hint: "string".to_string(),
                        description: "How to read document_data: \"utf8\" (default, the text \
                                      itself) or \"base64\". Say which; the two are not \
                                      distinguishable from the content."
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "print_job",
                    "job_name": "Test Document",
                    "document_format": "text/plain",
                    "document_data": "Hello, Printer!\n"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_job_attributes".to_string(),
                description: "Query status and details of a specific print job".to_string(),
                parameters: vec![Parameter {
                    name: "job_id".to_string(),
                    type_hint: "number".to_string(),
                    description: "Job ID returned from print_job operation".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_job_attributes",
                    "job_id": 123
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the IPP printer".to_string(),
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
                name: "wait_for_more".to_string(),
                description: "Do nothing and wait for the next IPP response. The correct answer \
                    when what arrived needs no follow-up -- without it the model has to \
                    invent an action it does not want."
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_printer_attributes".to_string(),
                description: "Query printer capabilities in response to previous operation"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_printer_attributes"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_job_attributes".to_string(),
                description: "Query job status after submitting a print job".to_string(),
                parameters: vec![Parameter {
                    name: "job_id".to_string(),
                    type_hint: "number".to_string(),
                    description: "Job ID to query".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_job_attributes",
                    "job_id": 123
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IPP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "ipp_connected",
                "Triggered when IPP client is initialized",
                json!({"type": "get_printer_attributes"}),
            ),
            EventType::new(
                "ipp_response_received",
                "Triggered when IPP client receives a response from the printer",
                json!({"type": "get_job_attributes", "job_id": 123}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>IPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ipp",
            "ipp client",
            "internet printing protocol",
            "print",
            "printer",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .implementation("ipp crate 5.3 with AsyncIppClient")
                .llm_control("Full control over print operations: get-printer-attributes, print-job, get-job-attributes")
                .e2e_testing("CUPS test server or local IPP printer")
                .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "IPP client for printing and querying print jobs"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to ipp://localhost:631/printers/test-printer and query its capabilities"
    }
    fn group_name(&self) -> &'static str {
        "File & Print"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls print operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:631",
                "base_stack": "ipp",
                "startup_params": {
                    "printer_path": "/printers/test-printer"
                },
                "instruction": "Query printer capabilities and submit a test print job"
            }),
            // Script mode: Code-based print job handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:631",
                "base_stack": "ipp",
                "startup_params": {
                    "printer_path": "/printers/test-printer"
                },
                "event_handlers": [{
                    "event_pattern": "ipp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ipp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed printer query
            json!({
                "type": "open_client",
                "remote_addr": "localhost:631",
                "base_stack": "ipp",
                "startup_params": {
                    "printer_path": "/printers/test-printer"
                },
                "event_handlers": [
                    {
                        "event_pattern": "ipp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "get_printer_attributes"
                            }]
                        }
                    },
                    {
                        "event_pattern": "ipp_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for IppClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::ipp::IppClient;

            // `printer_path` is a declared startup parameter and was read by nothing: the URI
            // was built from `remote_addr` alone, so every `startup_params:
            // {"printer_path": "/printers/test-printer"}` in this file's own examples did
            // nothing, and an operator who set the field in the dashboard got the same request
            // as one who left it blank.
            //
            // It matters more here than a dead knob usually does. IPP addresses a *printer*,
            // not a host: `http://host:631/printers/foo` and `http://host:631/printers/bar` are
            // different queues on the same server, and with no path the request goes to the
            // server root, which a real IPP server answers with 404 or with the wrong queue's
            // attributes.
            let printer_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("printer_path"))
                .transpose()?
                .flatten()
                .filter(|s| !s.trim().is_empty());

            IppClient::connect_with_llm_actions(
                ctx.remote_addr,
                printer_path,
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
            "get_printer_attributes" => Ok(ClientActionResult::Custom {
                name: "ipp_get_printer_attributes".to_string(),
                data: json!({}),
            }),
            "print_job" => {
                let job_name = action
                    .get("job_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'job_name' field")?
                    .to_string();

                let document_format = action
                    .get("document_format")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let document_data = action
                    .get("document_data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'document_data' field")?;

                // The encoding is declared, never sniffed.
                //
                // This used to guess: "all ASCII alphanumeric (plus +/=) and a length divisible
                // by four" meant base64, anything else meant text. A four-character document is
                // both — printing the word `Test` produced three bytes of binary on the wire and
                // nothing said so. `"48656c6c6f"` is simultaneously valid text and valid hex and
                // only the sender knows which it means; this is the same defect `send_tcp_data`
                // had, in base64 rather than hex, and the fix is the same explicit field.
                //
                // The old guess also swallowed a genuine base64 error into the raw bytes with
                // `unwrap_or_else`, so a truncated document was printed as its own base64 text.
                let data_bytes = match action
                    .get("encoding")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("utf8")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "utf8" | "utf-8" | "text" | "plain" => document_data.as_bytes().to_vec(),
                    "base64" | "b64" => {
                        use base64::{engine::general_purpose, Engine as _};
                        general_purpose::STANDARD
                            .decode(document_data)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                "print_job 'document_data' is not valid base64: {e}. Either fix \
                                 the encoding or omit the 'encoding' field to send the string \
                                 as text."
                            )
                            })?
                    }
                    other => {
                        return Err(anyhow::anyhow!(
                            "print_job 'encoding' must be \"utf8\" or \"base64\", got {other:?}"
                        ))
                    }
                };

                Ok(ClientActionResult::Custom {
                    name: "ipp_print_job".to_string(),
                    data: json!({
                        "job_name": job_name,
                        "document_format": document_format,
                        "document_data": data_bytes,
                    }),
                })
            }
            "get_job_attributes" => {
                // Range-check before narrowing. `as i32` wraps, so `4294967297` becomes `1`
                // and the client asks the printer about a completely different job — one it
                // may well have, so the answer looks like a real answer. RFC 8011 §5.3.2
                // types job-id as integer(1:MAX), which is exactly what this can carry.
                let job_id = action
                    .get("job_id")
                    .and_then(|v| v.as_i64())
                    .context("Missing or invalid 'job_id' field")?;
                if !(1..=i32::MAX as i64).contains(&job_id) {
                    return Err(anyhow::anyhow!(
                        "job_id {job_id} is not an IPP job-id (1-2147483647, RFC 8011 §5.3.2). \
                         Use the job-id the printer returned from print_job."
                    ));
                }
                let job_id = job_id as i32;

                Ok(ClientActionResult::Custom {
                    name: "ipp_get_job_attributes".to_string(),
                    data: json!({
                        "job_id": job_id,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // Declared in get_sync_actions, so it has to be executable here too --
            // advertising a name the executor rejects shows the model a tool it is
            // then punished for using.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown IPP client action: {}",
                action_type
            )),
        }
    }
}
