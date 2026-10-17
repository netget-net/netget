//! XML-RPC protocol actions implementation
//!
//! This module implements the action system for XML-RPC.
//! The LLM controls all XML-RPC responses through these actions, including:
//! - Method execution responses (success values, faults)
//! - Introspection (system.listMethods, system.methodHelp, system.methodSignature)
//! - Extensions (nil values, i8/64-bit integers, system.multicall)

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{Event, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

use super::{generate_fault, generate_success_response, MethodCall, XmlRpcValue};

/// XML-RPC protocol action handler
pub struct XmlRpcProtocol;

impl XmlRpcProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Read an integer the model may have written as a JSON string.
    ///
    /// Models routinely quote numbers (`"8"` for `8`), and refusing that turns
    /// an otherwise correct answer into an XML-RPC fault the caller cannot act
    /// on. The rest of the tree already coerces this way (usb-fido2's
    /// `approval_id` takes a number or a numeric string), so accept it here
    /// too. Anything that is not a whole number is still refused.
    fn as_integer(value: &serde_json::Value, what: &str) -> Result<i64> {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            .with_context(|| {
                format!(
                    "value must be an integer for value_type '{}', got {}",
                    what, value
                )
            })
    }

    /// Same for doubles: `"19.99"` is a number a model plausibly quotes.
    fn as_double(value: &serde_json::Value) -> Result<f64> {
        value
            .as_f64()
            .or_else(|| value.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
            .with_context(|| {
                format!(
                    "value must be a number for value_type 'double', got {}",
                    value
                )
            })
    }

    /// Same for booleans: XML-RPC itself writes them as 0/1, and models mirror
    /// that or quote `"true"`.
    fn as_boolean(value: &serde_json::Value) -> Result<bool> {
        if let Some(b) = value.as_bool() {
            return Ok(b);
        }
        if let Some(i) = value.as_i64() {
            return Ok(i != 0);
        }
        match value.as_str().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref s) if s == "true" || s == "1" => Ok(true),
            Some(ref s) if s == "false" || s == "0" => Ok(false),
            _ => Err(anyhow::anyhow!(
                "value must be a boolean for value_type 'boolean', got {}",
                value
            )),
        }
    }

    fn execute_success_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let value_type = action
            .get("value_type")
            .and_then(|v| v.as_str())
            .context("Missing 'value_type' parameter")?;

        let value = action.get("value").context("Missing 'value' parameter")?;

        // Convert JSON value to XmlRpcValue
        let xmlrpc_value = match value_type {
            "int" | "i4" => {
                // Range-checked, not cast: `as i32` silently wrapped, so 5000000000
                // went on the wire as 705032704.
                let i = Self::as_integer(value, value_type)?;
                let i = i32::try_from(i).map_err(|_| {
                    anyhow::anyhow!(
                        "{} does not fit in an XML-RPC <int> (-2147483648..2147483647); use value_type 'i8'",
                        i
                    )
                })?;
                XmlRpcValue::Int(i)
            }
            "i8" => {
                let i = Self::as_integer(value, "i8")?;
                XmlRpcValue::I8(i)
            }
            "boolean" | "bool" => {
                let b = Self::as_boolean(value)?;
                XmlRpcValue::Boolean(b)
            }
            "string" => {
                let s = value.as_str().context("Invalid string value")?;
                XmlRpcValue::String(s.to_string())
            }
            "double" => {
                let d = Self::as_double(value)?;
                if !d.is_finite() {
                    // NaN/inf render as "NaN"/"inf", which is not valid <double>.
                    return Err(anyhow::anyhow!("double value must be finite"));
                }
                XmlRpcValue::Double(d)
            }
            "array" => {
                let arr = value.as_array().context("Invalid array value")?;
                let items: Vec<XmlRpcValue> = arr
                    .iter()
                    .map(|v| self.json_to_xmlrpc_value(v))
                    .collect::<Result<Vec<_>>>()?;
                XmlRpcValue::Array(items)
            }
            "struct" => {
                let obj = value.as_object().context("Invalid struct value")?;
                let members: Vec<(String, XmlRpcValue)> = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.json_to_xmlrpc_value(v)?)))
                    .collect::<Result<Vec<_>>>()?;
                XmlRpcValue::Struct(members)
            }
            "nil" | "null" => XmlRpcValue::Nil,
            _ => return Err(anyhow::anyhow!("Unknown value_type: {}", value_type)),
        };

        let xml = generate_success_response(&xmlrpc_value);

        debug!("XML-RPC success response generated ({} bytes)", xml.len());
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_fault_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // `fault_code` is declared `required: true`, and a value that is present but not a
        // whole number is an error rather than a silent -32603. It used to be
        // `.and_then(|v| v.as_i64()).unwrap_or(-32603)`, so the quoted form models routinely
        // produce — `"fault_code": "-32601"` — became "internal error" on the wire: the model
        // said "no such method" and the caller was told netget had broken. `as_integer`
        // accepts the quoted form for the same reason every other field here does.
        // Absent stays -32603, which is the honest default for "the handler did not say".
        let code_i64 = match action.get("fault_code") {
            Some(value) => Self::as_integer(value, "fault_code")?,
            None => -32603,
        };
        let code = i32::try_from(code_i64).map_err(|_| {
            anyhow::anyhow!("fault_code {} does not fit in an XML-RPC <int>", code_i64)
        })?;

        let message = action
            .get("fault_string")
            .and_then(|v| v.as_str())
            .context("Missing 'fault_string' parameter")?;

        let xml = generate_fault(code, message);

        debug!("XML-RPC fault response: {} - {}", code, message);
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_list_methods_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let methods = action
            .get("methods")
            .and_then(|v| v.as_array())
            .context("Missing 'methods' parameter")?;

        // Non-string entries used to be dropped silently while the log still
        // reported methods.len(), so the log disagreed with the wire.
        let method_list: Vec<XmlRpcValue> = methods
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| XmlRpcValue::String(s.to_string()))
                    .context("every entry of 'methods' must be a method-name string")
            })
            .collect::<Result<Vec<_>>>()?;

        let method_count = method_list.len();
        let response_value = XmlRpcValue::Array(method_list);
        let xml = generate_success_response(&response_value);

        debug!(
            "XML-RPC system.listMethods response ({} methods)",
            method_count
        );
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_method_help_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let help_text = action
            .get("help_text")
            .and_then(|v| v.as_str())
            .context("Missing 'help_text' parameter")?;

        let response_value = XmlRpcValue::String(help_text.to_string());
        let xml = generate_success_response(&response_value);

        debug!("XML-RPC system.methodHelp response");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    fn execute_method_signature_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let signatures = action
            .get("signatures")
            .and_then(|v| v.as_array())
            .context("Missing 'signatures' parameter")?;

        // Convert signatures array to XML-RPC array of arrays
        // A flat list like ["int","int"] used to produce an empty result with no
        // error, because every non-array entry was filtered out.
        let sig_list: Vec<XmlRpcValue> = signatures
            .iter()
            .map(|v| {
                let arr = v.as_array().context(
                    "each entry of 'signatures' must itself be an array of type names, \
                     starting with the return type",
                )?;
                let types: Vec<XmlRpcValue> = arr
                    .iter()
                    .map(|t| {
                        t.as_str()
                            .map(|s| XmlRpcValue::String(s.to_string()))
                            .context("signature type names must be strings")
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(XmlRpcValue::Array(types))
            })
            .collect::<Result<Vec<_>>>()?;

        let response_value = XmlRpcValue::Array(sig_list);
        let xml = generate_success_response(&response_value);

        debug!("XML-RPC system.methodSignature response");
        Ok(ActionResult::Output(xml.as_bytes().to_vec()))
    }

    /// Helper: Convert JSON value to XmlRpcValue (auto-detect type)
    fn json_to_xmlrpc_value(&self, value: &serde_json::Value) -> Result<XmlRpcValue> {
        match value {
            serde_json::Value::Null => Ok(XmlRpcValue::Nil),
            serde_json::Value::Bool(b) => Ok(XmlRpcValue::Boolean(*b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                        Ok(XmlRpcValue::Int(i as i32))
                    } else {
                        Ok(XmlRpcValue::I8(i))
                    }
                } else if let Some(f) = n.as_f64() {
                    Ok(XmlRpcValue::Double(f))
                } else {
                    Err(anyhow::anyhow!("Invalid number"))
                }
            }
            serde_json::Value::String(s) => Ok(XmlRpcValue::String(s.clone())),
            serde_json::Value::Array(arr) => {
                let items: Vec<XmlRpcValue> = arr
                    .iter()
                    .map(|v| self.json_to_xmlrpc_value(v))
                    .collect::<Result<Vec<_>>>()?;
                Ok(XmlRpcValue::Array(items))
            }
            serde_json::Value::Object(obj) => {
                let members: Vec<(String, XmlRpcValue)> = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.json_to_xmlrpc_value(v)?)))
                    .collect::<Result<Vec<_>>>()?;
                Ok(XmlRpcValue::Struct(members))
            }
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for XmlRpcProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // XML-RPC is purely request-response, no async actions needed
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            success_response_action(),
            fault_response_action(),
            list_methods_response_action(),
            method_help_response_action(),
            method_signature_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "XML-RPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![XMLRPC_METHOD_CALL_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>XML-RPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["xmlrpc", "xml-rpc", "xml rpc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Hand-written XML-RPC codec over HTTP POST (quick-xml, hyper 1)")
            .llm_control("Every method call: a typed return value or a fault code/string")
            .e2e_testing("curl and mocked in-process HTTP")
            .notes(
                "Parameters reach the model with their XML-RPC types: <int>5</int> is the \
                 number 5, not \"5\". <base64> is reported as a structural description, not \
                 an encoded blob. Faults are XML-escaped, so a fault_string containing < or \
                 & is still valid XML. system.multicall is not implemented. Any path is \
                 accepted; there is no auth, no rate limiting, and non-POST returns a fault \
                 body with HTTP 200 rather than 405. Request bodies are capped at 4 MiB and \
                 value nesting at 64 levels.",
            )
            .max_inbound_bytes(crate::server::xmlrpc::MAX_REQUEST_BODY_BYTES)
            .request_only(
                "XML-RPC is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "XML-RPC server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an XML-RPC server on port 8080 with methods add(a,b) and greet(name)"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: instruction-based
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "xmlrpc",
                "instruction": "XML-RPC server with add(a,b), subtract(a,b), and system.listMethods. Return proper fault codes for errors"
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "xmlrpc",
                "event_handlers": [{
                    "event_pattern": "xmlrpc_method_call",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "method = event.get('method_name', '')\nparams = event.get('params', [])\nif method == 'add' and len(params) >= 2:\n    action('xmlrpc_success_response', value_type='int', value=params[0] + params[1])\nelse:\n    action('xmlrpc_fault_response', fault_code=-32601, fault_string='Method not found')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "xmlrpc",
                "event_handlers": [{
                    "event_pattern": "xmlrpc_method_call",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "xmlrpc_success_response",
                            "value_type": "string",
                            "value": "Hello from XML-RPC server"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for XmlRpcProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::xmlrpc::XmlRpcServer;
            XmlRpcServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field")?;

        match action_type {
            "xmlrpc_success_response" => self.execute_success_response(action),
            "xmlrpc_fault_response" => self.execute_fault_response(action),
            "xmlrpc_list_methods_response" => self.execute_list_methods_response(action),
            "xmlrpc_method_help_response" => self.execute_method_help_response(action),
            "xmlrpc_method_signature_response" => self.execute_method_signature_response(action),
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}

// Action definitions

fn success_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "xmlrpc_success_response".to_string(),
        description: "Send XML-RPC success response with a value".to_string(),
        parameters: vec![
            Parameter {
                name: "value_type".to_string(),
                type_hint: "string".to_string(),
                description: "Type of the return value (int, i8, boolean, string, double, array, struct, nil)".to_string(),
                required: true,
            },
            Parameter {
                name: "value".to_string(),
                type_hint: "any".to_string(),
                description: "The actual value to return (type must match value_type)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "xmlrpc_success_response",
            "value_type": "int",
            "value": 42
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XML-RPC success type={value_type}")
                .with_debug("XML-RPC xmlrpc_success_response: type={value_type}"),
        ),
    }
}

fn fault_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "xmlrpc_fault_response".to_string(),
        description: "Send XML-RPC fault/error response".to_string(),
        parameters: vec![
            Parameter {
                name: "fault_code".to_string(),
                type_hint: "number".to_string(),
                description: "Fault code (standard codes: -32700 parse error, -32600 invalid request, -32601 method not found, -32602 invalid params, -32603 internal error)".to_string(),
                required: true,
            },
            Parameter {
                name: "fault_string".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "xmlrpc_fault_response",
            "fault_code": -32601,
            "fault_string": "Method not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XML-RPC fault {fault_code}: {fault_string}")
                .with_debug("XML-RPC xmlrpc_fault_response: code={fault_code} message={fault_string}"),
        ),
    }
}

fn list_methods_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "xmlrpc_list_methods_response".to_string(),
        description: "Respond to system.listMethods introspection with array of method names"
            .to_string(),
        parameters: vec![Parameter {
            name: "methods".to_string(),
            type_hint: "array".to_string(),
            description: "Array of available method names (strings)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "xmlrpc_list_methods_response",
            "methods": ["add", "subtract", "system.listMethods", "system.methodHelp"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XML-RPC list methods ({methods_len})")
                .with_debug("XML-RPC xmlrpc_list_methods_response: count={methods_len}"),
        ),
    }
}

fn method_help_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "xmlrpc_method_help_response".to_string(),
        description: "Respond to system.methodHelp introspection with documentation string"
            .to_string(),
        parameters: vec![Parameter {
            name: "help_text".to_string(),
            type_hint: "string".to_string(),
            description: "Documentation/help text for the requested method".to_string(),
            required: true,
        }],
        example: json!({
            "type": "xmlrpc_method_help_response",
            "help_text": "add(a, b) - Returns the sum of two numbers"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XML-RPC method help")
                .with_debug("XML-RPC xmlrpc_method_help_response"),
        ),
    }
}

fn method_signature_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "xmlrpc_method_signature_response".to_string(),
        description: "Respond to system.methodSignature introspection with array of signatures".to_string(),
        parameters: vec![Parameter {
            name: "signatures".to_string(),
            type_hint: "array".to_string(),
            description: "Array of signature arrays. Each signature is [return_type, param1_type, param2_type, ...]. Multiple signatures indicate overloads.".to_string(),
            required: true,
        }],
        example: json!({
            "type": "xmlrpc_method_signature_response",
            "signatures": [["int", "int", "int"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> XML-RPC method signature")
                .with_debug("XML-RPC xmlrpc_method_signature_response: {signatures_len} sigs"),
        ),
    }
}

// Event type definitions

/// XML-RPC method call event
pub static XMLRPC_METHOD_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmlrpc_method_call",
        "XML-RPC method call received from client",
        json!({
            "type": "xmlrpc_success_response",
            "value_type": "int",
            "value": 42
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method_name".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the RPC method being called".to_string(),
            required: true,
        },
        Parameter {
            name: "params".to_string(),
            type_hint: "array".to_string(),
            description: "Array of parameter values (can be integers, strings, booleans, arrays, structs, etc.)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        success_response_action(),
        fault_response_action(),
        list_methods_response_action(),
        method_help_response_action(),
        method_signature_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("XML-RPC {method_name}")
            .with_debug("XML-RPC method={method_name}")
            .with_trace("XML-RPC: {json_pretty(.)}"),
    )
});

/// Create event from method call
pub fn create_method_call_event(method_call: &MethodCall) -> Event {
    // Convert XmlRpcValue params to JSON
    let params_json: Vec<serde_json::Value> = method_call
        .params
        .iter()
        .map(xmlrpc_value_to_json)
        .collect();

    Event::new(
        &XMLRPC_METHOD_CALL_EVENT,
        json!({
            "method_name": method_call.method_name,
            "params": params_json,
        }),
    )
}

/// Convert XmlRpcValue to JSON for LLM
fn xmlrpc_value_to_json(value: &XmlRpcValue) -> serde_json::Value {
    match value {
        XmlRpcValue::Int(i) => json!(i),
        XmlRpcValue::I8(i) => json!(i),
        XmlRpcValue::Boolean(b) => json!(b),
        XmlRpcValue::String(s) => json!(s),
        XmlRpcValue::Double(d) => json!(d),
        XmlRpcValue::DateTime(dt) => json!(dt),
        // Never hand the model a base64 blob (project rule: no raw bytes or
        // encoded payloads in event data). Report it structurally, with the text
        // only when the bytes happen to be UTF-8. This path is newly reachable:
        // before the parser was fixed, <base64> was decoded as a plain string.
        XmlRpcValue::Base64(bytes) => json!({
            "xmlrpc_type": "base64",
            "byte_length": bytes.len(),
            "text": std::str::from_utf8(bytes).ok(),
        }),
        XmlRpcValue::Array(arr) => {
            let items: Vec<serde_json::Value> = arr.iter().map(xmlrpc_value_to_json).collect();
            json!(items)
        }
        XmlRpcValue::Struct(members) => {
            let obj: serde_json::Map<String, serde_json::Value> = members
                .iter()
                .map(|(k, v)| (k.clone(), xmlrpc_value_to_json(v)))
                .collect();
            json!(obj)
        }
        XmlRpcValue::Nil => json!(null),
    }
}
