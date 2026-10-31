//! Shared HTTP action execution logic

use crate::llm::actions::protocol_trait::ActionResult;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use tracing::debug;

/// Parsed HTTP response data
#[derive(Debug)]
pub struct HttpResponseData {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Execute HTTP response action (shared by HTTP/1.1 and HTTP/2).
///
/// Deliberately lenient about the shapes models actually emit, because a
/// rejected action never reaches the client: `execute_actions()` only logs a
/// warning and drops it, and the request then falls through to the server's
/// `default_response` or, without one, a fail-closed `500`. Concretely:
///
/// - `status` may be a number or a numeric string (`200` or `"200"`), and must
///   be a real HTTP status (100-599) — a bogus value is an error here rather
///   than a panic later while building the response.
/// - `body` is optional: omitting it means an empty body, which is what a 204 /
///   304 needs. A non-string body (object/array/number) is serialized to JSON
///   text instead of being discarded.
/// - header values that are not strings are stringified rather than dropped.
///
/// The result is the structured response the request handler turns into a real
/// HTTP response; it is always UTF-8 text — there is no path for binary bodies.
pub fn execute_http_response_action(action: serde_json::Value) -> Result<ActionResult> {
    let status_value = action
        .get("status")
        .context("Missing 'status' parameter (HTTP status code, e.g. 200)")?;

    let status = match status_value {
        serde_json::Value::Number(n) => n.as_u64(),
        // Models routinely quote the status code.
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
    .filter(|s| (100..=599).contains(s))
    .with_context(|| {
        format!(
            "Invalid 'status' parameter {}: expected an HTTP status code between 100 and 599",
            status_value
        )
    })? as u16;

    let headers = action
        .get("headers")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| match v {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(s) => Some((k.clone(), s.clone())),
                    other => Some((k.clone(), other.to_string())),
                })
                .collect::<HashMap<String, String>>()
        })
        .unwrap_or_default();

    let body = match action.get("body") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => {
            debug!(
                "HTTP response body was not a string; serializing {} to JSON text",
                other
            );
            other.to_string()
        }
    };

    // Return structured data that caller will convert to HTTP response
    let response_data = json!({
        "status": status,
        "headers": headers,
        "body": body
    });

    Ok(ActionResult::Output(
        serde_json::to_vec(&response_data).context("Failed to serialize HTTP response")?,
    ))
}
