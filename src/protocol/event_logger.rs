//! Event lifecycle logging
//!
//! Provides centralized logging for event processing lifecycle:
//! - Event start (when event is received)
//! - Event completion (when actions are executed)
//! - Action execution logging
//!
//! Uses LogTemplate for protocol-specific log formatting.
//!
//! Every level a template renders reaches the status stream as well as the file
//! (`Sink::Both` for DEBUG and TRACE): a protocol writes one template per level so that the
//! dashboard's log-level filter can show the detail it asks for, and
//! `tests/server/{openvpn,ipsec}/log_template_test.rs` read the DEBUG line off the channel.

use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::{Log, Sink};
use crate::protocol::log_template::{LogLevel, LogTemplate};
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::ServerId;
use crate::utils::clock::Instant;
use serde_json::Value;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;

/// Context for logging an event's lifecycle
///
/// Tracks timing and context information from event start to completion.
/// Provides methods to log at appropriate levels using the event's LogTemplate.
///
/// # Example
/// ```rust,ignore
/// let ctx = EventLogContext::new(
///     &event,
///     server_id,
///     Some(connection_id),
///     Some(client_addr),
///     "HTTP",
/// );
///
/// ctx.log_start(Some(&status_tx));
///
/// // ... process event, get action results ...
///
/// ctx.log_complete(Some(&status_tx), &action_results);
/// ```
pub struct EventLogContext<'a> {
    /// Reference to the event being logged
    pub event: &'a Event,
    /// When event processing started
    pub start_time: Instant,
    /// Server ID processing this event
    pub server_id: ServerId,
    /// Connection ID if applicable
    pub connection_id: Option<ConnectionId>,
    /// Client address if known
    pub client_addr: Option<SocketAddr>,
    /// Protocol name for fallback logging
    pub protocol_name: String,
}

impl<'a> EventLogContext<'a> {
    /// Create a new event log context
    ///
    /// Automatically records the start time for duration tracking.
    pub fn new(
        event: &'a Event,
        server_id: ServerId,
        connection_id: Option<ConnectionId>,
        client_addr: Option<SocketAddr>,
        protocol_name: impl Into<String>,
    ) -> Self {
        Self {
            event,
            start_time: Instant::now(),
            server_id,
            connection_id,
            client_addr,
            protocol_name: protocol_name.into(),
        }
    }

    /// Build enriched data with context fields
    ///
    /// Adds client_ip, client_port, server_id, connection_id to the event data.
    ///
    /// `pub` so `tests/event_logger_test.rs` can assert on the enrichment
    /// directly — CLAUDE.md forbids unit-test modules in `src/`, so an
    /// internal helper has to be reachable to be tested.
    pub fn build_enriched_data(&self) -> Value {
        let mut data = self.event.data.clone();
        if let Some(obj) = data.as_object_mut() {
            if let Some(addr) = self.client_addr {
                obj.insert(
                    "client_ip".to_string(),
                    serde_json::json!(addr.ip().to_string()),
                );
                obj.insert("client_port".to_string(), serde_json::json!(addr.port()));
            }
            obj.insert(
                "server_id".to_string(),
                serde_json::json!(self.server_id.as_u32()),
            );
            if let Some(conn_id) = self.connection_id {
                obj.insert(
                    "connection_id".to_string(),
                    serde_json::json!(conn_id.as_u32()),
                );
            }
            obj.insert(
                "protocol".to_string(),
                serde_json::json!(self.protocol_name.clone()),
            );
            obj.insert("event_id".to_string(), serde_json::json!(self.event.id()));
        }
        data
    }

    /// Log event start (DEBUG level)
    ///
    /// Called when an event is received and about to be processed.
    /// Uses the event's debug template if available, otherwise falls back
    /// to a generic message.
    pub fn log_start(&self, status_tx: Option<&UnboundedSender<String>>) {
        let data = self.build_enriched_data();

        if let Some(ref template) = self.event.event_type.log_template {
            if let Some(msg) = template.render(LogLevel::Debug, &data) {
                Log::new(status_tx).debug_to(Sink::Both, &msg);
                return;
            }
        }

        // Fallback: log event ID and basic info
        let fallback_msg = format!(
            "{} event '{}' from {}",
            self.protocol_name,
            self.event.id(),
            self.client_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        Log::new(status_tx).debug_to(Sink::Both, &fallback_msg);
    }

    /// Log event completion (INFO/DEBUG/TRACE levels)
    ///
    /// Called after actions have been executed.
    /// Enriches data with timing and response information.
    ///
    /// Logs at:
    /// - INFO: One-liner access log style
    /// - DEBUG: With timing information
    /// - TRACE: Full details
    pub fn log_complete(
        &self,
        status_tx: Option<&UnboundedSender<String>>,
        action_results: &[ActionResult],
    ) {
        let duration = self.start_time.elapsed();
        let mut data = self.build_enriched_data();

        // Add timing and result info
        if let Some(obj) = data.as_object_mut() {
            obj.insert(
                "duration_ms".to_string(),
                serde_json::json!(duration.as_millis() as u64),
            );
            obj.insert(
                "action_count".to_string(),
                serde_json::json!(action_results.len()),
            );

            // Calculate total response bytes
            let response_bytes: usize = action_results
                .iter()
                .flat_map(|r| r.get_all_output())
                .map(|o| o.len())
                .sum();
            obj.insert(
                "response_bytes".to_string(),
                serde_json::json!(response_bytes),
            );

            // Add status from first Custom result if present
            for result in action_results {
                if let ActionResult::Custom {
                    name,
                    data: custom_data,
                } = result
                {
                    if let Some(status) = custom_data.get("status") {
                        obj.insert("status".to_string(), status.clone());
                    }
                    obj.insert("action_name".to_string(), serde_json::json!(name));
                    break;
                }
            }
        }

        if let Some(ref template) = self.event.event_type.log_template {
            // TRACE: Full details
            if let Some(msg) = template.render(LogLevel::Trace, &data) {
                Log::new(status_tx).trace_to(Sink::Both, &msg);
            }

            // INFO: Access log style (one-liner)
            if let Some(msg) = template.render(LogLevel::Info, &data) {
                Log::new(status_tx).info(&msg);
            }

            // DEBUG: With timing (always log at debug for event completion)
            if let Some(msg) = template.render(LogLevel::Debug, &data) {
                let msg_with_timing = format!("{} ({}ms)", msg, duration.as_millis());
                Log::new(status_tx).debug_to(Sink::Both, &msg_with_timing);
            } else {
                // Fallback debug with timing
                let fallback_msg = format!(
                    "{} '{}' completed in {}ms, {} action(s), {} bytes",
                    self.protocol_name,
                    self.event.id(),
                    duration.as_millis(),
                    action_results.len(),
                    data.get("response_bytes")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                Log::new(status_tx).debug_to(Sink::Both, &fallback_msg);
            }
        } else {
            // No template: fallback logging
            let fallback_msg = format!(
                "{} '{}' completed in {}ms, {} action(s)",
                self.protocol_name,
                self.event.id(),
                duration.as_millis(),
                action_results.len()
            );
            Log::new(status_tx).debug_to(Sink::Both, &fallback_msg);
        }
    }
}

/// Log action execution result
///
/// Called after a protocol action has been executed.
/// Uses the action's log template if available.
///
/// # Arguments
/// * `action_name` - The action type name (e.g., "send_http_response")
/// * `action_data` - The action JSON data
/// * `result` - The ActionResult from execution
/// * `template` - Optional LogTemplate from the ActionDefinition
/// * `status_tx` - Optional channel for TUI updates
pub fn log_action_result(
    action_name: &str,
    action_data: &Value,
    result: &ActionResult,
    template: Option<&LogTemplate>,
    status_tx: Option<&UnboundedSender<String>>,
) {
    // Enrich action data with result info
    let mut enriched_data = action_data.clone();
    if let Some(obj) = enriched_data.as_object_mut() {
        // Add output info
        let output_bytes: usize = result.get_all_output().iter().map(|o| o.len()).sum();
        obj.insert("output_bytes".to_string(), serde_json::json!(output_bytes));
        obj.insert(
            "closes_connection".to_string(),
            serde_json::json!(result.closes_connection()),
        );
        obj.insert(
            "waits_for_more".to_string(),
            serde_json::json!(result.waits_for_more()),
        );
        obj.insert("action_name".to_string(), serde_json::json!(action_name));
    }

    if let Some(template) = template {
        // Use template if available
        if let Some(msg) = template.render(LogLevel::Trace, &enriched_data) {
            Log::new(status_tx).trace_to(Sink::Both, format!("Action {}: {}", action_name, msg));
        }

        if let Some(msg) = template.render(LogLevel::Debug, &enriched_data) {
            Log::new(status_tx).debug_to(Sink::Both, format!("Action {}: {}", action_name, msg));
        }

        if let Some(msg) = template.render(LogLevel::Info, &enriched_data) {
            Log::new(status_tx).info(format!("Action {}: {}", action_name, msg));
        }
    } else {
        // Fallback to summarize_action
        let summary = crate::llm::actions::summarize_action(action_data);
        Log::new(status_tx).debug_to(Sink::Both, format!("Action executed: {}", summary));
    }
}
