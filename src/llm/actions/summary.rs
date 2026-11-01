//! Action summary formatting for logging
//!
//! This module provides utilities to create concise, human-readable summaries
//! of LLM actions for logging purposes.

use super::common::CommonAction;
use super::tools::ToolAction;
use serde_json::Value;

/// Generate a summary of an action for logging
///
/// Returns a brief description like:
/// - "notify_operator"
/// - "open_server: HTTP:8080 \"Act as REST API...\""
/// - "read_file: schema.json (full, 1024 lines)"
pub fn summarize_action(action: &Value) -> String {
    // Try to parse as common action
    if let Ok(common) = CommonAction::from_json(action) {
        return summarize_common_action(&common);
    }

    // Try to parse as tool action
    if let Ok(tool) = ToolAction::from_json(action) {
        return tool.describe();
    }

    // Try to extract type for protocol-specific actions
    if let Some(action_type) = action.get("type").and_then(|t| t.as_str()) {
        return summarize_protocol_action(action_type, action);
    }

    // Fallback
    "unknown_action".to_string()
}

/// Summarize a common action
fn summarize_common_action(action: &CommonAction) -> String {
    match action {
        CommonAction::NotifyOperator { message } => {
            let preview = crate::utils::truncate_for_log(&message, 37);
            format!("notify_operator: \"{}\"", preview)
        }
        CommonAction::OpenServer {
            interface,
            port,
            protocol,
            instruction,
            ..
        } => {
            let instr_preview = crate::utils::truncate_for_log(&instruction, 27);
            let binding = if let Some(iface) = interface {
                format!("interface={}", iface)
            } else if let Some(p) = port {
                format!("port={}", p)
            } else {
                "default".to_string()
            };
            format!(
                "open_server: {} {} \"{}\"",
                protocol, binding, instr_preview
            )
        }
        CommonAction::CloseServer { server_id } => {
            format!("close_server: #{}", server_id)
        }
        CommonAction::CloseAllServers => "close_all_servers".to_string(),
        CommonAction::UpdateInstruction { instruction } => {
            let preview = crate::utils::truncate_for_log(&instruction, 27);
            format!("update_instruction: \"{}\"", preview)
        }
        CommonAction::ChangeModel { model } => {
            format!("change_model: {}", model)
        }
        CommonAction::SetMemory { value } => {
            let preview = crate::utils::truncate_for_log(&value, 27);
            format!("set_memory: \"{}\"", preview)
        }
        CommonAction::AppendMemory { value } => {
            let preview = crate::utils::truncate_for_log(&value, 27);
            format!("append_memory: \"{}\"", preview)
        }
        CommonAction::SetConnectionMemory { value } => {
            let preview = crate::utils::truncate_for_log(&value, 27);
            format!("set_connection_memory: \"{}\"", preview)
        }
        CommonAction::AppendConnectionMemory { value } => {
            let preview = crate::utils::truncate_for_log(&value, 27);
            format!("append_connection_memory: \"{}\"", preview)
        }
        CommonAction::AppendToLog {
            output_name,
            content,
        } => {
            let preview = crate::utils::truncate_for_log(&content, 27);
            format!("append_to_log: {} \"{}\"", output_name, preview)
        }
        CommonAction::ScheduleTask {
            task_id,
            recurring,
            delay_secs,
            interval_secs,
            ..
        } => {
            if *recurring {
                let interval = interval_secs.or(*delay_secs).unwrap_or(0);
                format!(
                    "schedule_task: {} (recurring, interval: {}s)",
                    task_id, interval
                )
            } else {
                let delay = delay_secs.unwrap_or(0);
                format!("schedule_task: {} (one-shot, delay: {}s)", task_id, delay)
            }
        }
        CommonAction::CancelTask { task_id } => {
            format!("cancel_task: {}", task_id)
        }
        CommonAction::OpenClient {
            protocol,
            remote_addr,
            instruction,
            ..
        } => {
            let instr_preview = crate::utils::truncate_for_log(&instruction, 27);
            format!(
                "open_client: {} → {} \"{}\"",
                protocol, remote_addr, instr_preview
            )
        }
        CommonAction::CloseClient { client_id } => {
            format!("close_client: #{}", client_id)
        }
        CommonAction::CloseAllClients => "close_all_clients".to_string(),
        CommonAction::CloseConnectionById { connection_id } => {
            format!("close_connection_by_id: #{}", connection_id)
        }
        CommonAction::ReconnectClient { client_id } => {
            format!("reconnect_client: #{}", client_id)
        }
        CommonAction::UpdateServer { server_id, .. } => {
            format!("update_server: #{}", server_id)
        }
        CommonAction::UpdateClient { client_id, .. } => {
            format!("update_client: #{}", client_id)
        }
        CommonAction::UpdateClientInstruction {
            client_id,
            instruction,
        } => {
            let preview = crate::utils::truncate_for_log(&instruction, 27);
            format!("update_client_instruction: #{} \"{}\"", client_id, preview)
        }
        CommonAction::ProvideFeedback { feedback } => {
            let summary = if let Some(obj) = feedback.as_object() {
                format!("provide_feedback: {} fields", obj.len())
            } else {
                "provide_feedback".to_string()
            };
            summary
        }
        #[cfg(feature = "sqlite")]
        CommonAction::CreateDatabase {
            name,
            is_memory,
            owner,
            schema_ddl,
        } => {
            let storage_type = if *is_memory {
                "in-memory"
            } else {
                "file-based"
            };
            let owner_display = owner.as_deref().unwrap_or("auto");
            format!(
                "create_database: {} ({}, owner: {}, schema: {})",
                name,
                storage_type,
                owner_display,
                if schema_ddl.is_some() { "yes" } else { "no" }
            )
        }
        #[cfg(feature = "sqlite")]
        CommonAction::DeleteDatabase { database_id } => {
            format!("delete_database: db-{}", database_id)
        }
    }
}

/// Summarize a protocol-specific action
fn summarize_protocol_action(action_type: &str, action: &Value) -> String {
    match action_type {
        // TCP actions
        "send_tcp_data" => {
            if let Some(data) = action.get("data").and_then(|d| d.as_str()) {
                let preview = crate::utils::truncate_for_log(&data, 27);
                format!("send_tcp_data: \"{}\"", preview)
            } else {
                "send_tcp_data".to_string()
            }
        }
        "send_to_connection" => {
            if let Some(conn_id) = action.get("connection_id").and_then(|c| c.as_str()) {
                format!("send_to_connection: {}", conn_id)
            } else {
                "send_to_connection".to_string()
            }
        }
        "close_tcp_connection" => "close_tcp_connection".to_string(),

        // HTTP actions
        "send_http_response" => {
            if let Some(status) = action.get("status").and_then(|s| s.as_u64()) {
                format!("send_http_response: {}", status)
            } else {
                "send_http_response".to_string()
            }
        }

        // UDP actions
        "send_udp_response" => "send_udp_response".to_string(),
        "send_to_address" => {
            if let Some(addr) = action.get("address").and_then(|a| a.as_str()) {
                format!("send_to_address: {}", addr)
            } else {
                "send_to_address".to_string()
            }
        }

        // DNS actions
        "send_dns_response" => {
            if let Some(record_type) = action.get("record_type").and_then(|r| r.as_str()) {
                format!("send_dns_response: {}", record_type)
            } else {
                "send_dns_response".to_string()
            }
        }

        // DHCP actions
        "send_dhcp_response" => {
            if let Some(msg_type) = action.get("message_type").and_then(|m| m.as_str()) {
                format!("send_dhcp_response: {}", msg_type)
            } else {
                "send_dhcp_response".to_string()
            }
        }

        // NTP actions
        "send_ntp_response" => "send_ntp_response".to_string(),

        // SNMP actions
        "send_snmp_response" => "send_snmp_response".to_string(),
        "send_trap" => {
            if let Some(oid) = action.get("trap_oid").and_then(|o| o.as_str()) {
                format!("send_trap: {}", oid)
            } else {
                "send_trap".to_string()
            }
        }

        // SSH actions
        "send_ssh_data" => "send_ssh_data".to_string(),
        "send_ssh_exit" => "send_ssh_exit".to_string(),

        // IRC actions
        "send_irc_message" => "send_irc_message".to_string(),

        // Generic fallback
        _ => action_type.to_string(),
    }
}

/// Generate a summary of all actions in a response
///
/// Returns a string like:
/// "3 actions: → read_file: schema.json (full), → open_server: HTTP:8080 \"...\", → notify_operator"
pub fn summarize_actions(actions: &[Value]) -> String {
    if actions.is_empty() {
        return "0 actions".to_string();
    }

    let summaries: Vec<String> = actions
        .iter()
        .map(|a| format!("→ {}", summarize_action(a)))
        .collect();

    format!("{} actions: {}", actions.len(), summaries.join(", "))
}
