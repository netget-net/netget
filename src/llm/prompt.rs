//! Prompt building for LLM interactions
//!
//! This module provides two main prompt builders:
//! 1. User input handler - interprets user commands and manages the server
//! 2. Network event handler - handles incoming network events based on instructions

use crate::llm::actions::{
    generate_base_stack_documentation, get_all_tool_actions, get_network_event_tool_actions,
    get_user_input_common_actions, ActionDefinition,
};
use crate::llm::ollama_client::Message;
use crate::llm::template_engine::{TemplateDataBuilder, TEMPLATE_ENGINE};
use crate::state::app_state::AppState;
use crate::state::ServerId;

/// Builder for constructing LLM prompts
pub struct PromptBuilder;

impl PromptBuilder {
    // ============================================================================
    // SECTION BUILDERS - These build individual sections of prompts
    // (Only used for programmatic generation, not in templates)
    // ============================================================================

    /// Build current state section (server state + system capabilities)
    async fn build_current_state_section(state: &AppState, server_id: Option<ServerId>) -> String {
        Self::build_current_state_section_public(state, server_id).await
    }

    /// Public version of build_current_state_section for use by conversation handler
    pub async fn build_current_state_section_public(
        state: &AppState,
        server_id: Option<ServerId>,
    ) -> String {
        let mode = state.get_mode().await;
        let servers = state.get_all_servers().await;
        let system_caps = state.get_system_capabilities().await;

        let mut current_state = String::from("# Current State\n\n");

        if let Some(sid) = server_id {
            // Specific server context
            if let Some(server) = servers.iter().find(|s| s.id == sid) {
                current_state.push_str(&format!(
                    r#"## Active Server

- **Server ID**: #{}
- **Protocol**: {}
- **Port**: {}
- **Status**: {}
- **Memory**: {}
"#,
                    server.id.as_u32(),
                    server.protocol_name,
                    server.port,
                    server.status,
                    if server.memory.is_empty() {
                        "(empty)"
                    } else {
                        &server.memory
                    }
                ));
            } else {
                current_state.push_str("Server not found.\n");
            }
        } else if mode == crate::state::app_state::Mode::Server && !servers.is_empty() {
            // All servers context
            current_state.push_str("## Running Servers\n\n");
            current_state.push_str("You may be asked to update these servers and you need to refer to them by number:\n\n");
            for server in &servers {
                current_state.push_str(&format!(
                    "- Server #{}: **{}** on port {} ({})\n",
                    server.id.as_u32(),
                    server.protocol_name,
                    server.port,
                    server.status
                ));
            }
            current_state.push('\n');
        } else {
            current_state.push_str("No servers currently running.\n\n");
        }

        // Append system capabilities
        current_state.push_str(&format!(
            r#"## System Capabilities

- **Privileged ports (<1024)**: {} {}
- **Raw socket access**: {} {}

"#,
            if system_caps.can_bind_privileged_ports {
                "✓ Available"
            } else {
                "✗ Not available"
            },
            if system_caps.can_bind_privileged_ports {
                ""
            } else {
                "— Warn user if they request port <1024"
            },
            if system_caps.has_raw_socket_access {
                "✓ Available"
            } else {
                "✗ Not available"
            },
            if system_caps.has_raw_socket_access {
                ""
            } else {
                "— DataLink protocol unavailable"
            }
        ));

        // Append SQLite databases information
        #[cfg(feature = "sqlite")]
        {
            let databases = state.get_all_databases().await;
            if !databases.is_empty() {
                current_state.push_str("## SQLite Databases\n\n");
                current_state.push_str("Active databases available for queries:\n\n");
                for db in databases {
                    current_state.push_str(&db.schema_summary());
                    current_state.push('\n');
                }
            }
        }

        current_state
    }

    /// Public version of build_actions_section for use by conversation handler
    pub fn build_actions_section_public(actions: &[ActionDefinition]) -> String {
        if actions.is_empty() {
            return "# Available Actions\n\nNo actions available.\n\n".to_string();
        }

        // Separate tool actions from regular actions
        let (tool_actions, regular_actions): (Vec<_>, Vec<_>) =
            actions.iter().partition(|a| a.is_tool());

        let mut text = String::new();

        // Show tool actions first if any exist
        if !tool_actions.is_empty() {
            text.push_str(
                r#"# Available Tools

Tools gather information and return results to you. After a tool completes, you'll be invoked again with the results so you can decide what to do next.

"#,
            );
            for (i, action) in tool_actions.iter().enumerate() {
                text.push_str(&format!("## {}. {}\n", i + 1, action.to_prompt_text()));
            }
        }

        // Then show regular actions
        if !regular_actions.is_empty() {
            text.push_str(
                r#"# Available Actions

Include actions in your JSON response to execute operations.
Include every action to execute, in order, in one final response without tool calls.
If tools are available, use them first; actions in an intermediate tool round are drafts.

"#,
            );
            for (i, action) in regular_actions.iter().enumerate() {
                text.push_str(&format!("## {}. {}\n", i + 1, action.to_prompt_text()));
            }
        }

        text
    }

    /// Build base stack documentation section (used for dynamic generation)
    fn build_base_stack_docs_section(
        include_disabled: bool,
        min_stability: Option<crate::protocol::metadata::DevelopmentState>,
    ) -> String {
        generate_base_stack_documentation(include_disabled, min_stability)
    }

    /// Build retry message for parse errors (minimal, reusable)
    ///
    /// Used when LLM returns invalid JSON. Shows the required format with one example.
    /// This is much shorter than repeating the entire prompt.
    ///
    /// # Arguments
    /// * `error` - The parse error that occurred
    pub fn build_retry_prompt(error: &str) -> String {
        format!(
            r#"# ❌ Error: Invalid Response Format

**Parse error:** {}

## What Went Wrong

Your response was not one JSON object of the required shape. This usually happens when:
- You included explanatory text before or after the JSON
- You wrapped the JSON in markdown code blocks
- The JSON syntax is incorrect (missing quotes, commas, brackets, etc.)
- You returned valid JSON of another shape, or several objects instead of one

## Required Format

One JSON object, optionally preceded by a `<reasoning>…</reasoning>` block, and nothing else:

```
{{"actions": [{{"type": "<an action from the Available Actions list>", "param": "value"}}]}}
```

- Put every action you want performed, in order, into that one `actions` array
- `{{"actions": []}}` means "do nothing now"
- Use a `tools` key only if the prompt above lists tools
- No markdown formatting

---

**Please retry:** Respond to the original request using the correct JSON format. Nothing from the rejected response was executed."#,
            error
        )
    }

    /// Build retry message for unknown action errors
    ///
    /// Used when LLM returns actions that don't exist. Lists the unknown actions
    /// and reminds the LLM to only use actions from the Available Actions list.
    ///
    /// # Arguments
    /// * `unknown_actions` - List of action names that don't exist
    /// * `available_action_names` - List of valid action names
    pub fn build_unknown_action_retry_prompt(
        unknown_actions: &[String],
        available_action_names: &[String],
    ) -> String {
        let unknown_list = unknown_actions
            .iter()
            .map(|a| format!("- `{}`", a))
            .collect::<Vec<_>>()
            .join("\n");

        // Always the names themselves: "see the section above" sent a model scrolling a long
        // prompt for the one thing this message exists to give it.
        let available_summary = available_action_names
            .iter()
            .map(|a| format!("`{}`", a))
            .collect::<Vec<_>>()
            .join(", ");
        // Only where the tool is actually offered. Network events and clients have no tools, and
        // a model that followed this advice there spent its last retry on another unknown action.
        let documentation_rule = if available_action_names
            .iter()
            .any(|a| a == "read_documentation")
        {
            "3. If you need a protocol-specific action, call the `read_documentation` tool first to learn that protocol's actions"
        } else {
            "3. Pick the closest match from the Valid Actions below; if none fits, return `{\"actions\": []}`"
        };

        format!(
            r#"# ❌ Error: Unknown Action(s)

**The following action(s) do not exist:**
{}

## What Went Wrong

You used action name(s) that are not in the Available Actions list. This is NOT allowed.

**CRITICAL RULES:**
1. You can ONLY use actions explicitly listed in the "Available Actions" section
2. Do NOT invent, guess, or hallucinate action names
{}

## Valid Actions

{}

---

**Please retry:** Use ONLY names from the Available Actions list. Return the complete corrected response; no action from the rejected response has been executed."#,
            unknown_list, documentation_rule, available_summary
        )
    }

    /// Build retry message for malformed action errors
    ///
    /// Used when LLM returns actions with missing required parameters or invalid values.
    /// Shows the malformed action JSON and the parse error.
    ///
    /// # Arguments
    /// * `malformed_actions` - List of (action_json, error_message) tuples
    pub fn build_malformed_action_retry_prompt(
        malformed_actions: &[(serde_json::Value, String)],
    ) -> String {
        let errors_list = malformed_actions
            .iter()
            .map(|(action_json, error)| {
                let action_str = serde_json::to_string_pretty(action_json)
                    .unwrap_or_else(|_| action_json.to_string());
                format!(
                    "**Action:**\n```json\n{}\n```\n**Error:** {}",
                    action_str, error
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        format!(
            r#"# ❌ Error: Malformed Action(s)

**The following action(s) have invalid or missing parameters:**

{}

## What Went Wrong

Your action JSON is missing required parameters or has invalid values. Each action type has specific required parameters that must be provided.

Look up the failing action's Parameters in "Available Actions": every parameter marked required must be present, with the documented type (numbers as numbers, not strings).

## How to Fix

Check the action definition in "Available Actions" for required parameters and provide all of them with correct types.

---

**Please retry:** Fix the malformed action(s) by providing all required parameters with correct values."#,
            errors_list
        )
    }

    /// Build format reminder message (added before every LLM call)
    ///
    /// This is a short system message added at the end of the conversation
    /// to remind the LLM about the required response format.
    pub fn build_format_reminder() -> String {
        r#"**REMINDER:** Respond with valid JSON only: `{"actions": [{"type": "...", ...}]}`"#
            .to_string()
    }

    /// Filter actions based on scripting mode
    pub(crate) fn filter_actions_by_scripting_mode(
        actions: Vec<ActionDefinition>,
        has_scripting: bool,
    ) -> Vec<ActionDefinition> {
        if has_scripting {
            actions
        } else {
            // Remove script-related actions and parameters when LLM mode is selected
            actions
                .into_iter()
                .filter_map(|mut action| {
                    if action.name == "update_script" {
                        // Remove update_script action entirely when in LLM mode
                        None
                    } else if action.name == "open_server" {
                        // Remove script parameters from open_server
                        action.parameters.retain(|p| {
                            !matches!(
                                p.name.as_str(),
                                "script_language"
                                    | "script_path"
                                    | "script_inline"
                                    | "script_handles"
                            )
                        });
                        Some(action)
                    } else {
                        Some(action)
                    }
                })
                .collect()
        }
    }

    // ============================================================================
    // ACTION-BASED PROMPT SYSTEM
    // ============================================================================

    /// Build unified prompt with action system (SYSTEM PROMPT ONLY)
    ///
    /// This builds the SYSTEM prompt only. The trigger/event should be provided
    /// as a separate USER message by the caller.
    ///
    /// # Arguments
    /// * `state` - Application state for context
    /// * `server_id` - Optional server ID for context
    /// * `instructions` - How to handle the situation
    /// * `available_actions` - List of actions the LLM can use
    /// * `include_base_stacks` - Whether to include full base stack documentation
    pub async fn build_action_prompt(
        state: &AppState,
        server_id: Option<ServerId>,
        instructions: &str,
        available_actions: Vec<ActionDefinition>,
        include_base_stacks: bool,
        conversation_history: Option<String>,
    ) -> String {
        // Get selected scripting mode
        let selected_mode = state.get_selected_scripting_mode().await;
        let has_scripting = selected_mode != crate::state::app_state::ScriptingMode::Off;

        // Filter actions based on scripting mode
        let filtered_actions =
            Self::filter_actions_by_scripting_mode(available_actions, has_scripting);

        // Try to use template first
        let template_name = if server_id.is_some() {
            "network_request/main"
        } else {
            "user_input/main"
        };

        // Prepare template data
        let servers = state.get_all_servers().await;
        let include_disabled = state.get_include_disabled_protocols().await;
        // The operator's --min-stability floor also shapes the model's base-stack
        // menu, so it is not guided toward a protocol it would be refused at start.
        let min_stability = state.get_min_stability().await;

        // Split actions into tools and regular actions and convert to JSON
        let (tool_actions_raw, regular_actions_raw): (Vec<_>, Vec<_>) =
            filtered_actions.iter().partition(|a| a.is_tool());

        // Convert actions to JSON for templates
        let tool_actions: Vec<serde_json::Value> = tool_actions_raw
            .iter()
            .map(|a| {
                let mut params_map = serde_json::Map::new();
                for param in &a.parameters {
                    params_map.insert(
                        param.name.clone(),
                        serde_json::json!({
                            "type": param.type_hint,
                            "description": param.description,
                            "required": param.required
                        }),
                    );
                }

                serde_json::json!({
                    "name": a.name,
                    "description": a.description,
                    "is_tool": a.is_tool(),
                    "parameters": params_map,
                    "example": a.example.to_string()
                })
            })
            .collect();

        let regular_actions: Vec<serde_json::Value> = regular_actions_raw
            .iter()
            .map(|a| {
                let mut params_map = serde_json::Map::new();
                for param in &a.parameters {
                    params_map.insert(
                        param.name.clone(),
                        serde_json::json!({
                            "type": param.type_hint,
                            "description": param.description,
                            "required": param.required
                        }),
                    );
                }

                serde_json::json!({
                    "name": a.name,
                    "description": a.description,
                    "is_tool": a.is_tool(),
                    "parameters": params_map,
                    "example": a.example.to_string()
                })
            })
            .collect();

        // Get system capabilities
        let system_caps = state.get_system_capabilities().await;

        // Convert servers to simple objects for templates
        let servers_data: Vec<serde_json::Value> = servers
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id.as_u32(),
                    "protocol_name": s.protocol_name,
                    "port": s.port,
                    "status": s.status.to_string(),
                    "memory": s.memory
                })
            })
            .collect();

        let active_server_data = server_id.and_then(|id| {
            servers.iter().find(|s| s.id == id).map(|s| {
                serde_json::json!({
                    "id": s.id.as_u32(),
                    "protocol_name": s.protocol_name,
                    "port": s.port,
                    "status": s.status.to_string(),
                    "memory": s.memory,
                    "instruction": s.instruction
                })
            })
        });

        // Build template data
        let web_search_mode = state.get_web_search_mode().await;
        let web_search_enabled = web_search_mode != crate::state::app_state::WebSearchMode::Off;

        let data = TemplateDataBuilder::new()
            .field("conversation_history", &conversation_history)
            .field("instructions", instructions)
            .field("tool_actions", &tool_actions)
            .field("regular_actions", &regular_actions)
            .field("include_base_stacks", include_base_stacks)
            .field("include_disabled_protocols", include_disabled)
            .field("scripting_enabled", has_scripting)
            .field("selected_scripting_mode", selected_mode.as_str())
            .field(
                "event_handler_mode",
                state.get_event_handler_mode().await.as_str(),
            )
            .field("mode", state.get_mode().await.as_str())
            .field("servers", &servers_data)
            .optional_field("active_server", active_server_data)
            .field("web_search_enabled", web_search_enabled)
            .field(
                "tool_examples",
                if web_search_enabled {
                    "`read_file` and `web_search`"
                } else {
                    "`read_file`"
                },
            )
            .field(
                "base_stack_docs",
                Self::build_base_stack_docs_section(include_disabled, min_stability),
            )
            .field(
                "current_state",
                Self::build_current_state_section(state, server_id).await,
            )
            .field("scripting_environment", selected_mode.as_str())
            .field(
                "can_bind_privileged_ports",
                system_caps.can_bind_privileged_ports,
            )
            .field("has_raw_socket_access", system_caps.has_raw_socket_access)
            .build();

        // Render template
        let result = TEMPLATE_ENGINE
            .render_json(template_name, &data)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to render template {}: {}", template_name, e);
                format!("# Error\n\nFailed to render prompt template: {}", e)
            });

        // Debug: log template rendering result
        tracing::debug!(
            "Rendered template '{}': {} chars",
            template_name,
            result.len()
        );
        if result.is_empty() {
            tracing::warn!("Template '{}' rendered to empty string!", template_name);
        }

        result
    }

    /// Build system prompt for user input using new action system
    ///
    /// This builds the SYSTEM prompt only (without the user input trigger).
    /// The caller should add the user input as a separate user message.
    ///
    /// By default, `open_server` and `open_client` are DISABLED. They become enabled
    /// only after `read_documentation` tool is called.
    /// Use `build_user_input_system_prompt_with_docs` to explicitly enable them.
    ///
    /// # Arguments
    /// * `state` - Application state
    /// * `protocol_async_actions` - Optional async actions from active protocol
    /// * `conversation_history` - Optional conversation history
    pub async fn build_user_input_system_prompt(
        state: &AppState,
        protocol_async_actions: Vec<ActionDefinition>,
        conversation_history: Option<String>,
    ) -> String {
        // By default, open_server and open_client are DISABLED
        // Use build_user_input_system_prompt_with_docs to enable them after docs are read
        Self::build_user_input_system_prompt_with_docs(
            state,
            protocol_async_actions,
            conversation_history,
            false, // is_open_server_enabled
            false, // is_open_client_enabled
        )
        .await
    }

    /// Build system prompt for user input with explicit open_server/open_client enablement
    ///
    /// This variant allows explicitly controlling whether open_server/open_client are enabled.
    /// Used by ConversationHandler after documentation tools have been called.
    ///
    /// # Arguments
    /// * `state` - Application state
    /// * `protocol_async_actions` - Optional async actions from active protocol
    /// * `conversation_history` - Optional conversation history
    /// * `is_open_server_enabled` - Whether open_server action is enabled
    /// * `is_open_client_enabled` - Whether open_client action is enabled
    pub async fn build_user_input_system_prompt_with_docs(
        state: &AppState,
        protocol_async_actions: Vec<ActionDefinition>,
        conversation_history: Option<String>,
        is_open_server_enabled: bool,
        is_open_client_enabled: bool,
    ) -> String {
        let selected_mode = state.get_selected_scripting_mode().await;
        let scripting_env = state.get_scripting_env().await;

        // Check if documentation has been fetched (for prompt guidance, not action enablement)
        let has_documentation = conversation_history
            .as_ref()
            .map(|history| {
                history.contains("read_documentation")
                    || history.contains("read_server_documentation")
                    || history.contains("read_client_documentation")
                    || history.contains("Server Protocol:")
                    || history.contains("Client Protocol:")
            })
            .unwrap_or(false);

        let has_running_servers = !state.get_all_servers().await.is_empty();

        let mut actions = get_user_input_common_actions(
            selected_mode,
            &scripting_env,
            is_open_server_enabled,
            is_open_client_enabled,
        );

        // Add tool actions
        let web_search_mode = state.get_web_search_mode().await;
        actions.extend(get_all_tool_actions(web_search_mode));

        // Add protocol async actions
        actions.extend(protocol_async_actions);

        let web_search_available = web_search_mode != crate::state::app_state::WebSearchMode::Off;
        let tool_examples = if web_search_available {
            "`read_file` and `web_search`"
        } else {
            "`read_file`"
        };
        let instructions = if is_open_server_enabled || is_open_client_enabled {
            format!(
                r#"## Your Mission

Understand what the user wants and respond with the appropriate actions to make it happen.

### Important Guidelines

1. **Use built-in protocols**: When users ask to start servers, use the `open_server` action with the appropriate `base_stack` (e.g., `http`, `ssh`, `dns`, `s3`). NetGet has 50+ protocols built-in - leverage them!

2. **Gather information first**: Use tools like {} to read files or search for information before taking action.

3. **Update, don't recreate**: If a user asks to modify an existing server (e.g., "add an endpoint", "change the behavior"), use `update_instruction` - don't create a new server on the same port.

4. **JSON responses only**: Your entire response must be valid JSON: `{{"actions": [...]}}`
            "#,
                tool_examples
            )
        } else {
            format!(
                r#"## Your Mission

Understand what the user wants and respond with the appropriate actions to make it happen.

### Important Guidelines

1. **Read documentation first**: Before starting servers or clients, you MUST call `read_documentation` with the protocol(s) you need. This enables the server/client actions and explains when to use each mode.

2. **Understanding Server vs Client** (CRITICAL):
   - **Server (hosting)**: Use when user wants to HOST/SERVE content
     - Keywords: "serve", "host", "listen", "provide", "run server"
     - Example: "host a website", "start HTTP server", "run DNS server"
   - **Client (connecting)**: Use when user wants to CONNECT to existing remote server
     - Keywords: "connect to", "fetch from", "query", "send to", "access remote"
     - Example: "connect to Redis at localhost:6379", "send ping to host"
   - ⚠️ If user says "serve", "host", or "provide", use server mode even if they say "client". The ACTION matters more than the word choice!

3. **Gather information**: Use tools like {} to read files or search for information before taking action.

4. **Update, don't recreate**: If a user asks to modify an existing server (e.g., "add an endpoint", "change the behavior"), use `update_instruction` - don't create a new server on the same port.

5. **JSON responses only**: Your entire response must be valid JSON: `{{"actions": [...]}}`

**IMPORTANT**: The server and client actions are DISABLED until you read protocol documentation. Use `read_documentation` first!
            "#,
                tool_examples
            )
        };

        // Build prompt with conditional base stack docs
        // Only show full base stack docs after documentation has been fetched or explicitly enabled
        // Also check if protocols have been documented in AppState
        let has_documented_protocols =
            state.is_server_docs_read().await || state.is_client_docs_read().await;
        let include_base_stacks = has_documentation
            || has_running_servers
            || has_documented_protocols
            || is_open_server_enabled
            || is_open_client_enabled;

        Self::build_action_prompt(
            state,
            None,
            &instructions,
            actions,
            include_base_stacks,
            conversation_history,
        )
        .await
    }

    /// Build system prompt for feedback processing
    ///
    /// This builds the SYSTEM prompt for processing accumulated feedback.
    /// The prompt includes feedback instructions, current instance state, and available adjustment actions.
    ///
    /// # Arguments
    /// * `state` - Application state
    /// * `server_id` - Server ID if processing server feedback
    /// * `client_id` - Client ID if processing client feedback
    /// * `feedback_instructions` - Instructions for how to process feedback
    /// * `current_instruction` - Current instruction of the instance
    /// * `memory` - Current memory of the instance
    /// * `feedback_entries` - Accumulated feedback entries
    /// * `available_actions` - The adjustments on offer: `feedback::get_feedback_actions`,
    ///   the same list the answer is validated against and executed by
    #[allow(clippy::too_many_arguments)]
    pub async fn build_feedback_system_prompt(
        state: &AppState,
        server_id: Option<ServerId>,
        client_id: Option<crate::state::ClientId>,
        feedback_instructions: &str,
        current_instruction: &str,
        memory: &str,
        feedback_entries: &[serde_json::Value],
        available_actions: Vec<ActionDefinition>,
    ) -> String {
        use crate::llm::feedback::{feedback_instance_view, FeedbackTarget};

        // The list is advertised as given: it is the same list the response is validated
        // against (`feedback::get_feedback_actions`), so filtering it here would make the
        // two disagree.
        let action_json = |a: &ActionDefinition| {
            let mut params_map = serde_json::Map::new();
            for param in &a.parameters {
                params_map.insert(
                    param.name.clone(),
                    serde_json::json!({
                        "type": param.type_hint,
                        "description": param.description,
                        "required": param.required
                    }),
                );
            }
            serde_json::json!({
                "name": a.name,
                "description": a.description,
                "is_tool": a.is_tool(),
                "parameters": params_map,
                "example": a.example.to_string()
            })
        };
        let (tool_actions_raw, regular_actions_raw): (Vec<_>, Vec<_>) =
            available_actions.iter().partition(|a| a.is_tool());
        let tool_actions: Vec<serde_json::Value> =
            tool_actions_raw.into_iter().map(action_json).collect();
        let regular_actions: Vec<serde_json::Value> =
            regular_actions_raw.into_iter().map(action_json).collect();
        let action_names: Vec<&str> = available_actions.iter().map(|a| a.name.as_str()).collect();

        let target = FeedbackTarget::from_ids(server_id, client_id);
        let instance = feedback_instance_view(state, target, current_instruction, memory).await;

        let feedback_strings: Vec<String> = feedback_entries
            .iter()
            .map(|entry| serde_json::to_string_pretty(entry).unwrap_or_else(|_| entry.to_string()))
            .collect();

        let data = TemplateDataBuilder::new()
            .field(
                "instance_type",
                target.map(|t| t.kind()).unwrap_or("instance"),
            )
            .field("instance_id", target.map(|t| t.id()))
            .field("instance", &instance)
            .field("feedback_instructions", feedback_instructions)
            .field("feedback_count", feedback_entries.len())
            .field("feedback_entries", &feedback_strings)
            .field("tool_actions", &tool_actions)
            .field("regular_actions", &regular_actions)
            .field("action_names", action_names.join(", "))
            .build();

        TEMPLATE_ENGINE
            .render_json("feedback/main", &data)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to render feedback template: {}", e);
                format!(
                    "# Error\n\nFailed to render feedback prompt template: {}",
                    e
                )
            })
    }

    /// Convert a prompt string to conversation messages
    ///
    /// Splits a prompt into system and user messages suitable for conversation-based API.
    /// The prompt is expected to have a system instruction part and a user input part.
    ///
    /// For simplicity, this treats the entire prompt as a system message initially.
    /// TODO: Parse prompts better to separate system vs user content.
    pub fn prompt_to_messages(prompt: String) -> Vec<Message> {
        // For now, treat the whole prompt as system message
        // This is a transitional approach while we migrate to conversation-based prompts
        vec![Message::system(prompt)]
    }

    /// Build prompt for network events using new action system (SYSTEM PROMPT ONLY)
    ///
    /// This builds the SYSTEM prompt only for a network event. The caller should provide
    /// the event description and context as a separate USER message.
    ///
    /// # Arguments
    /// * `state` - Application state
    /// * `server_id` - ID of the server handling this event
    /// * `all_actions` - All actions (common + protocol + custom, pre-assembled)
    pub async fn build_network_event_action_prompt_for_server(
        state: &AppState,
        server_id: ServerId,
        all_actions: Vec<ActionDefinition>,
    ) -> String {
        Self::build_network_event_action_prompt_for_server_with_actions(
            state,
            server_id,
            all_actions,
        )
        .await
        .0
    }

    /// The exact list of actions a network-event prompt advertises, given the assembled list.
    ///
    /// Two adjustments separate what a caller assembles from what the model is actually
    /// offered:
    ///
    /// * tools are removed: a network event asks for its immediate response actions;
    /// * [`Self::filter_actions_by_scripting_mode`] removes `update_script` and the
    ///   script parameters of `open_server` when scripting is Off.
    ///
    /// A caller that validates the model's response against its own pre-adjustment list
    /// therefore accepts actions that were never advertised (`update_script` with scripting
    /// Off) and offers native tool schemas that omit ones that were. Validate against this.
    pub async fn advertised_network_event_actions(
        state: &AppState,
        mut all_actions: Vec<ActionDefinition>,
    ) -> Vec<ActionDefinition> {
        all_actions.retain(|action| !action.is_tool());

        let selected_mode = state.get_selected_scripting_mode().await;
        let has_scripting = selected_mode != crate::state::app_state::ScriptingMode::Off;
        Self::filter_actions_by_scripting_mode(all_actions, has_scripting)
    }

    /// The exact list of actions a **user-input** prompt advertises, given the assembled list.
    ///
    /// The sibling of [`Self::advertised_network_event_actions`], and it exists for the same
    /// reason: `build_user_input_system_prompt_with_docs` renders
    /// [`Self::filter_actions_by_scripting_mode`]'s output, so a caller that hands its own
    /// pre-filter list to `with_native_tools` — or validates the model's reply against it —
    /// offers and accepts actions the prompt never showed. With scripting Off that means
    /// advertising `open_server`'s script parameters in the tool schema while the prose says
    /// they do not exist.
    ///
    /// Permissive rather than broken, but it is the same divergence that made the feedback
    /// loop unable to succeed, so it is worth closing at the source instead of per call site.
    pub async fn advertised_user_input_actions(
        state: &AppState,
        all_actions: Vec<ActionDefinition>,
    ) -> Vec<ActionDefinition> {
        let selected_mode = state.get_selected_scripting_mode().await;
        let has_scripting = selected_mode != crate::state::app_state::ScriptingMode::Off;
        Self::filter_actions_by_scripting_mode(all_actions, has_scripting)
    }

    /// Build a network-event system prompt and return the actions it advertises.
    ///
    /// The second element is what the caller must validate the model's response against and
    /// what it must hand to `with_native_tools` — see
    /// [`Self::advertised_network_event_actions`].
    pub async fn build_network_event_action_prompt_for_server_with_actions(
        state: &AppState,
        server_id: ServerId,
        all_actions: Vec<ActionDefinition>,
    ) -> (String, Vec<ActionDefinition>) {
        // Remove tools and script actions the current scripting mode does not allow.
        // The caller validates against this same list.
        let advertised = Self::advertised_network_event_actions(state, all_actions).await;

        // Note: all_actions already contains common + protocol + custom actions
        // They are pre-assembled by the action_helper, so we don't add common actions here
        let instruction = state.get_instruction(server_id).await.unwrap_or_default();
        let instructions_str = if instruction.is_empty() {
            "Respond to the request with the available actions.".to_string()
        } else {
            instruction
        };

        // Network events don't need base stack docs (server already running, handling specific event)
        // Network events don't use conversation history
        //
        // `build_action_prompt` re-applies the scripting-mode filter; it is idempotent, so the
        // rendered list is exactly `advertised`.
        let prompt = Self::build_action_prompt(
            state,
            Some(server_id),
            &instructions_str,
            advertised.clone(),
            false,
            None,
        )
        .await;

        (prompt, advertised)
    }

    /// Build event trigger message for network events
    ///
    /// This builds the USER message containing the event description and context.
    /// Should be used with build_network_event_action_prompt_for_server.
    ///
    /// # Arguments
    /// * `event_description` - Description of the network event
    /// * `context_json` - Structured context data (protocol-specific parameters)
    pub fn build_event_trigger_message(
        event_description: &str,
        context_json: serde_json::Value,
    ) -> String {
        if context_json.is_null() || context_json == serde_json::json!({}) {
            format!("Event: {}", event_description)
        } else {
            format!(
                "Event: {}\n\nContext data:\n{}",
                event_description,
                serde_json::to_string_pretty(&context_json)
                    .unwrap_or_else(|_| context_json.to_string())
            )
        }
    }

    /// Build event trigger message with event ID (for mock testing compatibility)
    ///
    /// # Arguments
    /// * `event_id` - Event type ID (e.g., "bootp_request")
    /// * `event_description` - Description of the network event
    /// * `context_json` - Structured context data (protocol-specific parameters)
    pub fn build_event_trigger_message_with_id(
        event_id: &str,
        event_description: &str,
        context_json: serde_json::Value,
    ) -> String {
        // A heading of its own: the trigger used to run straight on from the System
        // Capabilities list at the end of the system prompt. `Event ID:` and `Context data:`
        // stay as the labels; the test mock finds the current event by them.
        if context_json.is_null() || context_json == serde_json::json!({}) {
            format!(
                "# Event to answer\nEvent ID: {}\nEvent: {}",
                event_id, event_description
            )
        } else {
            format!(
                "# Event to answer\nEvent ID: {}\nEvent: {}\nContext data:\n{}",
                event_id,
                event_description,
                serde_json::to_string_pretty(&context_json)
                    .unwrap_or_else(|_| context_json.to_string())
            )
        }
    }

    /// The actions a scheduled task may use, and how each one is executed.
    ///
    /// Computed once per firing and used for both halves of the run: the prompt advertises
    /// exactly `actions`, the conversation validates against exactly `actions`, and
    /// `src/cli/tasks.rs` routes each returned action by the names recorded here. A scope
    /// is offered only what its executor can actually carry out:
    ///
    /// - **Global**: the operator's management vocabulary (open/close/update servers and
    ///   clients, schedule/cancel tasks, databases, `show_message`) plus every tool. Not
    ///   `set_memory`, `append_memory`, `append_to_log` or `update_instruction`: with no
    ///   instance in scope those fall through to "the first server", an arbitrary target.
    /// - **Server #N**: memory, `show_message`, `append_to_log`, and — when at least one live
    ///   connection registered a peer handle — the protocol's actions, each with a required
    ///   `connection_id` naming which connection runs it.
    /// - **Connection conn-M on server #N**: the same, aimed at that connection.
    /// - **Client #N**: memory, `show_message`, and the client's protocol actions when its
    ///   loop accepts injected commands. Not `append_to_log`, which writes to a server log.
    ///
    /// Protocol actions are executed *inside* the instance (`AppState::send_to_peer` /
    /// `send_to_client`), because a protocol action executed anywhere else produces bytes
    /// nobody writes.
    pub async fn task_action_set(
        state: &AppState,
        task: &crate::state::ScheduledTask,
    ) -> TaskActionSet {
        use crate::llm::actions::get_network_event_common_actions;
        use crate::state::task::TaskScope;

        let selected_mode = state.get_selected_scripting_mode().await;
        let web_search_mode = state.get_web_search_mode().await;

        let mut set = TaskActionSet::default();
        let mut actions: Vec<ActionDefinition>;

        match &task.scope {
            TaskScope::Global => {
                let scripting_env = state.get_scripting_env().await;
                actions = get_user_input_common_actions(selected_mode, &scripting_env, true, true);
                actions.retain(|a| !GLOBAL_TASK_UNTARGETED_ACTIONS.contains(&a.name.as_str()));
                actions.extend(get_all_tool_actions(web_search_mode));
            }
            TaskScope::Server(sid) => {
                actions = get_network_event_common_actions();
                let peers = Self::task_peer_connections(state, *sid, None).await;
                match Self::task_peer_vocabulary(state, *sid).await {
                    Err(reason) => set.protocol_unavailable = Some(reason),
                    Ok(_) if peers.is_empty() => {
                        set.protocol_unavailable = Some(
                            "no live connection of this server accepts injected actions right now"
                                .to_string(),
                        )
                    }
                    Ok(vocabulary) => {
                        for mut action in vocabulary {
                            if !action.parameters.iter().any(|p| p.name == "connection_id") {
                                set.routing_only_connection_id.insert(action.name.clone());
                            }
                            action.parameters.retain(|p| p.name != "connection_id");
                            action.parameters.insert(
                                0,
                                crate::llm::actions::Parameter {
                                    name: "connection_id".to_string(),
                                    type_hint: "number".to_string(),
                                    description: format!(
                                        "Which connection runs this action: one of {}",
                                        peers
                                            .iter()
                                            .map(|c| c.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ),
                                    required: true,
                                },
                            );
                            if let Some(obj) = action.example.as_object_mut() {
                                obj.insert(
                                    "connection_id".to_string(),
                                    serde_json::json!(peers[0]),
                                );
                            }
                            set.protocol_actions.insert(action.name.clone());
                            actions.push(action);
                        }
                        set.peer_connections = peers;
                    }
                }
                actions.extend(get_network_event_tool_actions(web_search_mode));
            }
            TaskScope::Connection(sid, cid) => {
                actions = get_network_event_common_actions();
                let peers = Self::task_peer_connections(state, *sid, Some(cid.as_u32())).await;
                match Self::task_peer_vocabulary(state, *sid).await {
                    Err(reason) => set.protocol_unavailable = Some(reason),
                    Ok(_) if peers.is_empty() => {
                        set.protocol_unavailable = Some(format!(
                            "connection {} does not accept injected actions (it is closed, or \
                             its protocol registers no peer handle)",
                            cid
                        ))
                    }
                    Ok(vocabulary) => {
                        for action in vocabulary {
                            set.protocol_actions.insert(action.name.clone());
                            actions.push(action);
                        }
                        set.peer_connections = peers;
                    }
                }
                actions.extend(get_network_event_tool_actions(web_search_mode));
            }
            TaskScope::Client(cid) => {
                actions = get_network_event_common_actions();
                actions.retain(|a| a.name != "append_to_log");
                let protocol = match state.get_protocol_name_for_client(*cid).await {
                    Some(name) => crate::protocol::client_registry::CLIENT_REGISTRY.get(&name),
                    None => None,
                };
                match protocol {
                    None => {
                        set.protocol_unavailable =
                            Some("the client or its protocol no longer exists".to_string())
                    }
                    Some(_) if !state.has_client_handle(*cid).await => {
                        set.protocol_unavailable = Some(
                            "the client is not connected, or its protocol does not accept \
                             injected actions"
                                .to_string(),
                        )
                    }
                    Some(protocol) => {
                        // Clients union; servers narrow — `client_llm_action_set` is the one
                        // place that rule lives, and `send_to_client` executes any of it.
                        for action in crate::llm::actions::client_trait::client_llm_action_set(
                            protocol.as_ref(),
                            state,
                            None,
                        ) {
                            set.protocol_actions.insert(action.name.clone());
                            actions.push(action);
                        }
                    }
                }
                actions.extend(get_network_event_tool_actions(web_search_mode));
            }
        }

        // A protocol action that shares a common action's name would be ambiguous to route;
        // the first definition wins, as it does for the model's tool schema.
        let mut seen = std::collections::BTreeSet::new();
        actions.retain(|a| seen.insert(a.name.clone()));

        let has_scripting = selected_mode != crate::state::app_state::ScriptingMode::Off;
        set.actions = Self::filter_actions_by_scripting_mode(actions, has_scripting);
        set
    }

    /// The server protocol's peer vocabulary (sync ∪ async), or why it has none.
    async fn task_peer_vocabulary(
        state: &AppState,
        server_id: ServerId,
    ) -> Result<Vec<ActionDefinition>, String> {
        let protocol_name = state
            .get_protocol_name(server_id)
            .await
            .ok_or_else(|| "the server no longer exists".to_string())?;
        let registry = crate::protocol::server_registry::registry();
        if let Some(reason) = registry.request_only_reason(&protocol_name) {
            return Err(format!(
                "{} speaks only in answer to a request: {}",
                protocol_name, reason
            ));
        }
        let protocol = registry
            .resolve(&protocol_name)
            .map_err(|e| e.to_string())?;
        let mut actions = protocol.get_sync_actions();
        for action in protocol.get_async_actions(state) {
            if !actions.iter().any(|a| a.name == action.name) {
                actions.push(action);
            }
        }
        Ok(actions)
    }

    /// Live connections of a server that accept injected actions, ascending; restricted to
    /// `only` when given.
    async fn task_peer_connections(
        state: &AppState,
        server_id: ServerId,
        only: Option<u32>,
    ) -> Vec<u32> {
        let Some(server) = state.get_server(server_id).await else {
            return Vec::new();
        };
        let mut ids: Vec<u32> = server
            .connections
            .iter()
            .filter(|(_, c)| c.status == crate::state::server::ConnectionStatus::Active)
            .map(|(id, _)| id.as_u32())
            .filter(|id| only.is_none_or(|o| o == *id))
            .collect();
        ids.sort_unstable();
        let mut live = Vec::with_capacity(ids.len());
        for id in ids {
            if state.has_peer_handle(server_id, id).await {
                live.push(id);
            }
        }
        live
    }

    /// Build prompt for scheduled task execution.
    ///
    /// Renders `scheduled_task/main`, whose preamble says what actually happened — a timer
    /// fired; there is no network event to answer and no user to talk to — and states the
    /// task's scope and that instance's state. `set` is [`Self::task_action_set`] for this
    /// task, computed once by the caller: the prompt advertises exactly `set.actions`, which
    /// is also what the conversation validates against.
    ///
    /// The prompt ends with `\n\nTrigger: Scheduled task '<name>' …`, which the test mock
    /// (`tests/helpers/mock_ollama.rs`) uses to recognise a task call.
    pub async fn build_task_execution_prompt(
        state: &crate::state::AppState,
        task: &crate::state::ScheduledTask,
        set: &TaskActionSet,
    ) -> String {
        use crate::state::task::{TaskScope, TaskType};

        let actions = &set.actions;
        let offered: std::collections::BTreeSet<&str> =
            actions.iter().map(|a| a.name.as_str()).collect();

        let created_ago = crate::state::task::format_duration(task.created_at.elapsed());
        let schedule = match &task.task_type {
            TaskType::OneShot { delay_secs } => format!("one-shot, {}s after creation", delay_secs),
            TaskType::Recurring {
                interval_secs,
                max_executions,
                executions_count,
            } => match max_executions {
                Some(max) => format!(
                    "recurring every {}s, run {} of at most {}",
                    interval_secs,
                    executions_count.saturating_add(1),
                    max
                ),
                None => format!(
                    "recurring every {}s, run {}",
                    interval_secs,
                    executions_count.saturating_add(1)
                ),
            },
        };

        let scope_label: String;
        let mut scope_lines: Vec<String> = Vec::new();
        let mut instance_instruction = String::new();
        let mut memory = String::new();
        let mut history: Option<String> = None;
        let mut trigger_target = String::new();

        match &task.scope {
            TaskScope::Global => {
                scope_label = "global — not tied to any server, connection or client".to_string();
                let servers = state.get_all_servers().await;
                if servers.is_empty() {
                    scope_lines.push("No servers are running.".to_string());
                } else {
                    scope_lines.push("Servers:".to_string());
                    for s in &servers {
                        scope_lines.push(format!(
                            "- Server #{}: {} on port {} ({})",
                            s.id.as_u32(),
                            s.protocol_name,
                            s.port,
                            s.status
                        ));
                    }
                }
                let clients = state.get_all_clients().await;
                if clients.is_empty() {
                    scope_lines.push("No clients are running.".to_string());
                } else {
                    scope_lines.push("Clients:".to_string());
                    for c in &clients {
                        scope_lines.push(format!(
                            "- Client #{}: {} to {} ({})",
                            c.id.as_u32(),
                            c.protocol_name,
                            c.remote_addr,
                            c.status
                        ));
                    }
                }
            }
            TaskScope::Server(sid) | TaskScope::Connection(sid, _) => {
                let server = state.get_server(*sid).await;
                match &task.scope {
                    TaskScope::Connection(_, cid) => {
                        scope_label = format!("connection {} on server #{}", cid, sid.as_u32());
                        trigger_target =
                            format!(" for connection {} on server #{}", cid, sid.as_u32());
                    }
                    _ => {
                        scope_label = format!("server #{}", sid.as_u32());
                        trigger_target = format!(" on server #{}", sid.as_u32());
                    }
                }
                match &server {
                    None => scope_lines.push(format!("Server #{} no longer exists.", sid.as_u32())),
                    Some(server) => {
                        scope_lines.push(format!(
                            "- Server #{}: {} on port {} ({})",
                            server.id.as_u32(),
                            server.protocol_name,
                            server.port,
                            server.status
                        ));
                        instance_instruction = server.instruction.clone();
                        memory = server.memory.clone();
                        if let TaskScope::Connection(_, cid) = &task.scope {
                            match server.connections.get(cid) {
                                None => scope_lines
                                    .push(format!("- Connection {}: no longer exists", cid)),
                                Some(conn) => scope_lines.push(format!(
                                    "- Connection {}: {} → {}, {:?}, {} bytes sent / {} received, \
                                     last activity {} ago",
                                    cid,
                                    conn.remote_addr,
                                    conn.local_addr,
                                    conn.status,
                                    conn.bytes_sent,
                                    conn.bytes_received,
                                    crate::state::task::format_duration(
                                        conn.last_activity.elapsed()
                                    )
                                )),
                            }
                            history = state.render_server_history(*sid, Some(*cid)).await;
                        } else {
                            let live = server
                                .connections
                                .values()
                                .filter(|c| {
                                    c.status == crate::state::server::ConnectionStatus::Active
                                })
                                .count();
                            scope_lines.push(format!("- Live connections: {}", live));
                        }
                    }
                }
            }
            TaskScope::Client(cid) => {
                scope_label = format!("client #{}", cid.as_u32());
                trigger_target = format!(" for client #{}", cid.as_u32());
                match state.get_client(*cid).await {
                    None => scope_lines.push(format!("Client #{} no longer exists.", cid.as_u32())),
                    Some(client) => {
                        scope_lines.push(format!(
                            "- Client #{}: {} to {} ({})",
                            client.id.as_u32(),
                            client.protocol_name,
                            client.remote_addr,
                            client.status
                        ));
                        instance_instruction = client.instruction.clone();
                        memory = client.memory.clone();
                        history = state.render_client_history(*cid).await;
                    }
                }
            }
        }

        // How the protocol actions reach the wire — or why there are none.
        let protocol_note = if !matches!(task.scope, TaskScope::Global) {
            if let Some(reason) = &set.protocol_unavailable {
                Some(format!(
                    "No protocol actions are offered: {}. Only the actions listed below can be used.",
                    reason
                ))
            } else {
                match &task.scope {
                    TaskScope::Server(_) => Some(format!(
                        "Protocol actions run inside one live connection; name it in \
                         `connection_id` (connections accepting actions: {}).",
                        set.peer_connections
                            .iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    TaskScope::Connection(_, cid) => Some(format!(
                        "Protocol actions run inside connection {} and go to its peer.",
                        cid
                    )),
                    TaskScope::Client(_) => Some(
                        "Protocol actions run inside the client's connection and go to the \
                         server it is connected to."
                            .to_string(),
                    ),
                    TaskScope::Global => None,
                }
            }
        } else {
            None
        };

        let (tool_actions, regular_actions): (Vec<_>, Vec<_>) =
            actions.iter().partition(|a| a.is_tool());
        let tool_actions: Vec<serde_json::Value> = tool_actions
            .iter()
            .map(|a| Self::task_action_json(a))
            .collect();
        let regular_actions: Vec<serde_json::Value> = regular_actions
            .iter()
            .map(|a| Self::task_action_json(a))
            .collect();

        // The Required Format example must be an action this task is actually offered:
        // a protocol action if there is one, else show_message, else the first offered.
        let example_action = actions
            .iter()
            .filter(|a| !a.is_tool())
            .find(|a| set.protocol_actions.contains(&a.name))
            .or_else(|| actions.iter().find(|a| a.name == "show_message"))
            .or_else(|| actions.iter().find(|a| !a.is_tool()))
            .map(|a| a.example.to_string())
            .unwrap_or_else(|| "{\"type\": \"show_message\", \"message\": \"done\"}".to_string());
        let example_tool = actions
            .iter()
            .find(|a| a.is_tool())
            .map(|a| a.example.to_string());

        let system_caps = state.get_system_capabilities().await;
        let data = TemplateDataBuilder::new()
            .field("task_name", &task.name)
            .field("schedule", &schedule)
            .field("created_ago", &created_ago)
            .field("scope_label", &scope_label)
            .field("scope_lines", scope_lines.join("\n"))
            .field("instruction", &task.instruction)
            .field("previous_error", &task.last_error)
            .field(
                "task_context",
                task.context
                    .as_ref()
                    .map(|c| serde_json::to_string_pretty(c).unwrap_or_else(|_| c.to_string())),
            )
            .field("instance_instruction", &instance_instruction)
            .field("memory", &memory)
            .field("memory_actions", offered.contains("set_memory"))
            .field("history", &history)
            .field("protocol_note", &protocol_note)
            .field("tool_actions", &tool_actions)
            .field("regular_actions", &regular_actions)
            .field("example_action", &example_action)
            .field("example_tool", &example_tool)
            .field("is_global", matches!(task.scope, TaskScope::Global))
            .field(
                "can_bind_privileged_ports",
                system_caps.can_bind_privileged_ports,
            )
            .field("has_raw_socket_access", system_caps.has_raw_socket_access)
            .build();

        let system_prompt = TEMPLATE_ENGINE
            .render_json("scheduled_task/main", &data)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to render template scheduled_task/main: {}", e);
                format!("# Error\n\nFailed to render prompt template: {}", e)
            });

        format!(
            "{}\n\nTrigger: Scheduled task '{}' fired{} (created {} ago)",
            system_prompt.trim_end(),
            task.name,
            trigger_target,
            created_ago
        )
    }

    /// One action as the `shared/partials/actions` partial renders it.
    fn task_action_json(a: &ActionDefinition) -> serde_json::Value {
        let mut params_map = serde_json::Map::new();
        for param in &a.parameters {
            params_map.insert(
                param.name.clone(),
                serde_json::json!({
                    "type": param.type_hint,
                    "description": param.description,
                    "required": param.required
                }),
            );
        }
        serde_json::json!({
            "name": a.name,
            "description": a.description,
            "is_tool": a.is_tool(),
            "parameters": params_map,
            "example": a.example.to_string()
        })
    }

    // ========================================================================
}

/// Operator actions a global task is not offered: with no instance in scope each of them
/// falls through to "the first server", which is an arbitrary target rather than a choice.
const GLOBAL_TASK_UNTARGETED_ACTIONS: &[&str] = &[
    "set_memory",
    "append_memory",
    "append_to_log",
    "update_instruction",
];

/// What a scheduled task may do this firing — see [`PromptBuilder::task_action_set`].
#[derive(Debug, Default, Clone)]
pub struct TaskActionSet {
    /// Every action offered (common, protocol and tools), scripting-filtered. The prompt
    /// advertises exactly these and the conversation validates against exactly these.
    pub actions: Vec<ActionDefinition>,
    /// Offered actions that belong to the instance's protocol. They execute inside the
    /// instance: `AppState::send_to_peer` for a server or connection, `send_to_client` for a
    /// client.
    pub protocol_actions: std::collections::BTreeSet<String>,
    /// Server or connection scope: the live connections that accept injected actions.
    pub peer_connections: Vec<u32>,
    /// Server scope: protocol actions whose `connection_id` exists only to route them, and is
    /// removed before the action is handed to the connection.
    pub routing_only_connection_id: std::collections::BTreeSet<String>,
    /// Why the instance's protocol actions are not offered, when they are not.
    pub protocol_unavailable: Option<String>,
}
