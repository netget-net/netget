//! Event handler - coordinates responses to events using LLM

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::info;

use super::errors::ActionExecutionError;
use super::types::{AppEvent, UserCommand};
use crate::cli::server_startup;
use crate::llm::actions::get_all_tool_actions;
use crate::llm::format_indented_dimmed_lines;
use crate::llm::OllamaClient;
use crate::llm::{execute_actions, CommonAction, Server};
use crate::state::app_state::{AppState, Mode};
use crate::ui::App;

/// Whether reading the protocol documentation is a precondition for
/// `open_server` / `open_client`.
///
/// This is the *only* switch for that policy. It governs both halves of it:
///
/// 1. whether the two actions are offered in the action list at all
///    (`is_open_server_enabled` / `is_open_client_enabled` below), and
/// 2. whether the first `open_server` / `open_client` of the process is answered
///    with `ActionExecutionError::DocumentationRequired` instead of being
///    executed (see `execute_server_management_action`).
///
/// The second half used to be unconditional, which cost a full extra model
/// round-trip on the first server or client opened by every process while
/// telling the model nothing it could not already ask for: the handler fetches
/// the documentation itself and marks the protocol documented *before* raising
/// the error, so falling through and starting the server loses no information.
/// It also meant every mocked test had to answer a retry it never asked for.
///
/// Note the gate is process-global, not per-protocol: `is_server_docs_read()`
/// returns `!documented_server_protocols.is_empty()`, so with the flag on it
/// fires once per process and then never again, whatever protocol comes next.
///
/// Deliberately still a `const` rather than a runtime setting: it selects
/// between two *prompting strategies*, not between two behaviours a user would
/// want to switch per run — there is no CLI flag, MCP argument or settings key
/// that would sensibly carry it, and promoting it would mean threading a new
/// field through `AppState` (and the prompt builder, which reads the docs state
/// separately) to expose a knob whose `true` side we have measured to be worse.
/// If it ever needs to vary at runtime, that is the moment to add it to
/// `Settings`, not before.
const REQUIRE_DOCS_FOR_OPEN_ACTIONS: bool = false;

/// Whether the operator prompt offers `open_server` and `open_client` right now.
///
/// Always both while [`REQUIRE_DOCS_FOR_OPEN_ACTIONS`] is off; with it on, each once its
/// side's documentation has been read. The prompt builder's default entry point asks this
/// too, so what a test renders is what an operator's turn renders.
pub async fn open_actions_enabled(state: &AppState) -> (bool, bool) {
    if REQUIRE_DOCS_FOR_OPEN_ACTIONS {
        (
            state.is_server_docs_read().await,
            state.is_client_docs_read().await,
        )
    } else {
        (true, true)
    }
}

/// Log detailed open_server action summary to the status channel
fn log_open_server_summary(
    status_tx: &mpsc::UnboundedSender<String>,
    mac_address: &Option<String>,
    interface: &Option<String>,
    host: &Option<String>,
    port: Option<u16>,
    protocol: &str,
    send_first: bool,
    initial_memory: &Option<String>,
    instruction: &str,
    startup_params: &Option<serde_json::Value>,
    event_handlers: &Option<Vec<serde_json::Value>>,
    scheduled_tasks: &Option<Vec<crate::llm::actions::common::ServerTaskDefinition>>,
    feedback_instructions: &Option<String>,
) {
    // Header
    let _ = status_tx.send("[INFO] ═══ open_server ═══".to_string());

    // Basic server configuration
    let _ = status_tx.send(format!("[INFO]   Protocol: {}", protocol));
    if let Some(p) = port {
        let _ = status_tx.send(format!("[INFO]   Port: {}", p));
    }
    if let Some(h) = host {
        let _ = status_tx.send(format!("[INFO]   Host: {}", h));
    }
    if let Some(i) = interface {
        let _ = status_tx.send(format!("[INFO]   Interface: {}", i));
    }
    if let Some(m) = mac_address {
        let _ = status_tx.send(format!("[INFO]   MAC Address: {}", m));
    }
    if send_first {
        let _ = status_tx.send("[INFO]   Send First: yes".to_string());
    }

    // Instruction (truncated if long)
    if !instruction.is_empty() {
        let truncated = crate::utils::truncate_for_log(instruction, 100);
        let _ = status_tx.send(format!("[INFO]   Instruction: {}", truncated));
    }

    // Initial memory (truncated if long)
    if let Some(mem) = initial_memory {
        if !mem.is_empty() {
            let truncated = crate::utils::truncate_for_log(mem, 100);
            let _ = status_tx.send(format!("[INFO]   Initial Memory: {}", truncated));
        }
    }

    // Startup params
    if let Some(params) = startup_params {
        if !params.is_null() {
            let shown = crate::utils::redact::redact_sensitive(params);
            let params_str =
                serde_json::to_string_pretty(&shown).unwrap_or_else(|_| shown.to_string());
            let _ = status_tx.send("[INFO]   Startup Params:".to_string());
            for line in format_indented_dimmed_lines(&params_str, 8) {
                let _ = status_tx.send(format!("[INFO] {}", line));
            }
        }
    }

    // Event handlers summary
    if let Some(handlers) = event_handlers {
        let _ = status_tx.send(format!(
            "[INFO]   Event Handlers: {} configured",
            handlers.len()
        ));
        for handler in handlers {
            let event_pattern = handler
                .get("event_pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("*");
            let handler_type = handler
                .get("handler")
                .and_then(|h| h.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            let _ = status_tx.send(format!("[INFO]     • {} → {}", event_pattern, handler_type));

            // For script handlers, show the script code (dimmed)
            if handler_type == "script" {
                if let Some(code) = handler
                    .get("handler")
                    .and_then(|h| h.get("code"))
                    .and_then(|c| c.as_str())
                {
                    let truncated = crate::utils::truncate_for_log(code, 200);
                    for line in format_indented_dimmed_lines(&truncated, 8) {
                        let _ = status_tx.send(format!("[INFO] {}", line));
                    }
                }
            }

            // For static handlers, show the actions (dimmed)
            if handler_type == "static" {
                if let Some(actions) = handler.get("handler").and_then(|h| h.get("actions")) {
                    let actions_str = serde_json::to_string_pretty(actions)
                        .unwrap_or_else(|_| actions.to_string());
                    let truncated = crate::utils::truncate_for_log(&actions_str, 300);
                    for line in format_indented_dimmed_lines(&truncated, 8) {
                        let _ = status_tx.send(format!("[INFO] {}", line));
                    }
                }
            }
        }
    }

    // Scheduled tasks summary
    if let Some(tasks) = scheduled_tasks {
        let _ = status_tx.send(format!(
            "[INFO]   Scheduled Tasks: {} configured",
            tasks.len()
        ));
        for task in tasks {
            let timing = if task.recurring {
                task.interval_secs
                    .map(|i| format!("every {}s", i))
                    .unwrap_or_else(|| "recurring".to_string())
            } else {
                task.delay_secs
                    .map(|d| format!("after {}s", d))
                    .unwrap_or_else(|| "one-shot".to_string())
            };
            let _ = status_tx.send(format!("[INFO]     • {} ({})", task.task_id, timing));
            // Task instruction (dimmed)
            let truncated = crate::utils::truncate_for_log(&task.instruction, 100);
            for line in format_indented_dimmed_lines(&truncated, 8) {
                let _ = status_tx.send(format!("[INFO] {}", line));
            }
        }
    }

    // Feedback instructions
    if let Some(fb) = feedback_instructions {
        let truncated = crate::utils::truncate_for_log(fb, 100);
        let _ = status_tx.send(format!("[INFO]   Feedback Instructions: {}", truncated));
    }

    let _ = status_tx.send("[INFO] ══════════════════".to_string());
}

/// Log detailed open_client action summary to the status channel
fn log_open_client_summary(
    status_tx: &mpsc::UnboundedSender<String>,
    protocol: &str,
    remote_addr: &str,
    instruction: &str,
    startup_params: &Option<serde_json::Value>,
    initial_memory: &Option<String>,
    event_handlers: &Option<Vec<serde_json::Value>>,
    scheduled_tasks: &Option<Vec<crate::llm::actions::common::ServerTaskDefinition>>,
    feedback_instructions: &Option<String>,
) {
    // Header
    let _ = status_tx.send("[INFO] ═══ open_client ═══".to_string());

    // Basic client configuration
    let _ = status_tx.send(format!("[INFO]   Protocol: {}", protocol));
    let _ = status_tx.send(format!("[INFO]   Remote: {}", remote_addr));

    // Instruction (truncated if long)
    if !instruction.is_empty() {
        let truncated = crate::utils::truncate_for_log(instruction, 100);
        let _ = status_tx.send(format!("[INFO]   Instruction: {}", truncated));
    }

    // Initial memory (truncated if long)
    if let Some(mem) = initial_memory {
        if !mem.is_empty() {
            let truncated = crate::utils::truncate_for_log(mem, 100);
            let _ = status_tx.send(format!("[INFO]   Initial Memory: {}", truncated));
        }
    }

    // Startup params
    if let Some(params) = startup_params {
        if !params.is_null() {
            let shown = crate::utils::redact::redact_sensitive(params);
            let params_str =
                serde_json::to_string_pretty(&shown).unwrap_or_else(|_| shown.to_string());
            let _ = status_tx.send("[INFO]   Startup Params:".to_string());
            for line in format_indented_dimmed_lines(&params_str, 8) {
                let _ = status_tx.send(format!("[INFO] {}", line));
            }
        }
    }

    // Event handlers summary (same logic as server)
    if let Some(handlers) = event_handlers {
        let _ = status_tx.send(format!(
            "[INFO]   Event Handlers: {} configured",
            handlers.len()
        ));
        for handler in handlers {
            let event_pattern = handler
                .get("event_pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("*");
            let handler_type = handler
                .get("handler")
                .and_then(|h| h.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            let _ = status_tx.send(format!("[INFO]     • {} → {}", event_pattern, handler_type));

            if handler_type == "script" {
                if let Some(code) = handler
                    .get("handler")
                    .and_then(|h| h.get("code"))
                    .and_then(|c| c.as_str())
                {
                    let truncated = crate::utils::truncate_for_log(code, 200);
                    for line in format_indented_dimmed_lines(&truncated, 8) {
                        let _ = status_tx.send(format!("[INFO] {}", line));
                    }
                }
            }

            if handler_type == "static" {
                if let Some(actions) = handler.get("handler").and_then(|h| h.get("actions")) {
                    let actions_str = serde_json::to_string_pretty(actions)
                        .unwrap_or_else(|_| actions.to_string());
                    let truncated = crate::utils::truncate_for_log(&actions_str, 300);
                    for line in format_indented_dimmed_lines(&truncated, 8) {
                        let _ = status_tx.send(format!("[INFO] {}", line));
                    }
                }
            }
        }
    }

    // Scheduled tasks summary
    if let Some(tasks) = scheduled_tasks {
        let _ = status_tx.send(format!(
            "[INFO]   Scheduled Tasks: {} configured",
            tasks.len()
        ));
        for task in tasks {
            let timing = if task.recurring {
                task.interval_secs
                    .map(|i| format!("every {}s", i))
                    .unwrap_or_else(|| "recurring".to_string())
            } else {
                task.delay_secs
                    .map(|d| format!("after {}s", d))
                    .unwrap_or_else(|| "one-shot".to_string())
            };
            let _ = status_tx.send(format!("[INFO]     • {} ({})", task.task_id, timing));
            let truncated = crate::utils::truncate_for_log(&task.instruction, 100);
            for line in format_indented_dimmed_lines(&truncated, 8) {
                let _ = status_tx.send(format!("[INFO] {}", line));
            }
        }
    }

    // Feedback instructions
    if let Some(fb) = feedback_instructions {
        let truncated = crate::utils::truncate_for_log(fb, 100);
        let _ = status_tx.send(format!("[INFO]   Feedback Instructions: {}", truncated));
    }

    let _ = status_tx.send("[INFO] ══════════════════".to_string());
}

/// Event handler that coordinates all event processing
#[derive(Clone)]
pub struct EventHandler {
    /// Application state
    state: AppState,
    /// Ollama client
    llm: OllamaClient,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(state: AppState, llm: OllamaClient) -> Self {
        Self { state, llm }
    }

    /// List available models from Ollama
    pub async fn list_models(&self) -> Result<Vec<String>> {
        self.llm.list_models().await
    }

    /// Get a clone of the Ollama client
    pub fn get_llm_client(&self) -> OllamaClient {
        self.llm.clone()
    }

    /// Replace the LLM client (used by /backend command to switch backends at runtime)
    pub fn set_llm_client(&mut self, client: OllamaClient) {
        self.llm = client;
    }

    /// Handle an application event
    /// Returns Ok(true) if the application should quit
    pub async fn handle_event(&mut self, event: AppEvent, ui: &mut App) -> Result<bool> {
        match event {
            AppEvent::UserCommand(cmd) => self.handle_user_command(cmd, ui).await,
            AppEvent::Tick => {
                // Periodic updates can go here
                Ok(false)
            }
            AppEvent::Shutdown => {
                info!("Shutdown event received");
                Ok(true)
            }
        }
    }

    /// Handle user commands
    /// Returns Ok(true) if the application should quit
    async fn handle_user_command(&mut self, command: UserCommand, ui: &mut App) -> Result<bool> {
        match command {
            UserCommand::Status => {
                self.handle_status(ui).await?;
                Ok(false)
            }
            UserCommand::ShowModel => {
                self.handle_show_model(ui).await?;
                Ok(false)
            }
            UserCommand::ChangeModel { model } => {
                self.handle_change_model(model, ui).await?;
                Ok(false)
            }
            UserCommand::ShowBackend => {
                self.handle_show_backend(ui).await?;
                Ok(false)
            }
            UserCommand::SetBackend { args } => {
                self.handle_set_backend(args, ui).await?;
                Ok(false)
            }
            UserCommand::ShowLogLevel => {
                ui.add_llm_message(format!("Current log level: {}", ui.log_level.as_str()));
                Ok(false)
            }
            UserCommand::ChangeLogLevel { level } => {
                use crate::ui::app::LogLevel;
                if let Some(log_level) = LogLevel::parse(&level) {
                    ui.set_log_level(log_level);
                } else {
                    ui.add_llm_message(format!(
                        "Invalid log level: {level}. Use: error, warn, info, debug, or trace"
                    ));
                }
                Ok(false)
            }
            UserCommand::TestOutput { count } => {
                // Generate test output lines (used for terminal overflow testing)
                for i in 0..count {
                    ui.add_llm_message(format!("Test line {} of {}", i + 1, count));
                }
                Ok(false)
            }
            UserCommand::TestAsk => {
                // Test web search approval prompt by triggering a search to DuckDuckGo
                use crate::llm::actions::tools::{execute_tool, ToolAction};

                ui.add_llm_message(
                    "[INFO] Testing web search approval with DuckDuckGo...".to_string(),
                );

                // Get web search mode and approval channel
                let web_search_mode = self.state.get_web_search_mode().await;
                let approval_tx = self.state.get_web_approval_channel().await;

                // Create a web search action for DuckDuckGo with a long path to test truncation
                let action = ToolAction::WebSearch {
                    query: "https://duckduckgo.com/?q=test+search+query+with+very+long+parameters&ia=web&category=general&filters=none".to_string(),
                };

                // Execute the tool (this will trigger approval prompt if in ASK mode)
                let result = execute_tool(
                    &action,
                    approval_tx.as_ref(),
                    web_search_mode,
                    Some(&self.state),
                )
                .await;

                // Display the result
                if result.success {
                    ui.add_llm_message("[INFO] Web search completed successfully".to_string());
                    ui.add_llm_message(format!("[DEBUG] Result: {}", result.result));
                } else {
                    ui.add_llm_message(format!("[ERROR] Web search failed: {}", result.result));
                }

                Ok(false)
            }
            UserCommand::SetFooterStatus { message } => {
                // This command is only supported in rolling TUI mode
                if message.is_some() {
                    ui.add_llm_message(
                        "Footer status command is only supported in rolling TUI mode".to_string(),
                    );
                }
                Ok(false)
            }
            UserCommand::StopAll => {
                self.handle_stop_all(ui).await?;
                Ok(false)
            }
            UserCommand::StopById { id } => {
                self.handle_stop_by_id(id, ui).await?;
                Ok(false)
            }
            UserCommand::Save { name, id } => {
                self.handle_save(name, id, ui).await?;
                Ok(false)
            }
            UserCommand::Load { name } => {
                self.handle_load(name, ui).await?;
                Ok(false)
            }
            #[cfg(feature = "sqlite")]
            UserCommand::Sqlite { db_id, query } => {
                self.handle_sqlite(db_id, query, ui).await?;
                Ok(false)
            }
            UserCommand::Quit => {
                self.handle_quit(ui).await?;
                Ok(true) // Signal to quit
            }
            UserCommand::UnknownSlashCommand { command } => {
                ui.add_llm_message(format!("Unknown command: {command}"));
                ui.add_llm_message(
                    "Available commands: /status, /model [name], /log [level], /docs [protocol], /quit".to_string(),
                );
                Ok(false)
            }
            UserCommand::Interpret { input: _ } => {
                ui.add_llm_message(
                    "Internal error: Interpret command should use async path".to_string(),
                );
                Ok(false)
            }
            UserCommand::ShowWebSearch => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Web search command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::SetWebSearch { mode: _ } => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Web search command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::ShowEventHandler => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Event handler command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::SetEventHandler { mode: _ } => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Event handler command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::ShowDocs { protocol } => {
                self.handle_show_docs(protocol, ui).await?;
                Ok(false)
            }
            UserCommand::ShowEnvironment => {
                self.handle_show_environment(ui).await?;
                Ok(false)
            }
            UserCommand::ShowUsage => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Usage command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::ShowStability => {
                let min = self.state.get_min_stability().await;
                for line in crate::protocol::stability_report(min) {
                    ui.add_llm_message(line);
                }
                Ok(false)
            }
            UserCommand::ListSimple => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Simple protocol command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::StartSimple { protocol: _ } => {
                // This command is only supported in rolling TUI mode
                ui.add_llm_message(
                    "Simple protocol command is only supported in rolling TUI mode".to_string(),
                );
                Ok(false)
            }
            UserCommand::Manage | UserCommand::Update { .. } => {
                // These commands are only supported in rolling TUI mode
                ui.add_llm_message(
                    "The /manage and /update commands are only supported in rolling TUI mode"
                        .to_string(),
                );
                Ok(false)
            }
        }
    }

    /// Handle interpret command using NEW action-based system with multi-turn tool support
    /// This method can be spawned in a task without blocking the UI
    pub async fn handle_interpret_with_actions(
        &mut self,
        input: String,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Option<Box<dyn Server + Send>>,
    ) -> Result<()> {
        use crate::llm::{ConversationHandler, PromptBuilder};

        // Get protocol async actions if available
        let protocol_async_actions = if let Some(ref proto) = protocol {
            proto.get_async_actions(&self.state)
        } else {
            Vec::new()
        };

        // Get model, ensuring one is selected
        let current_model = self.state.get_ollama_model().await;
        let model = match crate::llm::ensure_model_selected(
            current_model.clone(),
            &self.state.get_ollama_url().await,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to ensure model is selected: {}", e));
            }
        };

        // If model was auto-selected (wasn't set before), notify via status_tx
        if current_model.is_none() {
            let _ = status_tx.send(format!(
                "⚠  Auto-selected model: {} (no model was configured)",
                model
            ));
        }

        // Create LLM client with status channel for trace logs
        let llm_with_status = self.llm.clone().with_status_tx(status_tx.clone());

        // Get web search mode and approval channel
        let web_search_mode = self.state.get_web_search_mode().await;
        let approval_tx = self.state.get_web_approval_channel().await;

        // Get conversation history from persistent state
        let conversation_history = self.state.get_user_conversation_history().await;

        // Check if open_server/open_client should be enabled based on configuration
        let (is_open_server_enabled, is_open_client_enabled) =
            open_actions_enabled(&self.state).await;

        // Build system prompt (without user input - that's added as a message)
        let system_prompt = PromptBuilder::build_user_input_system_prompt_with_docs(
            &self.state,
            protocol_async_actions.clone(),
            conversation_history,
            is_open_server_enabled,
            is_open_client_enabled,
        )
        .await;

        // Get available actions for retry correction messages
        let selected_mode = self.state.get_selected_scripting_mode().await;
        let scripting_env = self.state.get_scripting_env().await;
        let mut available_actions = crate::llm::actions::common::get_operator_common_actions(
            selected_mode,
            &scripting_env,
            is_open_server_enabled,
            is_open_client_enabled,
        );
        available_actions.extend(get_all_tool_actions(web_search_mode));
        available_actions.extend(protocol_async_actions);
        crate::llm::actions::common::restrict_protocol_lists(
            &mut available_actions,
            self.state.get_include_disabled_protocols().await,
            self.state.get_min_stability().await,
        );

        // Narrow to what the prompt actually advertises before this list is used as the native
        // tool schema and as the retry-correction catalogue. The prompt builder applies
        // filter_actions_by_scripting_mode to what it renders; handing the unfiltered list to
        // with_native_tools offered the model script parameters the prose told it do not exist,
        // and validated its reply against a superset of what it was shown.
        let available_actions =
            PromptBuilder::advertised_user_input_actions(&self.state, available_actions).await;

        // Get or create persistent conversation state
        let conversation_state = self.state.get_or_create_user_conversation_state().await;

        // Get rate limiter for user requests
        let rate_limiter = self.state.get_rate_limiter().await;

        let mut conversation = ConversationHandler::new(
            system_prompt,
            std::sync::Arc::new(llm_with_status),
            model,
            rate_limiter,
            crate::llm::RequestSource::User, // User input always waits for rate limits
        )
        .with_native_tools(&available_actions)
        .with_status_tx(status_tx.clone())
        .with_tracking(
            self.state.clone(),
            crate::state::app_state::ConversationSource::User,
            input.clone(),
        )
        .with_conversation_state(conversation_state);

        // Register conversation immediately so it shows in UI
        self.state
            .register_conversation(
                conversation.conversation_id().to_string(),
                crate::state::app_state::ConversationSource::User,
                input.clone(),
            )
            .await;

        // Mark as registered to prevent duplicate registration in generate_with_tools_and_retry
        conversation.mark_registered();

        // Add user input as a separate user message
        conversation.add_user_message(input);

        // Retry loop for execution-time errors (e.g., port conflicts)
        const MAX_EXECUTION_RETRIES: usize = 1;
        let mut execution_attempts = 0;

        loop {
            // Generate actions with tool calling and retry
            let actions = conversation
                .generate_with_tools_and_retry(
                    approval_tx.clone(),
                    web_search_mode,
                    available_actions.clone(),
                )
                .await;

            match actions {
                Ok(action_values) => {
                    let mut should_retry = false;
                    let mut retry_error: Option<crate::events::ActionExecutionError> = None;

                    // Handle server management actions FIRST (they need to be executed before other actions)
                    let mut state_changed = false;
                    for action_value in &action_values {
                        if let Ok(common_action) = CommonAction::from_json(action_value) {
                            // Check if this action will modify state (open_server, close_server, open_client, close_client, etc.)
                            let modifies_state = matches!(
                                common_action,
                                CommonAction::OpenServer { .. }
                                    | CommonAction::CloseServer { .. }
                                    | CommonAction::CloseAllServers
                                    | CommonAction::OpenClient { .. }
                                    | CommonAction::CloseClient { .. }
                                    | CommonAction::CloseAllClients
                                    | CommonAction::CloseConnectionById { .. }
                                    | CommonAction::UpdateServer { .. }
                                    | CommonAction::UpdateClient { .. }
                            );

                            match self
                                .execute_server_management_action(common_action, &status_tx)
                                .await
                            {
                                Ok(_) => {
                                    // Action executed successfully
                                    if modifies_state {
                                        state_changed = true;
                                    }
                                }
                                Err(e)
                                    if e.is_retryable()
                                        && execution_attempts < MAX_EXECUTION_RETRIES =>
                                {
                                    // Retryable error (e.g., port conflict) - prepare to retry
                                    should_retry = true;
                                    retry_error = Some(e);
                                    break; // Stop processing actions, we'll retry
                                }
                                Err(e) => {
                                    // Non-retryable error or max retries exceeded
                                    let _ = status_tx
                                        .send(format!("[ERROR] Error executing action: {e}"));
                                }
                            }
                        }
                    }

                    // Update conversation state if server state changed
                    if state_changed && !should_retry {
                        conversation.update_current_state(&self.state, None).await;
                        let _ = status_tx.send(
                            "[DEBUG] Updated conversation state after server changes".to_string(),
                        );
                    }

                    // If we should retry, add error to conversation and retry
                    if should_retry {
                        if let Some(error) = retry_error {
                            execution_attempts += 1;
                            let _ = status_tx.send(format!(
                                "[INFO] Execution error (attempt {}/{}), retrying with LLM feedback...",
                                execution_attempts,
                                MAX_EXECUTION_RETRIES + 1
                            ));

                            // Add error correction to conversation
                            let correction = error.build_correction_message();
                            conversation.add_user_message(correction);

                            // Continue loop to retry
                            continue;
                        }
                    }

                    // Then execute all other actions (including append_to_log)
                    let protocol_ref: Option<&dyn Server> =
                        protocol.as_ref().map(|p| p.as_ref() as &dyn Server);

                    // User input context - no specific server/client (global actions)
                    match execute_actions(
                        action_values.clone(),
                        &self.state,
                        protocol_ref,
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(result) => {
                            // Display messages
                            for msg in result.messages {
                                let _ = status_tx.send(msg);
                            }
                        }
                        Err(e) => {
                            let _ =
                                status_tx.send(format!("[ERROR] Failed to execute actions: {e}"));
                        }
                    }

                    // Success - break out of retry loop
                    break;
                }
                Err(e) => {
                    let _ = status_tx.send(format!("[ERROR] LLM error: {e}"));
                    // End conversation tracking since generate_with_tools_and_retry didn't complete
                    conversation.end_tracking().await;
                    break; // LLM errors don't retry at this level
                }
            }
        }

        Ok(())
    }

    /// Execute server management actions (open_server, close_server, etc.)
    ///
    /// Public so `tests/` can drive the real `open_server` / `open_client` executor —
    /// including `log_open_server_summary`, which used to panic on a multi-byte
    /// instruction — rather than re-implementing it. See the test-location policy in
    /// `CLAUDE.md`: tests reach internals through `netget::` public APIs.
    pub async fn execute_server_management_action(
        &mut self,
        action: CommonAction,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<(), crate::events::ActionExecutionError> {
        match action {
            CommonAction::OpenServer {
                mac_address,
                interface,
                host,
                port,
                protocol,
                send_first,
                initial_memory,
                instruction,
                startup_params,
                event_handlers,
                scheduled_tasks,
                feedback_instructions,
                history,
                batching,
            } => {
                // Documentation gate (off by default, see REQUIRE_DOCS_FOR_OPEN_ACTIONS):
                // when enabled, the first open_server of the process fetches the
                // protocol documentation and returns DocumentationRequired, which
                // makes the model retry the same action with the docs in context.
                if REQUIRE_DOCS_FOR_OPEN_ACTIONS && !self.state.is_server_docs_read().await {
                    // Fetch documentation for this protocol
                    use crate::llm::actions::tools::{execute_tool, ToolAction};
                    let doc_tool = ToolAction::ReadDocumentation {
                        protocols: vec![protocol.clone()],
                        protocol: None,
                    };

                    // Execute the tool to get documentation
                    let approval_tx = self.state.get_web_approval_channel().await;
                    let web_search_mode = self.state.get_web_search_mode().await;
                    let tool_result = execute_tool(
                        &doc_tool,
                        approval_tx.as_ref(),
                        web_search_mode,
                        Some(&self.state),
                    )
                    .await;

                    if tool_result.success {
                        // Mark docs as read so we don't loop forever
                        self.state
                            .mark_server_protocols_documented(&[protocol.clone()])
                            .await;

                        // Build the original action JSON for reference
                        let original_action = serde_json::json!({
                            "type": "open_server",
                            "mac_address": mac_address,
                            "interface": interface,
                            "host": host,
                            "port": port,
                            "protocol": protocol,
                            "send_first": send_first,
                            "initial_memory": initial_memory,
                            "instruction": instruction,
                            "startup_params": startup_params,
                            "event_handlers": event_handlers,
                            "scheduled_tasks": scheduled_tasks,
                            "feedback_instructions": feedback_instructions,
                        });

                        // Return DocumentationRequired error with the documentation
                        return Err(ActionExecutionError::DocumentationRequired {
                            action_type: "open_server".to_string(),
                            protocol: protocol.clone(),
                            documentation: tool_result.result,
                            original_action,
                        });
                    } else {
                        // If documentation fetch fails, log warning but proceed
                        let _ = status_tx.send(format!(
                            "[WARN] Failed to fetch documentation for {}: {}. Proceeding anyway.",
                            protocol, tool_result.result
                        ));
                    }
                }

                // Log detailed summary of the open_server action
                log_open_server_summary(
                    status_tx,
                    &mac_address,
                    &interface,
                    &host,
                    port,
                    &protocol,
                    send_first,
                    &initial_memory,
                    &instruction,
                    &startup_params,
                    &event_handlers,
                    &scheduled_tasks,
                    &feedback_instructions,
                );

                // Save copies for error handling before values are moved
                let mac_address_clone = mac_address.clone();
                let interface_clone = interface.clone();
                let host_clone = host.clone();
                let initial_memory_clone = initial_memory.clone();
                let instruction_clone = instruction.clone();
                let startup_params_clone = startup_params.clone();
                let event_handlers_clone = event_handlers.clone();
                let scheduled_tasks_clone = scheduled_tasks.clone();
                let feedback_instructions_clone = feedback_instructions.clone();

                // Use start_server_from_action which properly handles flexible binding
                // (including interface, mac_address, host for migrated protocols)
                match server_startup::start_server_from_action(
                    &self.state,
                    mac_address,
                    interface,
                    host,
                    port,
                    &protocol,
                    send_first,
                    initial_memory,
                    instruction,
                    startup_params,
                    event_handlers,
                    scheduled_tasks,
                    feedback_instructions,
                    crate::protocol::metadata::ConversationOverrides { history, batching },
                    status_tx.clone(),
                )
                .await
                {
                    Ok(server_id) => {
                        // Server started successfully
                        let _ = status_tx.send(format!(
                            "[INFO] Server #{} started successfully",
                            server_id.as_u32()
                        ));
                    }
                    Err(e) => {
                        // Check error type and provide appropriate retryable error
                        let error_msg = e.to_string();

                        // Check if it's a port binding error (retryable)
                        let is_port_conflict = error_msg.contains("Address already in use")
                            || error_msg.contains("port conflict")
                            || error_msg.contains("bind");

                        // Check if it's a validation error about missing or invalid parameters (retryable)
                        let is_validation_error = error_msg
                            .contains("Invalid event handler configuration")
                            || error_msg.contains("Missing 'instruction' field")
                            || error_msg.contains("instruction is required");

                        if is_port_conflict && port.is_some() {
                            // Port conflict - create retryable error
                            return Err(ActionExecutionError::PortConflict {
                                port: port.unwrap(),
                                protocol: protocol.to_string(),
                                underlying_error: error_msg,
                            });
                        } else if is_validation_error {
                            // Build the original action JSON for reference
                            let original_action = serde_json::json!({
                                "type": "open_server",
                                "mac_address": mac_address_clone,
                                "interface": interface_clone,
                                "host": host_clone,
                                "port": port,
                                "protocol": protocol,
                                "send_first": send_first,
                                "initial_memory": initial_memory_clone,
                                "instruction": instruction_clone,
                                "startup_params": startup_params_clone,
                                "event_handlers": event_handlers_clone,
                                "scheduled_tasks": scheduled_tasks_clone,
                                "feedback_instructions": feedback_instructions_clone,
                            });

                            let parameter_name = event_handler_parameter_name(&error_msg);

                            return Err(ActionExecutionError::InvalidActionParameters {
                                action_type: "open_server".to_string(),
                                parameter_name: parameter_name.to_string(),
                                error_message: error_msg.clone(),
                                original_action,
                            });
                        } else {
                            // Fatal error - propagate as fatal
                            let _ = status_tx
                                .send(format!("[ERROR] Failed to start server: {}", error_msg));
                            return Err(ActionExecutionError::Fatal(e));
                        }
                    }
                }

                // NOTE: scheduled_tasks and event_handlers are now handled by start_server_from_action
            }
            CommonAction::CloseServer { server_id } => {
                use crate::state::server::ServerStatus;

                // Close specific server
                let sid = crate::state::ServerId::new(server_id);

                // Mark server as Stopped instead of removing it (reaper will clean up after 30s)
                self.state
                    .update_server_status(sid, ServerStatus::Stopped)
                    .await;
                let _ = status_tx.send(format!("[SERVER] Stopped server #{}", sid.as_u32()));

                // Clean up tasks associated with this server
                self.state.cleanup_server_tasks(sid).await;
                let _ = status_tx.send(format!(
                    "[TASK] Cleaned up tasks for server #{}",
                    sid.as_u32()
                ));

                // Shut down any resident script processes for this server
                crate::scripting::ResidentScriptManager::shutdown_server(sid.as_u32()).await;

                // Check if all servers are stopped/error
                let all_stopped =
                    self.state.get_all_servers().await.iter().all(|s| {
                        matches!(s.status, ServerStatus::Stopped | ServerStatus::Error(_))
                    });

                if all_stopped {
                    self.state.set_mode(Mode::Idle).await;
                }

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::CloseAllServers => {
                use crate::state::server::ServerStatus;

                // Close all servers
                let server_ids = self.state.get_all_server_ids().await;

                for server_id in server_ids {
                    // Mark server as Stopped instead of removing it (reaper will clean up after 30s)
                    self.state
                        .update_server_status(server_id, ServerStatus::Stopped)
                        .await;
                    let _ =
                        status_tx.send(format!("[SERVER] Stopped server #{}", server_id.as_u32()));

                    // Clean up tasks associated with this server
                    self.state.cleanup_server_tasks(server_id).await;
                    let _ = status_tx.send(format!(
                        "[TASK] Cleaned up tasks for server #{}",
                        server_id.as_u32()
                    ));

                    // Shut down any resident script processes for this server
                    crate::scripting::ResidentScriptManager::shutdown_server(server_id.as_u32())
                        .await;
                }

                // Set mode to Idle
                self.state.set_mode(Mode::Idle).await;

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::UpdateInstruction { instruction } => {
                // No instance is in context here, so this can only mean the first server. The
                // operator prompt does not offer update_instruction for that reason (see
                // common::NOT_OFFERED_TO_OPERATOR); update_server names its target. This arm
                // remains for the scheduled-task path, which still offers it.
                if let Some(server_id) = self.state.get_first_server_id().await {
                    self.state
                        .set_instruction(server_id, instruction.clone())
                        .await;
                    let _ = status_tx.send(format!(
                        "[INFO] Server #{} instruction: {}",
                        server_id.as_u32(),
                        instruction
                    ));
                } else {
                    let _ =
                        status_tx.send("[WARN] No server to update instruction for".to_string());
                }
            }
            CommonAction::ChangeModel { model } => {
                self.state.set_ollama_model(Some(model.clone())).await;
                let _ = status_tx.send(format!("Changed model to: {model}"));

                // Signal main loop to update UI
                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            // Memory actions need server_id context
            CommonAction::SetMemory { value } => {
                if let Some(server_id) = self.state.get_first_server_id().await {
                    self.state.set_memory(server_id, value).await;
                }
            }
            CommonAction::AppendMemory { value } => {
                if let Some(server_id) = self.state.get_first_server_id().await {
                    self.state.append_memory(server_id, value).await;
                }
            }
            CommonAction::AppendToLog { .. } => {
                // AppendToLog is handled by the action executor, not here
                // This match arm exists to satisfy exhaustiveness checking
            }
            CommonAction::ScheduleTask {
                task_id,
                recurring,
                delay_secs,
                interval_secs,
                max_executions,
                server_id,
                connection_id,
                client_id,
                instruction,
                context,
                script_runtime,
                script_language,
                script_path,
                script_inline,
                script_handles,
            } => {
                use crate::state::task::{ScheduledTask, TaskScope};

                // A scheduled task always calls the model with its instruction; it runs no
                // script. Refuse script fields by name rather than scheduling a task that
                // silently does something other than what was asked.
                let script_fields: Vec<&str> = [
                    ("script_runtime", script_runtime.is_some()),
                    ("script_language", script_language.is_some()),
                    ("script_path", script_path.is_some()),
                    ("script_inline", script_inline.is_some()),
                    ("script_handles", script_handles.is_some()),
                ]
                .into_iter()
                .filter_map(|(name, present)| present.then_some(name))
                .collect();
                if !script_fields.is_empty() {
                    let _ = status_tx.send(format!(
                        "[ERROR] schedule_task '{}' not scheduled: a scheduled task runs no \
                         script, it calls the model with its instruction ({} not supported)",
                        task_id,
                        script_fields.join(", ")
                    ));
                    return Ok(());
                }

                // Determine scope: Connection > Server > Client > Global
                let scope = if let Some(conn_id_str) = connection_id {
                    // Connection scope requires server_id
                    if let Some(sid) = server_id {
                        let server_id_obj = crate::state::ServerId::new(sid);
                        match crate::server::connection::ConnectionId::from_string(&conn_id_str) {
                            Some(cid) => {
                                // Validate connection exists on server
                                if let Some(server) = self.state.get_server(server_id_obj).await {
                                    if server.connections.contains_key(&cid) {
                                        TaskScope::Connection(server_id_obj, cid)
                                    } else {
                                        let _ = status_tx.send(format!(
                                            "[ERROR] Connection {} not found on server #{}",
                                            conn_id_str, sid
                                        ));
                                        return Ok(());
                                    }
                                } else {
                                    let _ = status_tx.send(format!(
                                        "[ERROR] Server #{} not found for connection-scoped task",
                                        sid
                                    ));
                                    return Ok(());
                                }
                            }
                            None => {
                                let _ = status_tx.send(format!(
                                    "[ERROR] Invalid connection_id format: {}. Expected 'conn-123' or '123'",
                                    conn_id_str
                                ));
                                return Ok(());
                            }
                        }
                    } else {
                        let _ = status_tx.send(
                            "[ERROR] connection_id requires server_id to be specified".to_string(),
                        );
                        return Ok(());
                    }
                } else if let Some(sid) = server_id {
                    TaskScope::Server(crate::state::ServerId::new(sid))
                } else if let Some(cid) = client_id {
                    let client_id_obj = crate::state::ClientId::new(cid);
                    // Validate client exists
                    if self.state.get_client(client_id_obj).await.is_none() {
                        let _ = status_tx.send(format!(
                            "[ERROR] Client #{} not found for client-scoped task",
                            cid
                        ));
                        return Ok(());
                    }
                    TaskScope::Client(client_id_obj)
                } else {
                    TaskScope::Global
                };

                // Determine delay: for one-shot use delay_secs, for recurring use delay_secs or interval_secs
                let delay = if recurring {
                    delay_secs.or(interval_secs).unwrap_or(0)
                } else {
                    delay_secs.unwrap_or(0)
                };

                let mut task = if recurring {
                    let interval = interval_secs.unwrap_or(delay);
                    ScheduledTask::new_recurring(
                        crate::state::TaskId::new(0), // Temporary, will be assigned by add_task
                        task_id.clone(),
                        scope,
                        interval,
                        max_executions,
                        instruction,
                        context,
                    )
                } else {
                    ScheduledTask::new_one_shot(
                        crate::state::TaskId::new(0), // Temporary, will be assigned by add_task
                        task_id.clone(),
                        scope,
                        delay,
                        instruction,
                        context,
                    )
                }?;

                task.next_execution = crate::state::task::checked_task_deadline(delay)?;

                let task_id_num = self.state.add_task(task).await;

                if recurring {
                    let interval = interval_secs.unwrap_or(delay);
                    let max_info = if let Some(max) = max_executions {
                        format!(" (max {} executions)", max)
                    } else {
                        String::new()
                    };
                    let _ = status_tx.send(format!(
                        "[TASK] Scheduled recurring task '{}' (ID: {}) to execute every {}s{}",
                        task_id, task_id_num, interval, max_info
                    ));
                } else {
                    let _ = status_tx.send(format!(
                        "[TASK] Scheduled one-shot task '{}' (ID: {}) to execute in {}s",
                        task_id, task_id_num, delay
                    ));
                }
            }
            CommonAction::CancelTask { task_id } => {
                if let Some(task) = self.state.get_task(&task_id).await {
                    self.state.remove_task(task.id).await;
                    let _ = status_tx.send(format!("[TASK] Cancelled task '{}'", task_id));
                } else {
                    let _ = status_tx.send(format!("[WARN] Task '{}' not found", task_id));
                }
            }
            CommonAction::OpenClient {
                protocol,
                remote_addr,
                instruction,
                startup_params,
                initial_memory,
                event_handlers,
                scheduled_tasks,
                feedback_instructions,
                history,
                batching,
            } => {
                // Documentation gate (off by default, see REQUIRE_DOCS_FOR_OPEN_ACTIONS):
                // when enabled, the first open_client of the process fetches the
                // protocol documentation and returns DocumentationRequired, which
                // makes the model retry the same action with the docs in context.
                if REQUIRE_DOCS_FOR_OPEN_ACTIONS && !self.state.is_client_docs_read().await {
                    // Fetch documentation for this protocol
                    use crate::llm::actions::tools::{execute_tool, ToolAction};
                    let doc_tool = ToolAction::ReadDocumentation {
                        protocols: vec![protocol.clone()],
                        protocol: None,
                    };

                    // Execute the tool to get documentation
                    let approval_tx = self.state.get_web_approval_channel().await;
                    let web_search_mode = self.state.get_web_search_mode().await;
                    let tool_result = execute_tool(
                        &doc_tool,
                        approval_tx.as_ref(),
                        web_search_mode,
                        Some(&self.state),
                    )
                    .await;

                    if tool_result.success {
                        // Mark docs as read so we don't loop forever
                        self.state
                            .mark_client_protocols_documented(&[protocol.clone()])
                            .await;

                        // Build the original action JSON for reference
                        let original_action = serde_json::json!({
                            "type": "open_client",
                            "protocol": protocol,
                            "remote_addr": remote_addr,
                            "instruction": instruction,
                            "startup_params": startup_params,
                            "initial_memory": initial_memory,
                            "event_handlers": event_handlers,
                            "scheduled_tasks": scheduled_tasks,
                            "feedback_instructions": feedback_instructions,
                        });

                        // Return DocumentationRequired error with the documentation
                        return Err(ActionExecutionError::DocumentationRequired {
                            action_type: "open_client".to_string(),
                            protocol: protocol.clone(),
                            documentation: tool_result.result,
                            original_action,
                        });
                    } else {
                        // If documentation fetch fails, log warning but proceed
                        let _ = status_tx.send(format!(
                            "[WARN] Failed to fetch documentation for {}: {}. Proceeding anyway.",
                            protocol, tool_result.result
                        ));
                    }
                }

                let prepared_tasks = crate::state::task::prepare_tasks(
                    scheduled_tasks.as_deref(),
                    crate::state::task::TaskScope::Global,
                )?;

                // Log detailed summary of the open_client action
                log_open_client_summary(
                    status_tx,
                    &protocol,
                    &remote_addr,
                    &instruction,
                    &startup_params,
                    &initial_memory,
                    &event_handlers,
                    &scheduled_tasks,
                    &feedback_instructions,
                );

                use crate::state::client::{ClientInstance, ClientStatus};

                // Save copies for error handling before values are moved
                let event_handlers_clone = event_handlers.clone();
                let feedback_instructions_clone = feedback_instructions.clone();
                let initial_memory_clone = initial_memory.clone();

                // Parse the event-handler configuration *before* the client is registered.
                //
                // Parsing rejects unknown action names, unknown handler types and malformed
                // `{{event.…}}` references — all of them things the model gets wrong — so this
                // is a routinely reachable failure, not a theoretical one. It used to run
                // after `add_client`, which meant every rejection left an orphan client row
                // behind in `Connecting`, exactly the way undeclared startup parameters used
                // to leave an orphan server. Validate first, register nothing on failure.
                let parsed_event_handlers = match event_handlers {
                    Some(handlers_json) => match Self::parse_event_handlers(handlers_json) {
                        Ok(config) => Some(config),
                        Err(e) => {
                            // Build the original action JSON for reference
                            let original_action = serde_json::json!({
                                "type": "open_client",
                                "protocol": protocol,
                                "remote_addr": remote_addr,
                                "instruction": instruction,
                                "startup_params": startup_params,
                                "initial_memory": initial_memory_clone,
                                "event_handlers": event_handlers_clone,
                                "scheduled_tasks": scheduled_tasks,
                                "feedback_instructions": feedback_instructions_clone,
                            });

                            let error_msg = e.to_string();

                            // Return error instead of just warning - invalid config should fail
                            let _ = status_tx.send(format!(
                                "[ERROR] Invalid event handler configuration: {}",
                                error_msg
                            ));
                            return Err(ActionExecutionError::InvalidActionParameters {
                                action_type: "open_client".to_string(),
                                parameter_name: event_handler_parameter_name(&error_msg)
                                    .to_string(),
                                error_message: error_msg,
                                original_action,
                            });
                        }
                    },
                    None => None,
                };

                // Create client instance with temporary ID (add_client will assign real ID)
                let mut client = ClientInstance::new(
                    crate::state::ClientId::new(0),
                    remote_addr.clone(),
                    protocol.clone(),
                    instruction.clone(),
                );

                // Set optional fields
                if let Some(mem) = initial_memory {
                    client.memory = mem;
                }
                client.startup_params = startup_params.clone();
                client.feedback_instructions = feedback_instructions;
                if let Some(protocol_impl) = crate::protocol::CLIENT_REGISTRY.get(&protocol) {
                    let overrides =
                        crate::protocol::metadata::ConversationOverrides { history, batching };
                    let (history_entries, batching) = overrides
                        .resolve(&protocol_impl.metadata(), &protocol)
                        .map_err(|e| ActionExecutionError::InvalidActionParameters {
                            action_type: "open_client".to_string(),
                            parameter_name: if history
                                .is_some_and(|h| h > crate::protocol::metadata::MAX_HISTORY_ENTRIES)
                            {
                                "history".to_string()
                            } else {
                                "batching".to_string()
                            },
                            error_message: e.to_string(),
                            original_action: serde_json::json!({
                                "type": "open_client",
                                "protocol": protocol,
                                "remote_addr": remote_addr,
                                "history": history,
                                "batching": batching,
                            }),
                        })?;
                    client.history_entries = history_entries;
                    client.batching = batching;
                }

                // Add client to state (this allocates the real client ID)
                let client_id = self.state.add_client(client).await;

                // Apply the configuration parsed above. Parsing already happened, before
                // `add_client`, so a rejected configuration cannot leave an orphan client.
                if let Some(config) = parsed_event_handlers {
                    self.state
                        .set_client_event_handler_config(client_id, Some(config))
                        .await;
                    let _ = status_tx
                        .send("[INFO] Event handler configuration applied to client".to_string());
                }

                let _ = status_tx.send(format!(
                    "[CLIENT] Opening {} client #{} to {}...",
                    protocol,
                    client_id.as_u32(),
                    remote_addr
                ));

                // Start the client connection
                let llm_client = self.llm.clone();
                let status_tx_clone = status_tx.clone();
                match crate::cli::client_startup::start_client_by_id(
                    &self.state,
                    client_id,
                    &llm_client,
                    &status_tx_clone,
                )
                .await
                {
                    Ok(_) => {
                        // Client started successfully
                        let _ = status_tx.send(format!(
                            "[CLIENT] {} client #{} connected",
                            protocol,
                            client_id.as_u32()
                        ));

                        for mut task in prepared_tasks {
                            task.scope = crate::state::task::TaskScope::Client(client_id);
                            let task_name = task.name.clone();
                            let task_id_num = self.state.add_task(task).await;
                            let _ = status_tx.send(format!(
                                "[TASK] Created task '{}' (ID: {}) for client #{}",
                                task_name,
                                task_id_num,
                                client_id.as_u32()
                            ));
                        }
                    }
                    Err(e) => {
                        // Connection failed
                        self.state
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_tx.send(format!(
                            "[ERROR] Failed to connect {} client #{}: {}",
                            protocol,
                            client_id.as_u32(),
                            e
                        ));
                        return Err(e);
                    }
                }

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::CloseClient { client_id } => {
                use crate::state::client::ClientStatus;

                let cid = crate::state::ClientId::new(client_id);

                // Mark client as Disconnected
                self.state
                    .update_client_status(cid, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send(format!("[CLIENT] Closed client #{}", cid.as_u32()));

                // Clean up tasks associated with this client
                self.state.cleanup_client_tasks(cid).await;
                let _ = status_tx.send(format!(
                    "[TASK] Cleaned up tasks for client #{}",
                    cid.as_u32()
                ));

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::CloseAllClients => {
                use crate::state::client::ClientStatus;

                let client_ids = self.state.get_all_client_ids().await;

                for client_id in client_ids {
                    // Mark client as Disconnected
                    self.state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ =
                        status_tx.send(format!("[CLIENT] Closed client #{}", client_id.as_u32()));

                    // Clean up tasks associated with this client
                    self.state.cleanup_client_tasks(client_id).await;
                    let _ = status_tx.send(format!(
                        "[TASK] Cleaned up tasks for client #{}",
                        client_id.as_u32()
                    ));
                }

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::CloseConnectionById { connection_id } => {
                use crate::server::connection::ConnectionId;

                let conn_id = ConnectionId::new(connection_id);
                let all_servers = self.state.get_all_servers().await;

                let mut found = false;
                for server in all_servers {
                    if server.connections.contains_key(&conn_id) {
                        self.state
                            .close_connection_on_server(server.id, conn_id)
                            .await;
                        let _ = status_tx.send(format!(
                            "[CONNECTION] Closed connection {} on server #{}",
                            conn_id,
                            server.id.as_u32()
                        ));
                        found = true;
                        break;
                    }
                }

                if !found {
                    let _ = status_tx.send(format!(
                        "[ERROR] Connection {} not found on any running server",
                        conn_id
                    ));
                }

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::ReconnectClient { client_id } => {
                let cid = crate::state::ClientId::new(client_id);

                // Reconnect the client
                let llm_client = self.llm.clone();
                let status_tx_clone = status_tx.clone();

                let _ =
                    status_tx.send(format!("[CLIENT] Reconnecting client #{}...", cid.as_u32()));

                match crate::cli::client_startup::start_client_by_id(
                    &self.state,
                    cid,
                    &llm_client,
                    &status_tx_clone,
                )
                .await
                {
                    Ok(_) => {
                        let _ = status_tx
                            .send(format!("[CLIENT] Client #{} reconnected", cid.as_u32()));
                    }
                    Err(e) => {
                        let _ = status_tx.send(format!(
                            "[ERROR] Failed to reconnect client #{}: {}",
                            cid.as_u32(),
                            e
                        ));
                        return Err(e);
                    }
                }

                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::UpdateClientInstruction {
                client_id,
                instruction,
            } => {
                let cid = crate::state::ClientId::new(client_id);

                // Update client instruction
                self.state
                    .set_instruction_for_client(cid, instruction.clone())
                    .await;

                let _ = status_tx.send(format!(
                    "[CLIENT] Updated instruction for client #{}",
                    cid.as_u32()
                ));
                let _ = status_tx.send(format!("[CLIENT] New instruction: {}", instruction));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            CommonAction::UpdateServer {
                server_id,
                port,
                host,
                interface,
                mac_address,
                send_first,
                instruction,
                initial_memory,
                startup_params,
                event_handlers,
                scheduled_tasks,
                feedback_instructions,
                history,
                batching,
            } => {
                use crate::cli::management::{self, ServerForm};
                let form = ServerForm {
                    protocol: String::new(), // immutable; empty means "unchanged"
                    port,
                    host,
                    interface,
                    mac_address,
                    send_first,
                    instruction,
                    initial_memory,
                    startup_params,
                    event_handlers,
                    scheduled_tasks,
                    feedback_instructions,
                    history,
                    batching,
                };
                match management::update_server(
                    &self.state,
                    crate::state::ServerId::new(server_id),
                    form,
                    status_tx.clone(),
                )
                .await
                {
                    Ok(outcome) => {
                        let _ = status_tx.send(format!("[INFO] {}", outcome.summary));
                    }
                    Err(e) => {
                        let _ = status_tx.send(format!("[ERROR] Failed to update server: {}", e));
                        return Err(crate::events::ActionExecutionError::Fatal(e));
                    }
                }
            }
            CommonAction::UpdateClient {
                client_id,
                remote_addr,
                instruction,
                initial_memory,
                startup_params,
                event_handlers,
                scheduled_tasks,
                feedback_instructions,
                history,
                batching,
            } => {
                use crate::cli::management::{self, ClientForm};
                let form = ClientForm {
                    protocol: String::new(), // immutable; empty means "unchanged"
                    remote_addr,
                    instruction,
                    initial_memory,
                    startup_params,
                    event_handlers,
                    scheduled_tasks,
                    feedback_instructions,
                    history,
                    batching,
                };
                match management::update_client(
                    &self.state,
                    crate::state::ClientId::new(client_id),
                    form,
                    self.llm.clone(),
                    status_tx.clone(),
                )
                .await
                {
                    Ok(outcome) => {
                        let _ = status_tx.send(format!("[INFO] {}", outcome.summary));
                    }
                    Err(e) => {
                        let _ = status_tx.send(format!("[ERROR] Failed to update client: {}", e));
                        return Err(crate::events::ActionExecutionError::Fatal(e));
                    }
                }
            }

            #[cfg(feature = "sqlite")]
            CommonAction::CreateDatabase {
                name,
                is_memory,
                owner,
                schema_ddl,
            } => {
                use crate::state::DatabaseOwner;

                // The name becomes a filesystem path (`./netget_db_<name>.db`) that
                // `delete_database` later removes, so a model-supplied `../` or absolute
                // path would write and destroy files outside the working directory.
                // Reject, never sanitise: a rewritten name would leave the model referring
                // to a database that does not exist under that name.
                if let Err(e) = crate::state::sqlite::validate_database_name(&name) {
                    let _ = status_tx.send(format!("[ERROR] {}", e));
                    return Ok(());
                }

                // Construct path based on is_memory flag
                let db_path = if is_memory {
                    crate::state::sqlite::MEMORY_DATABASE_PATH.to_string()
                } else {
                    match crate::state::sqlite::database_file_path(&name) {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = status_tx.send(format!("[ERROR] {}", e));
                            return Ok(());
                        }
                    }
                };

                // Determine owner (default to global)
                let db_owner = if let Some(owner_str) = owner {
                    if owner_str == "global" {
                        DatabaseOwner::Global
                    } else if let Some(id_str) = owner_str.strip_prefix("server-") {
                        if let Ok(id) = id_str.parse::<u32>() {
                            DatabaseOwner::Server(crate::state::ServerId::new(id))
                        } else {
                            let _ = status_tx
                                .send(format!("[ERROR] Invalid server ID in owner: {}", owner_str));
                            return Ok(());
                        }
                    } else if let Some(id_str) = owner_str.strip_prefix("client-") {
                        if let Ok(id) = id_str.parse::<u32>() {
                            DatabaseOwner::Client(crate::state::ClientId::new(id))
                        } else {
                            let _ = status_tx
                                .send(format!("[ERROR] Invalid client ID in owner: {}", owner_str));
                            return Ok(());
                        }
                    } else {
                        let _ =
                            status_tx.send(format!("[ERROR] Invalid owner format: {}", owner_str));
                        return Ok(());
                    }
                } else {
                    // Default to first server or global
                    if let Some(sid) = self.state.get_first_server_id().await {
                        DatabaseOwner::Server(sid)
                    } else if let Some(cid) = self.state.get_first_client_id().await {
                        DatabaseOwner::Client(cid)
                    } else {
                        DatabaseOwner::Global
                    }
                };

                // Create database
                match self
                    .state
                    .create_database(
                        name.clone(),
                        db_path.clone(),
                        db_owner.clone(),
                        schema_ddl.as_deref(),
                    )
                    .await
                {
                    Ok(db_id) => {
                        let _ = status_tx.send(format!(
                            "[DB] Created database '{}' ({}) at {} (owner: {})",
                            name, db_id, db_path, db_owner
                        ));

                        // Show schema if provided
                        if let Some(db) = self.state.get_database(db_id).await {
                            if !db.tables.is_empty() {
                                let _ =
                                    status_tx.send(format!("[DB] Schema: {}", db.schema_summary()));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = status_tx.send(format!("[ERROR] Failed to create database: {}", e));
                    }
                }
            }

            #[cfg(feature = "sqlite")]
            CommonAction::DeleteDatabase { database_id } => {
                let db_id = crate::state::DatabaseId::new(database_id);

                match self.state.delete_database(db_id).await {
                    Ok(_) => {
                        let _ = status_tx.send(format!("[DB] Deleted database {}", db_id));
                    }
                    Err(e) => {
                        let _ = status_tx.send(format!("[ERROR] Failed to delete database: {}", e));
                    }
                }
            }

            CommonAction::ShowMessage { message } => {
                let _ = status_tx.send(format!("[CLIENT] {}", message));
            }
            CommonAction::ProvideFeedback { .. } => {
                // ProvideFeedback is handled by the action executor, not here
                // This match arm exists to satisfy exhaustiveness checking
            }
        }

        Ok(())
    }

    /// Parse event handlers from JSON array into EventHandlerConfig
    ///
    /// Static handlers are validated here rather than at the first packet:
    /// * every action name must exist in the action catalog of the protocol(s) that
    ///   declare an event matching the handler's `event_pattern` (see
    ///   [`action_catalog_for_pattern`]), and
    /// * every `{{event.…}}` reference must be well formed
    ///   ([`EventHandlerType::validate`]).
    ///
    /// Both used to fail silently at dispatch time — the peer got the protocol default,
    /// no error reached the caller, and the access log recorded the action as though it
    /// had run. Reporting them here means `start_server` / `open_server` rejects the
    /// configuration outright.
    pub fn parse_event_handlers(
        handlers_json: Vec<serde_json::Value>,
    ) -> Result<crate::scripting::EventHandlerConfig> {
        use crate::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};

        let mut config = EventHandlerConfig::new();

        for handler_json in handlers_json {
            // Parse event_pattern field
            let event_pattern = if let Some(pattern_str) =
                handler_json.get("event_pattern").and_then(|v| v.as_str())
            {
                EventPattern::from(pattern_str)
            } else {
                // Default to wildcard if not specified
                EventPattern::wildcard()
            };

            // Parse handler field
            let handler_type_json = handler_json.get("handler").ok_or_else(|| {
                anyhow::anyhow!("Missing 'handler' field in event handler configuration")
            })?;

            let handler_type_str = handler_type_json
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing 'type' field in handler configuration"))?;

            let handler_type = match handler_type_str {
                "llm" => {
                    let instruction = handler_type_json
                        .get("instruction")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!("Missing 'instruction' field for llm handler - instruction is required for LLM event handlers")
                        })?;
                    EventHandlerType::llm(instruction)
                }
                "script" => {
                    let language = handler_type_json
                        .get("language")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!("Missing 'language' field for script handler")
                        })?;
                    if crate::llm::event_handler_executor::parse_script_language(language).is_none()
                    {
                        anyhow::bail!(
                            "Unknown script language '{}' for script handler; accepted: {}",
                            language,
                            crate::llm::event_handler_executor::SCRIPT_LANGUAGE_TOKENS
                        );
                    }
                    let code = handler_type_json
                        .get("code")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!("Missing 'code' field for script handler")
                        })?;
                    // Opt-in resident (persistent) mode: keeps one interpreter
                    // alive per scope so in-process state survives across events.
                    let resident = handler_type_json
                        .get("resident")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if resident {
                        let scope = handler_type_json
                            .get("scope")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        EventHandlerType::script_resident(language, code, scope)
                    } else {
                        EventHandlerType::script(language, code)
                    }
                }
                "static" => {
                    let actions = handler_type_json
                        .get("actions")
                        .and_then(|v| v.as_array())
                        .ok_or_else(|| {
                            anyhow::anyhow!("Missing or invalid 'actions' field for static handler")
                        })?;
                    EventHandlerType::static_response(actions.clone())
                }
                // A human answers each matched event at the dashboard; no answer
                // within the timeout fails closed.
                "manual" => {
                    let timeout_secs = match handler_type_json.get("timeout_secs") {
                        None => crate::scripting::DEFAULT_MANUAL_TIMEOUT_SECS,
                        Some(v) => v.as_u64().filter(|t| *t > 0).ok_or_else(|| {
                            anyhow::anyhow!(
                                "'timeout_secs' for a manual handler must be a positive integer \
                                 number of seconds"
                            )
                        })?,
                    };
                    EventHandlerType::manual(timeout_secs)
                }
                _ => anyhow::bail!("Unknown handler type: {}", handler_type_str),
            };

            // Reject a malformed `{{event.…}}` reference now rather than at the first
            // packet. Only the shape is checkable without an event; whether a well-formed
            // reference resolves is decided by `interpolate_actions` at dispatch.
            //
            // The *field name* of a well-formed reference is deliberately NOT checked
            // here, even though a specific `event_pattern` resolves to an event type whose
            // `parameters` list looks like the right oracle. It is not one yet: several
            // protocols emit event data keys they never declare — `http_request` declares
            // `method`/`path`/`query_string`/`query`/`headers` but also emits `body`,
            // `body_bytes` and `body_is_binary` (`src/server/http/mod.rs`) — so rejecting
            // undeclared names would break handlers that work today. This becomes
            // checkable once every protocol's declared `parameters` are known to cover the
            // keys it actually emits.
            handler_type.validate().map_err(|e| {
                anyhow::anyhow!(
                    "Invalid event handler for {}: {}",
                    describe_pattern(&event_pattern),
                    e
                )
            })?;

            // Reject action names the protocol cannot execute.
            if let EventHandlerType::Static { ref actions } = handler_type {
                validate_static_action_names(&event_pattern, actions)?;
            }

            config.add_handler(EventHandler::new(event_pattern, handler_type));
        }

        Ok(config)
    }

    async fn handle_quit(&mut self, ui: &mut App) -> Result<()> {
        ui.add_llm_message("Quitting...".to_string());
        // The main event loop will handle the actual quit
        Ok(())
    }

    async fn handle_stop_all(&mut self, ui: &mut App) -> Result<()> {
        use crate::state::client::ClientStatus;
        use crate::state::server::ServerStatus;

        ui.add_llm_message("Stopping all servers, connections, and clients...".to_string());

        // Stop all servers
        let server_ids: Vec<_> = self.state.get_all_server_ids().await;
        for server_id in server_ids {
            self.state
                .update_server_status(server_id, ServerStatus::Stopped)
                .await;
            self.state.cleanup_server_tasks(server_id).await;
            crate::scripting::ResidentScriptManager::shutdown_server(server_id.as_u32()).await;
            ui.add_llm_message(format!("[SERVER] Stopped server #{}", server_id.as_u32()));
        }

        // Stop all clients
        let client_ids: Vec<_> = self.state.get_all_client_ids().await;
        for client_id in client_ids {
            self.state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            self.state.cleanup_client_tasks(client_id).await;
            ui.add_llm_message(format!("[CLIENT] Stopped client #{}", client_id.as_u32()));
        }

        ui.add_llm_message("All servers and clients stopped.".to_string());
        Ok(())
    }

    async fn handle_stop_by_id(&mut self, id: u32, ui: &mut App) -> Result<()> {
        use crate::server::connection::ConnectionId;
        use crate::state::client::{ClientId, ClientStatus};
        use crate::state::server::{ServerId, ServerStatus};

        // Try to find what type of entity this ID corresponds to
        let mut found = false;

        // Check if it's a server
        let server_id = ServerId::new(id);
        if self.state.get_server(server_id).await.is_some() {
            self.state
                .update_server_status(server_id, ServerStatus::Stopped)
                .await;
            self.state.cleanup_server_tasks(server_id).await;
            ui.add_llm_message(format!("[SERVER] Stopped server #{}", id));
            found = true;
        }

        // Check if it's a client
        let client_id = ClientId::new(id);
        if self.state.get_client(client_id).await.is_some() {
            self.state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            self.state.cleanup_client_tasks(client_id).await;
            ui.add_llm_message(format!("[CLIENT] Stopped client #{}", id));
            found = true;
        }

        // Check if it's a connection
        let connection_id = ConnectionId::new(id);
        let all_servers = self.state.get_all_servers().await;
        for server in all_servers {
            if server.connections.contains_key(&connection_id) {
                self.state
                    .close_connection_on_server(server.id, connection_id)
                    .await;
                ui.add_llm_message(format!(
                    "[CONNECTION] Closed connection #{} on server #{}",
                    id,
                    server.id.as_u32()
                ));
                found = true;
                break;
            }
        }

        if !found {
            ui.add_llm_message(format!(
                "No server, client, or connection found with ID #{}",
                id
            ));
        }

        Ok(())
    }

    async fn handle_status(&mut self, ui: &mut App) -> Result<()> {
        let summary = self.state.get_summary().await;
        ui.add_llm_message(format!("Status: {summary}"));

        // Show instruction for first server
        if let Some(server_id) = self.state.get_first_server_id().await {
            if let Some(instruction) = self.state.get_instruction(server_id).await {
                if !instruction.is_empty() {
                    ui.add_llm_message(format!(
                        "Server #{} instruction: {}",
                        server_id.as_u32(),
                        instruction
                    ));
                }
            }
        } else {
            ui.add_llm_message("No servers running".to_string());
        }

        Ok(())
    }

    async fn handle_show_model(&mut self, ui: &mut App) -> Result<()> {
        let current_model = self
            .state
            .get_ollama_model()
            .await
            .unwrap_or_else(|| "None".to_string());

        ui.add_llm_message(format!("Current model: {current_model}"));
        ui.add_llm_message("".to_string());
        ui.add_llm_message("Fetching available models...".to_string());

        // Fetch model list from Ollama
        match self.llm.list_models().await {
            Ok(models) => {
                if models.is_empty() {
                    ui.add_llm_message("No models found. Please pull a model first.".to_string());
                    ui.add_llm_message("Example: ollama pull llama3.2".to_string());
                } else {
                    ui.add_llm_message(format!("Available models ({}):", models.len()));
                    for model in &models {
                        if model == &current_model {
                            ui.add_llm_message(format!("  * {model} (current)"));
                        } else {
                            ui.add_llm_message(format!("    {model}"));
                        }
                    }
                    ui.add_llm_message("".to_string());
                    ui.add_llm_message("To change model, use: /model <name>".to_string());
                }
            }
            Err(e) => {
                ui.add_llm_message(format!("Failed to fetch models: {e}"));
                ui.add_llm_message("Make sure Ollama is running.".to_string());
            }
        }

        Ok(())
    }

    async fn handle_change_model(&mut self, model: String, ui: &mut App) -> Result<()> {
        // Validate model exists
        match self.llm.list_models().await {
            Ok(models) => {
                if models.contains(&model) {
                    self.state.set_ollama_model(Some(model.clone())).await;
                    ui.add_llm_message(format!("✓ Changed model to: {model}"));
                } else {
                    ui.add_llm_message(format!("✗ Model '{model}' not found"));
                    ui.add_llm_message("".to_string());

                    if models.is_empty() {
                        ui.add_llm_message("No models available. Pull a model first:".to_string());
                        ui.add_llm_message("  ollama pull llama3.2".to_string());
                    } else {
                        ui.add_llm_message("Available models:".to_string());
                        for available_model in &models {
                            ui.add_llm_message(format!("  {available_model}"));
                        }
                        ui.add_llm_message("".to_string());
                        ui.add_llm_message("Or pull the model:".to_string());
                        ui.add_llm_message(format!("  ollama pull {model}"));
                    }
                }
            }
            Err(e) => {
                ui.add_llm_message(format!("Failed to validate model: {e}"));
                ui.add_llm_message("Make sure Ollama is running.".to_string());
            }
        }

        Ok(())
    }

    async fn handle_show_backend(&mut self, ui: &mut App) -> Result<()> {
        let backend_type = self.llm.backend_type();
        let backend_url = self.llm.backend_url();
        let current_model = self
            .state
            .get_ollama_model()
            .await
            .unwrap_or_else(|| "None".to_string());

        ui.add_llm_message(format!("LLM Backend: {}", backend_type));
        ui.add_llm_message(format!("  URL: {}", backend_url));
        ui.add_llm_message(format!("  Model: {}", current_model));
        ui.add_llm_message("".to_string());
        ui.add_llm_message("To switch backend:".to_string());
        ui.add_llm_message("  /backend ollama [url]              - Switch to Ollama".to_string());
        ui.add_llm_message(
            "  /backend openai <url> [api-key]    - Switch to OpenAI-compatible".to_string(),
        );
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_set_backend(&mut self, args: String, ui: &mut App) -> Result<()> {
        let parts: Vec<&str> = args.splitn(3, ' ').collect();

        match parts.first().map(|s| s.to_lowercase()).as_deref() {
            Some("ollama") => {
                let url = parts.get(1).unwrap_or(&"http://localhost:11434");
                let new_client = crate::llm::OllamaClient::new(url.to_string())
                    .with_app_state(self.state.clone());
                self.llm = new_client.clone();
                self.state.set_llm_client(new_client).await;
                ui.add_llm_message(format!("✓ Switched to Ollama backend: {}", url));
                ui.add_llm_message("  Use /model to list and select a model.".to_string());
            }
            Some("openai") => {
                if parts.len() < 2 {
                    ui.add_llm_message("✗ Usage: /backend openai <url> [api-key]".to_string());
                    ui.add_llm_message("  The API key can also be set via NETGET_API_KEY or OPENAI_API_KEY env vars.".to_string());
                    return Ok(());
                }
                let url = parts[1];
                let api_key = if parts.len() >= 3 {
                    parts[2].to_string()
                } else {
                    // Try env vars
                    std::env::var("NETGET_API_KEY")
                        .or_else(|_| std::env::var("OPENAI_API_KEY"))
                        .unwrap_or_default()
                };
                if api_key.is_empty() {
                    ui.add_llm_message("✗ API key required. Provide as third argument or set NETGET_API_KEY/OPENAI_API_KEY env var.".to_string());
                    return Ok(());
                }
                let new_client = crate::llm::OllamaClient::new_openai(url, &api_key)
                    .with_app_state(self.state.clone());
                self.llm = new_client.clone();
                self.state.set_llm_client(new_client).await;
                ui.add_llm_message(format!("✓ Switched to OpenAI-compatible backend: {}", url));
                ui.add_llm_message("  Use /model <name> to set the model.".to_string());
            }
            _ => {
                ui.add_llm_message("✗ Unknown backend. Use: /backend ollama [url] or /backend openai <url> [api-key]".to_string());
            }
        }
        Ok(())
    }

    /// The browser build has exactly one backend, the page's LLM bridge, so there is nothing
    /// to switch to.
    #[cfg(target_arch = "wasm32")]
    async fn handle_set_backend(&mut self, _args: String, ui: &mut App) -> Result<()> {
        ui.add_llm_message(
            "✗ The browser build talks to the page's model bridge; pick the model on the page."
                .to_string(),
        );
        Ok(())
    }

    async fn handle_show_docs(&mut self, protocol: Option<String>, ui: &mut App) -> Result<()> {
        use crate::docs;

        if let Some(protocol_name) = protocol {
            // Show detailed docs for specific protocol
            match docs::show_protocol_docs(&protocol_name) {
                Ok(docs_text) => {
                    // Split into lines and add each line to the UI
                    for line in docs_text.lines() {
                        ui.add_llm_message(line.to_string());
                    }
                }
                Err(err_msg) => {
                    ui.add_llm_message(err_msg);
                }
            }
        } else {
            // List all protocols
            let docs_text = docs::list_all_protocols();
            for line in docs_text.lines() {
                ui.add_llm_message(line.to_string());
            }
        }

        Ok(())
    }

    /// Handle show environment command - display environment information
    async fn handle_show_environment(&mut self, ui: &mut App) -> Result<()> {
        use crate::protocol::{registry, CLIENT_REGISTRY};

        ui.add_llm_message("".to_string());
        ui.add_llm_message("=== NetGet Environment ===".to_string());
        ui.add_llm_message("".to_string());

        // System information
        ui.add_llm_message("System Information:".to_string());
        ui.add_llm_message(format!("  OS: {}", std::env::consts::OS));
        ui.add_llm_message(format!("  Architecture: {}", std::env::consts::ARCH));
        ui.add_llm_message(format!(
            "  Rust Version: {}",
            env!("CARGO_PKG_RUST_VERSION", "unknown")
        ));
        ui.add_llm_message(format!("  NetGet Version: {}", env!("CARGO_PKG_VERSION")));
        ui.add_llm_message("".to_string());

        // LLM configuration
        let model = self
            .state
            .get_ollama_model()
            .await
            .unwrap_or_else(|| "None".to_string());
        let web_search_mode = self.state.get_web_search_mode().await;
        let scripting_mode = self.state.get_selected_scripting_mode().await;

        ui.add_llm_message("LLM Configuration:".to_string());
        ui.add_llm_message(format!("  Ollama Model: {}", model));
        ui.add_llm_message(format!("  Web Search: {}", web_search_mode.as_str()));
        ui.add_llm_message(format!("  Scripting: {}", scripting_mode.as_str()));
        ui.add_llm_message("".to_string());

        // Get system capabilities
        let caps = self.state.get_system_capabilities().await;

        // Check server protocols
        let server_excluded = registry().get_excluded_protocols(&caps);
        let server_available = registry().get_available_protocols(&caps);

        // Check client protocols
        let client_excluded = CLIENT_REGISTRY.get_excluded_protocols(&caps);
        let client_available = CLIENT_REGISTRY.get_available_protocols(&caps);

        // System capabilities summary
        ui.add_llm_message("System Capabilities:".to_string());
        ui.add_llm_message(format!(
            "  Root Access: {}",
            if caps.is_root { "Yes" } else { "No" }
        ));
        ui.add_llm_message(format!(
            "  Privileged Ports (<1024): {}",
            if caps.can_bind_privileged_ports {
                "Yes"
            } else {
                "No"
            }
        ));
        ui.add_llm_message(format!(
            "  Raw Socket Access (pcap): {}",
            if caps.has_raw_socket_access {
                "Yes"
            } else {
                "No"
            }
        ));
        ui.add_llm_message("".to_string());

        // Summary
        let total_server_protocols = server_available.len() + server_excluded.len();
        let total_client_protocols = client_available.len() + client_excluded.len();

        ui.add_llm_message(format!(
            "Server Protocols: {} available, {} excluded (total {})",
            server_available.len(),
            server_excluded.len(),
            total_server_protocols
        ));
        ui.add_llm_message(format!(
            "Client Protocols: {} available, {} excluded (total {})",
            client_available.len(),
            client_excluded.len(),
            total_client_protocols
        ));
        ui.add_llm_message("".to_string());

        // Show excluded protocols if any
        if !server_excluded.is_empty() {
            ui.add_llm_message("Excluded Server Protocols:".to_string());
            let mut excluded_names: Vec<_> = server_excluded.keys().cloned().collect();
            excluded_names.sort();

            for protocol_name in excluded_names {
                if let Some(missing_deps) = server_excluded.get(&protocol_name) {
                    ui.add_llm_message(format!("  {}", protocol_name));
                    for dep in missing_deps {
                        ui.add_llm_message(format!("    ✗ {}: {}", dep.name(), dep.description()));
                        ui.add_llm_message(format!("      → {}", dep.installation_hint()));
                    }
                }
            }
            ui.add_llm_message("".to_string());
        }

        if !client_excluded.is_empty() {
            ui.add_llm_message("Excluded Client Protocols:".to_string());
            let mut excluded_names: Vec<_> = client_excluded.keys().cloned().collect();
            excluded_names.sort();

            for protocol_name in excluded_names {
                if let Some(missing_deps) = client_excluded.get(&protocol_name) {
                    ui.add_llm_message(format!("  {}", protocol_name));
                    for dep in missing_deps {
                        ui.add_llm_message(format!("    ✗ {}: {}", dep.name(), dep.description()));
                        ui.add_llm_message(format!("      → {}", dep.installation_hint()));
                    }
                }
            }
            ui.add_llm_message("".to_string());
        }

        if server_excluded.is_empty() && client_excluded.is_empty() {
            ui.add_llm_message("✓ All protocols are available!".to_string());
            ui.add_llm_message("".to_string());
        }

        Ok(())
    }

    async fn handle_save(&mut self, name: String, id: Option<u32>, ui: &mut App) -> Result<()> {
        use crate::state::client::ClientId;
        use crate::state::server::ServerId;
        use crate::utils::save_load;

        let path = if let Some(id_val) = id {
            // Save specific server or client by ID
            // Try server first
            let server_id = ServerId::new(id_val);
            if self.state.get_server(server_id).await.is_some() {
                match save_load::save_server(&self.state, server_id, &name).await {
                    Ok(path) => {
                        ui.add_llm_message(format!(
                            "[SAVE] Saved server #{} to: {}",
                            id_val,
                            path.display()
                        ));
                        path
                    }
                    Err(e) => {
                        ui.add_llm_message(format!(
                            "[ERROR] Failed to save server #{}: {}",
                            id_val, e
                        ));
                        return Ok(());
                    }
                }
            } else {
                // Try client
                let client_id = ClientId::new(id_val);
                if self.state.get_client(client_id).await.is_some() {
                    match save_load::save_client(&self.state, client_id, &name).await {
                        Ok(path) => {
                            ui.add_llm_message(format!(
                                "[SAVE] Saved client #{} to: {}",
                                id_val,
                                path.display()
                            ));
                            path
                        }
                        Err(e) => {
                            ui.add_llm_message(format!(
                                "[ERROR] Failed to save client #{}: {}",
                                id_val, e
                            ));
                            return Ok(());
                        }
                    }
                } else {
                    ui.add_llm_message(format!(
                        "[ERROR] No server or client found with ID #{}",
                        id_val
                    ));
                    return Ok(());
                }
            }
        } else {
            // Save all servers and clients
            match save_load::save_all(&self.state, &name).await {
                Ok(path) => {
                    let servers = self.state.get_all_servers().await;
                    let clients = self.state.get_all_clients().await;
                    ui.add_llm_message(format!(
                        "[SAVE] Saved {} server(s) and {} client(s) to: {}",
                        servers.len(),
                        clients.len(),
                        path.display()
                    ));
                    path
                }
                Err(e) => {
                    ui.add_llm_message(format!("[ERROR] Failed to save configuration: {}", e));
                    return Ok(());
                }
            }
        };

        ui.add_llm_message(format!(
            "[INFO] Use '/load {}' to restore this configuration",
            path.display()
        ));
        Ok(())
    }

    async fn handle_load(&mut self, name: String, ui: &mut App) -> Result<()> {
        use crate::utils::save_load;

        // Load actions from file
        let actions = match save_load::load_actions(&name).await {
            Ok(actions) => actions,
            Err(e) => {
                ui.add_llm_message(format!("[ERROR] Failed to load file '{}': {}", name, e));
                return Ok(());
            }
        };

        if actions.is_empty() {
            ui.add_llm_message(format!("[WARN] File '{}' contains no actions", name));
            return Ok(());
        }

        ui.add_llm_message(format!(
            "[LOAD] Loading {} action(s) from: {}",
            actions.len(),
            save_load::normalize_filename(&name)
        ));

        // Execute each action
        for (i, action) in actions.iter().enumerate() {
            if action.get("type").and_then(serde_json::Value::as_str) == Some("restore_session") {
                match save_load::restore_session(&self.state, &self.llm, &action["session"]).await {
                    Ok(()) => ui.add_llm_message("[LOAD] Restored session relationships".into()),
                    Err(error) => {
                        ui.add_llm_message(format!("[ERROR] Session restoration failed: {error:#}"))
                    }
                }
                continue;
            }

            // Try to parse as common action
            if let Ok(common_action) = crate::llm::actions::common::CommonAction::from_json(action)
            {
                use crate::llm::actions::common::CommonAction;

                match common_action {
                    CommonAction::OpenServer {
                        mac_address,
                        interface,
                        host,
                        port,
                        protocol,
                        send_first,
                        initial_memory,
                        instruction,
                        startup_params,
                        event_handlers,
                        scheduled_tasks,
                        feedback_instructions,
                        history,
                        batching,
                    } => {
                        // Create status channel for server startup messages
                        // Messages will be logged via tracing macros in the spawn method
                        let (status_tx, _status_rx) = mpsc::unbounded_channel();

                        // Execute open_server action via server startup
                        match server_startup::start_server_from_action(
                            &self.state,
                            mac_address,
                            interface.clone(),
                            host,
                            port,
                            &protocol,
                            send_first,
                            initial_memory,
                            instruction.clone(),
                            startup_params,
                            event_handlers,
                            scheduled_tasks,
                            feedback_instructions,
                            crate::protocol::metadata::ConversationOverrides { history, batching },
                            status_tx,
                        )
                        .await
                        {
                            Ok(server_id) => {
                                let binding_desc = if let Some(iface) = &interface {
                                    format!("interface {} ({})", iface, protocol)
                                } else if let Some(p) = port {
                                    format!("port {} ({})", p, protocol)
                                } else {
                                    format!("({})", protocol)
                                };
                                ui.add_llm_message(format!(
                                    "[LOAD] Opened server #{} on {}",
                                    server_id.as_u32(),
                                    binding_desc
                                ));
                            }
                            Err(e) => {
                                ui.add_llm_message(format!(
                                    "[ERROR] Failed to open server (action {}): {}",
                                    i + 1,
                                    e
                                ));
                            }
                        }
                    }
                    CommonAction::OpenClient {
                        protocol,
                        remote_addr,
                        instruction,
                        startup_params,
                        initial_memory,
                        event_handlers,
                        scheduled_tasks,
                        feedback_instructions,
                        history,
                        batching,
                    } => {
                        // Execute open_client action via client startup
                        use crate::cli::client_startup;

                        match client_startup::start_client_from_action(
                            &self.state,
                            &protocol,
                            &remote_addr,
                            instruction.clone(),
                            startup_params,
                            initial_memory,
                            event_handlers,
                            scheduled_tasks,
                            feedback_instructions,
                            crate::protocol::metadata::ConversationOverrides { history, batching },
                            self.llm.clone(),
                            None, // status_tx: /load path, drain to tracing
                        )
                        .await
                        {
                            Ok(client_id) => {
                                ui.add_llm_message(format!(
                                    "[LOAD] Opened client #{} to {} ({})",
                                    client_id.as_u32(),
                                    remote_addr,
                                    protocol
                                ));
                            }
                            Err(e) => {
                                ui.add_llm_message(format!(
                                    "[ERROR] Failed to open client (action {}): {}",
                                    i + 1,
                                    e
                                ));
                            }
                        }
                    }
                    _ => {
                        ui.add_llm_message(format!(
                            "[WARN] Skipping unsupported action type (action {})",
                            i + 1
                        ));
                    }
                }
            } else {
                ui.add_llm_message(format!("[WARN] Skipping invalid action (action {})", i + 1));
            }
        }

        ui.add_llm_message("[LOAD] Configuration loaded successfully".to_string());
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    async fn handle_sqlite(
        &mut self,
        db_id: Option<u32>,
        query: Option<String>,
        ui: &mut App,
    ) -> Result<()> {
        match (db_id, query) {
            (None, None) => {
                // List all databases
                let databases = self.state.get_all_databases().await;
                if databases.is_empty() {
                    ui.add_llm_message("[DB] No databases".to_string());
                } else {
                    ui.add_llm_message(format!("[DB] {} database(s):", databases.len()));
                    for db in databases {
                        ui.add_llm_message(format!("  {}", db.schema_summary()));
                    }
                }
            }
            (Some(id), None) => {
                // Show schema for specific database
                let db_id_obj = crate::state::DatabaseId::new(id);
                if let Some(db) = self.state.get_database(db_id_obj).await {
                    ui.add_llm_message(format!("[DB] Database {}:", db_id_obj));
                    ui.add_llm_message(db.schema_summary());
                } else {
                    ui.add_llm_message(format!("[ERROR] Database {} not found", db_id_obj));
                }
            }
            (Some(id), Some(sql)) => {
                // Execute query on specific database
                let db_id_obj = crate::state::DatabaseId::new(id);
                match self.state.execute_sql(db_id_obj, &sql).await {
                    Ok(result) => {
                        let formatted = result.format();
                        ui.add_llm_message(format!("[DB] Query result:\n{}", formatted));
                    }
                    Err(e) => {
                        ui.add_llm_message(format!("[ERROR] SQL error: {}", e));
                    }
                }
            }
            (None, Some(sql)) => {
                // Execute query on first database
                let databases = self.state.get_all_databases().await;
                if databases.is_empty() {
                    ui.add_llm_message("[ERROR] No databases available".to_string());
                } else {
                    let db_id = databases[0].id;
                    match self.state.execute_sql(db_id, &sql).await {
                        Ok(result) => {
                            let formatted = result.format();
                            ui.add_llm_message(format!("[DB] Query result:\n{}", formatted));
                        }
                        Err(e) => {
                            ui.add_llm_message(format!("[ERROR] SQL error: {}", e));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Static event-handler validation
// ---------------------------------------------------------------------------

/// Common action names the executor handles itself, before any protocol is consulted.
///
/// Mirrors the variants of [`crate::llm::CommonAction`]; an action naming one of these is
/// valid for every protocol, so it must never be rejected as unknown.
const COMMON_ACTION_NAMES: &[&str] = &[
    "show_message",
    "open_server",
    "close_server",
    "close_all_servers",
    "open_client",
    "close_client",
    "close_all_clients",
    "close_connection_by_id",
    "reconnect_client",
    "update_client_instruction",
    "update_instruction",
    "change_model",
    "set_memory",
    "append_memory",
    "append_to_log",
    "schedule_task",
    "cancel_task",
    "provide_feedback",
    #[cfg(feature = "sqlite")]
    "create_database",
    #[cfg(feature = "sqlite")]
    "delete_database",
];

/// The action names every protocol accepts (the [`crate::llm::CommonAction`] variants), for
/// callers outside this module that validate a handler-shaped answer — the MCP
/// `answer_intercept` tool holds an operator's answer to the same rule a static handler is
/// held to here.
pub fn common_action_names() -> &'static [&'static str] {
    COMMON_ACTION_NAMES
}

/// How many valid action names to spell out in an error before summarising the rest.
const MAX_LISTED_ACTIONS: usize = 40;

/// The set of action names a handler for `pattern` is allowed to use, plus a label
/// describing where that set came from.
struct ActionCatalog {
    /// Valid action names, sorted
    names: std::collections::BTreeSet<String>,
    /// Human-readable scope, e.g. `TCP` or `TCP, HTTP`
    scope: String,
}

/// Render an event pattern for an error message.
fn describe_pattern(pattern: &crate::scripting::EventPattern) -> String {
    use crate::scripting::EventPattern;
    match pattern {
        EventPattern::Specific(id) => format!("event '{}'", id),
        EventPattern::Wildcard => "the wildcard event pattern".to_string(),
    }
}

/// Collect every action name a **server** can execute in response to an event matching
/// `pattern`, or `None` if the protocol declares no event matching it.
///
/// `get_sync_actions()` is the protocol-wide catalog for event responses; each matching
/// event type may additionally advertise its own actions, so both are unioned.
///
/// `get_async_actions()` is deliberately **not** part of it, and this is the asymmetry a
/// future reader will be tempted to "fix": a server has two LLM entry points, so its
/// async/sync split is a real statement about what may answer a network event. TCP's
/// `close_connection` takes a `connection_id` and is a user-driven action against the server;
/// the verb for hanging up on the peer whose event this is, is `close_this_connection`. SSH's
/// `ssh_auth` narrows to `ssh_auth_decision` for the same reason. A handler answering an event
/// is in the sync position, so it is held to the sync vocabulary.
///
/// Clients are the opposite case and go through
/// [`crate::llm::actions::client_trait::client_action_names_for_pattern`] — see the note there.
fn server_actions_for_pattern(
    protocol: &dyn crate::llm::actions::protocol_trait::Protocol,
    pattern: &crate::scripting::EventPattern,
) -> Option<Vec<String>> {
    let event_types = protocol.get_event_types();
    let matching: Vec<_> = event_types
        .iter()
        .filter(|et| pattern.matches(&et.id))
        .collect();
    if matching.is_empty() {
        return None;
    }

    let mut names: Vec<String> = protocol
        .get_sync_actions()
        .into_iter()
        .map(|a| a.name)
        .collect();
    for event_type in matching {
        names.extend(event_type.actions.iter().map(|a| a.name.clone()));
    }
    Some(names)
}

/// Build the action catalog for a handler's event pattern.
///
/// Protocols are matched by the events they declare: a pattern of `tcp_data_received`
/// resolves to TCP alone and yields TCP's catalog; a wildcard pattern matches every
/// protocol and yields the union. Both server and client registries are consulted because
/// Name the `open_server` / `open_client` parameter an event-handler parse error refers to.
///
/// The error surfaces to the model inside `InvalidActionParameters`, whose whole value is
/// telling it *which* field to correct. This mapping was written out inline at both call
/// sites; identical logic in two places drifts, and the two paths must name the same field
/// for the same failure or the model is taught that the two actions differ when they do not.
fn event_handler_parameter_name(error_msg: &str) -> &'static str {
    if error_msg.contains("instruction") {
        "event_handlers[].handler.instruction"
    } else if error_msg.contains("event_handlers") {
        "event_handlers"
    } else {
        "unknown"
    }
}

/// The `AppState` used to enumerate a client's async actions while validating handlers.
///
/// `Protocol::get_async_actions` takes an `&AppState` and `parse_event_handlers` has none —
/// it is an associated function that validates a configuration, called before anything is
/// started. Building one per handler is out of the question: `AppState::new()` shells out to
/// `python3`, `node`, `go` and `perl` to detect the scripting environments and probes the
/// process's raw-socket capabilities, which is why `server_registry::register_protocols` also
/// builds a single shared dummy one. So this is built at most once per process, and only if a
/// static handler is actually validated.
///
/// Passing a state that is not the live one is sound *for enumerating names*: no client reads
/// it (all 100 `get_async_actions` implementations take `_state`), and a client whose
/// vocabulary varied with live state could not be validated ahead of start-up by any means.
fn catalog_state() -> &'static AppState {
    static CATALOG_STATE: std::sync::OnceLock<AppState> = std::sync::OnceLock::new();
    CATALOG_STATE.get_or_init(AppState::new)
}

/// `parse_event_handlers` serves `start_server` and `start_client` alike.
///
/// Protocols are matched by the events they declare, so a specific pattern resolves to the
/// protocol(s) that raise that event and a wildcard pattern matches every protocol in both
/// registries and yields the union of their catalogs. The union is what makes a wildcard
/// handler usable at all — the caller starts one instance, of one protocol, and the pattern
/// says nothing about which — and it is why a wildcard catalog is necessarily broader than
/// any one protocol's: validation here rejects a name *no* candidate protocol could execute,
/// which is the typo case it exists for.
///
/// Server and client contributions are gathered by different rules, and the difference is
/// deliberate: see [`server_actions_for_pattern`] (narrowing) and
/// [`crate::llm::actions::client_trait::client_action_names_for_pattern`] (union). For a
/// wildcard that matches both a server and a client this means the server contributes its
/// sync vocabulary and the client its whole one, which is exactly what each of them would
/// accept when the event fires.
///
/// If no compiled protocol declares a matching event (an event id we do not know about),
/// the catalog is empty and validation is skipped rather than rejecting the handler.
fn action_catalog_for_pattern(pattern: &crate::scripting::EventPattern) -> ActionCatalog {
    let mut names: std::collections::BTreeSet<String> = COMMON_ACTION_NAMES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let mut scopes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (_, protocol) in crate::protocol::server_registry::registry().all_protocols() {
        if let Some(actions) = server_actions_for_pattern(protocol.as_ref(), pattern) {
            scopes.insert(protocol.protocol_name().to_string());
            names.extend(actions);
        }
    }

    for protocol in crate::protocol::client_registry::CLIENT_REGISTRY.get_all() {
        if let Some(actions) = crate::llm::actions::client_trait::client_action_names_for_pattern(
            protocol.as_ref(),
            catalog_state(),
            pattern,
        ) {
            scopes.insert(protocol.protocol_name().to_string());
            names.extend(actions);
        }
    }

    if scopes.is_empty() {
        // Nothing declares this event: no catalog to validate against.
        return ActionCatalog {
            names: std::collections::BTreeSet::new(),
            scope: String::new(),
        };
    }

    let scope = scopes.into_iter().collect::<Vec<_>>().join(", ");
    ActionCatalog { names, scope }
}

/// Reject static handler actions whose `type` no matching protocol can execute.
///
/// Without this a typo'd action name is accepted by `start_server` and only surfaces when
/// the first packet arrives — where it produces no response at all.
fn validate_static_action_names(
    pattern: &crate::scripting::EventPattern,
    actions: &[serde_json::Value],
) -> Result<()> {
    let catalog = action_catalog_for_pattern(pattern);
    if catalog.names.is_empty() {
        // No protocol declares an event matching this pattern; nothing to check against.
        return Ok(());
    }

    for action in actions {
        let Some(name) = action.get("type").and_then(|v| v.as_str()) else {
            anyhow::bail!(
                "Static handler action for {} has no \"type\" field: {}",
                describe_pattern(pattern),
                action
            );
        };

        if catalog.names.contains(name) {
            continue;
        }

        let listed: Vec<&str> = catalog
            .names
            .iter()
            .take(MAX_LISTED_ACTIONS)
            .map(|s| s.as_str())
            .collect();
        let overflow = catalog.names.len().saturating_sub(listed.len());
        let mut valid = listed.join(", ");
        if overflow > 0 {
            valid.push_str(&format!(", … ({} more)", overflow));
        }

        anyhow::bail!(
            "Unknown action \"{}\" in the static handler for {}. \
             Valid actions for {}: {}",
            name,
            describe_pattern(pattern),
            catalog.scope,
            valid
        );
    }

    Ok(())
}
