//! LLM integration module
//!
//! Provides integration with Ollama for LLM-driven protocol handling

// New action system
pub mod action_helper;
pub mod actions; // Centralized helper for LLM calls
pub mod agent_queue; // Agent-answered LLM request queue (MCP --llm-agent mode)
pub mod answer_reuse; // Memoisation and record -> rules: reusing the model's answers
pub mod backend_error; // Backend failures (model not installed, unreachable) vs bad model output
pub mod bridge; // Requests handed to a host (the browser page) that owns the model
pub mod circuit_breaker; // Fail-fast guard for an unreachable LLM backend
pub mod conversation; // Conversation-based LLM interaction
pub mod conversation_state; // Conversation history management
pub mod default_instructions; // Default instructions registry
pub mod event_handler_executor; // Event handler execution (script/static/llm)
pub mod event_instructions; // Event-specific instructions
pub mod feedback; // Draining the provide_feedback buffer into call_llm_for_feedback
pub mod model_selection;
pub mod ollama_client;
pub mod prompt;
pub mod rate_limiter; // Rate limiting for LLM calls (concurrency + token throttling)
pub mod reference_parser; // XML reference parser for large content blocks
pub mod response_handler;
pub mod rule_export; // Turning the access log's model answers into event_handlers
pub mod template_engine; // Handlebars template engine // Model selection utilities // Keep the old client module for reference

// Embedded LLM inference (feature-gated)
#[cfg(feature = "embedded-llm")]
pub mod embedded_inference;

// Configuration persistence
pub mod config;

// Hybrid LLM manager (Ollama + embedded fallback)
#[cfg(feature = "embedded-llm")]
pub mod hybrid_manager;

// Re-exports from new action system
pub use actions::{
    common::{
        get_all_common_actions, get_network_event_common_actions, get_user_input_common_actions,
        CommonAction,
    },
    executor::{execute_actions, ActionFailure, ExecutionResult, FAILED_ACTION_TYPE_PREFIX},
    protocol_trait::{ActionResult, Server},
    ActionDefinition, ActionResponse, Parameter,
};

// Re-export action helper functions
pub use action_helper::{
    call_llm_for_client, call_llm_with_actions, call_llm_with_custom_actions,
    call_llm_with_protocol, ClientLlmResult,
};

// Current ollama client exports
pub use ollama_client::{
    accumulate_ollama_stream, accumulate_openai_stream, CommandAction, CommandInterpretation,
    GenerateResponse, HttpLlmResponse, LlmResponse, OllamaClient, OllamaResponseKind,
    OpenAiStreamAcc, SamplingOptions, StreamAccumulation, TokenUsage,
};
pub use prompt::PromptBuilder;
pub use response_handler::{handle_llm_response, ProcessedResponse};

// Conversation handler
pub use conversation::ConversationHandler;

// Conversation state management
pub use conversation_state::{ConversationMessage, ConversationState, MessageRole, MessageType};

// Message type from ollama_client module
pub use ollama_client::Message;

// Agent-answered LLM request queue
pub use agent_queue::{LlmRequestQueue, PendingLlmRequest};

// Host-answered LLM requests (the browser build)
pub use bridge::{BridgeReply, BridgeRequest, BridgeRequestKind, LlmBridge};

// Backend failures, kept apart from bad model output
pub use backend_error::{describe_llm_failure, BackendFailureKind, LlmBackendError};

// LLM backend circuit breaker
pub use circuit_breaker::{
    BreakerOpen, BreakerState, BreakerStatus, CircuitBreaker, DEFAULT_COOLDOWN,
    DEFAULT_FAILURE_THRESHOLD,
};

// Event instructions
pub use default_instructions::{resolve_instructions, DEFAULT_INSTRUCTIONS};
pub use event_instructions::{
    EventInstructions, Example, InstructionSource, ServerInstructionConfig,
};

// Model selection
pub use model_selection::{
    check_ollama_availability, ensure_model_selected, select_or_validate_model, ModelInfo,
};

// Embedded LLM inference (feature-gated exports)
#[cfg(feature = "embedded-llm")]
pub use embedded_inference::{EmbeddedLLMBackend, InferenceConfig};

// Configuration exports
#[cfg(feature = "embedded-llm")]
pub use config::EmbeddedLlmConfig;
pub use config::{LlmBackendType, NetGetConfig, OllamaConfig, OpenAIConfig};

// Hybrid manager exports
#[cfg(feature = "embedded-llm")]
pub use hybrid_manager::{ActiveBackend, HybridLLMManager};

// Rate limiter
pub use rate_limiter::{
    is_overload_error, RateLimitError, RateLimiter, RateLimiterConfig, RateLimiterPermit,
    RateLimiterStats, RequestSource, DEFAULT_MAX_QUEUED, DEFAULT_QUEUE_TIMEOUT_SECS,
};

/// Format text with indentation and ANSI dim styling for log output.
///
/// Each line is prefixed with the specified number of spaces and wrapped
/// with ANSI dim codes (\x1b[2m ... \x1b[0m) for greyed out appearance.
///
/// # Arguments
/// * `text` - The text to format
/// * `indent_spaces` - Number of spaces to indent each line (default: 8)
///
/// # Returns
/// Vec of formatted lines, each indented and dimmed (ready to send via tx.send())
pub fn format_indented_dimmed_lines(text: &str, indent_spaces: usize) -> Vec<String> {
    let indent = " ".repeat(indent_spaces);
    text.lines()
        .map(|line| format!("{}\x1b[2m{}\x1b[0m", indent, line))
        .collect()
}

/// Format text with indentation and ANSI dim styling for log output.
/// Returns a single string with lines joined by newlines (for tracing/debug output).
///
/// # Arguments
/// * `text` - The text to format
/// * `indent_spaces` - Number of spaces to indent each line (default: 8)
///
/// # Returns
/// Formatted string with each line indented and dimmed, joined by \n
pub fn format_indented_dimmed(text: &str, indent_spaces: usize) -> String {
    format_indented_dimmed_lines(text, indent_spaces).join("\n")
}
