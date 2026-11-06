use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// Manages conversation history with token-based size limits
#[derive(Debug, Clone)]
pub struct ConversationState {
    /// Unique conversation ID
    pub conversation_id: String,

    /// Conversation messages (limited by token count)
    pub messages: VecDeque<ConversationMessage>,

    /// Maximum token/character size for history
    pub max_token_size: usize,

    /// Current total size in characters
    pub current_size: usize,

    /// Flag indicating if older messages were removed
    pub truncated: bool,

    /// Conversation metadata
    pub started_at: DateTime<Utc>,
    pub last_interaction: DateTime<Utc>,

    /// Server protocols that have been documented in this conversation
    /// (enables open_server for these protocols)
    pub documented_server_protocols: HashSet<String>,

    /// Client protocols that have been documented in this conversation
    /// (enables open_client for these protocols)
    pub documented_client_protocols: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub timestamp: DateTime<Utc>,
    pub role: MessageRole,
    pub content: String,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    /// User input
    UserInput(String),

    /// LLM response (action JSON or raw if invalid)
    LLMResponse {
        action_json: Option<serde_json::Value>,
        raw_output: String,
    },

    /// Retry instruction (e.g., "Invalid JSON, please retry")
    RetryInstruction(String),

    /// Tool call reference (without content)
    ToolCall {
        tool_name: String,
        description: String, // Brief description, not full content
    },
}

impl ConversationState {
    /// Cap on a single stored message, as a fraction of `max_token_size`.
    ///
    /// `add_message` evicts from the front until the new message fits, so a single message
    /// larger than the whole window emptied the history and was then stored in full anyway —
    /// the window bounded the count of old messages but not the size of a new one. Capping
    /// each message at half the window guarantees at least two messages of history survive
    /// and that `current_size` can never exceed `max_token_size`.
    const MESSAGE_FRACTION: usize = 2;
    const MAX_MESSAGES: usize = 1024;
    pub const MAX_DOCUMENTED_PROTOCOLS: usize = 1024;

    /// Truncate a message payload to the per-message cap, char-safe, marking the cut so the
    /// model is not shown a silently amputated value.
    fn bound_message(&self, content: String) -> String {
        let cap = (self.max_token_size / Self::MESSAGE_FRACTION)
            .max(1)
            .min(self.max_token_size);
        if content.len() <= cap {
            return content;
        }
        let marker = crate::utils::truncate::TRUNCATION_MARKER;
        if cap < marker.len() {
            return crate::utils::truncate_str(&content, cap).to_string();
        }
        crate::utils::truncate_with_suffix(&content, cap - marker.len(), marker)
    }

    /// Create a new conversation state with token size limit
    pub fn new(max_token_size: usize) -> Self {
        let now = Utc::now();
        Self {
            conversation_id: uuid::Uuid::new_v4().to_string(),
            messages: VecDeque::new(),
            max_token_size,
            current_size: 0,
            truncated: false,
            started_at: now,
            last_interaction: now,
            documented_server_protocols: HashSet::new(),
            documented_client_protocols: HashSet::new(),
        }
    }

    /// Add a user input message
    pub fn add_user_input(&mut self, input: String) {
        let input = self.bound_message(input);
        let message = ConversationMessage {
            timestamp: Utc::now(),
            role: MessageRole::User,
            content: input.clone(),
            message_type: MessageType::UserInput(input),
        };
        self.add_message(message);
    }

    /// Add an LLM response message
    pub fn add_llm_response(&mut self, response: String, parsed_action: Option<serde_json::Value>) {
        let response = self.bound_message(response);
        // Parsed metadata is optional context, never a second unlimited history.
        // Drop rejected structures iteratively so a programmatically built deeply
        // nested Value cannot overflow the stack even during rejection.
        let parsed_action = parsed_action.and_then(|value| {
            if crate::utils::json_budget::within_budget(&value, self.max_token_size / 2, 4096, 64) {
                Some(value)
            } else {
                crate::utils::json_budget::drop_iteratively(value);
                None
            }
        });
        let message = ConversationMessage {
            timestamp: Utc::now(),
            role: MessageRole::Assistant,
            content: response.clone(),
            message_type: MessageType::LLMResponse {
                action_json: parsed_action,
                raw_output: response,
            },
        };
        self.add_message(message);
    }

    /// Add a retry instruction message
    pub fn add_retry_instruction(&mut self, instruction: String) {
        let instruction = self.bound_message(instruction);
        let message = ConversationMessage {
            timestamp: Utc::now(),
            role: MessageRole::System,
            content: instruction.clone(),
            message_type: MessageType::RetryInstruction(instruction),
        };
        self.add_message(message);
    }

    /// Add a tool call reference
    pub fn add_tool_call(&mut self, tool_name: String, brief_description: String) {
        let tool_name =
            crate::utils::truncate_str(&tool_name, 128.min(self.max_token_size)).to_owned();
        let brief_description = self.bound_message(brief_description);
        let content =
            self.bound_message(format!("Tool Call - {} ({})", tool_name, brief_description));
        let message = ConversationMessage {
            timestamp: Utc::now(),
            role: MessageRole::System,
            content: content.clone(),
            message_type: MessageType::ToolCall {
                tool_name,
                description: brief_description,
            },
        };
        self.add_message(message);
    }

    /// Add a message and manage size limits
    fn add_message(&mut self, message: ConversationMessage) {
        let message_size = message.content.len();

        // Empty entries consume no byte budget and would otherwise accumulate forever.
        // A zero-sized history disables storage rather than retaining one oversized entry.
        if message_size == 0 {
            return;
        }

        // Remove oldest messages if needed to stay under token limit
        while (self.current_size.saturating_add(message_size) > self.max_token_size
            || self.messages.len() >= Self::MAX_MESSAGES)
            && !self.messages.is_empty()
        {
            if let Some(removed) = self.messages.pop_front() {
                self.current_size = self.current_size.saturating_sub(removed.content.len());
                self.truncated = true;
            }
        }

        // Add the new message
        self.current_size += message_size;
        self.messages.push_back(message);
        self.last_interaction = Utc::now();
    }

    /// Get formatted history for inclusion in prompts
    pub fn get_history_for_prompt(&self) -> String {
        let mut history = String::new();

        // Add truncation notice if needed
        if self.truncated {
            history.push_str("[Note: Earlier messages were removed due to size limits]\n");
        }

        // Include documented protocols at the start of history
        // This ensures the LLM knows which protocols have been documented
        if !self.documented_server_protocols.is_empty()
            || !self.documented_client_protocols.is_empty()
        {
            history.push_str("<documented_protocols>\n");
            if !self.documented_server_protocols.is_empty() {
                let mut protocols: Vec<_> = self.documented_server_protocols.iter().collect();
                protocols.sort();
                history.push_str(&format!(
                    "Server protocols documented: {}\n",
                    protocols
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !self.documented_client_protocols.is_empty() {
                let mut protocols: Vec<_> = self.documented_client_protocols.iter().collect();
                protocols.sort();
                history.push_str(&format!(
                    "Client protocols documented: {}\n",
                    protocols
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            history.push_str("</documented_protocols>\n");
        }

        // Format each message with appropriate tags
        for message in &self.messages {
            match &message.message_type {
                MessageType::UserInput(input) => {
                    history.push_str(&format!("<user>{}</user>\n", input));
                }
                MessageType::LLMResponse {
                    action_json,
                    raw_output,
                } => {
                    if action_json.is_some() {
                        // Valid JSON response
                        history.push_str(&format!("<assistant>{}</assistant>\n", raw_output));
                    } else {
                        // Invalid JSON, show raw output
                        history.push_str(&format!("<assistant>{}</assistant>\n", raw_output));
                    }
                }
                MessageType::RetryInstruction(instruction) => {
                    history.push_str(&format!("<system>Retry - {}</system>\n", instruction));
                }
                MessageType::ToolCall {
                    tool_name,
                    description,
                } => {
                    history.push_str(&format!(
                        "<system>Tool Call - {} ({})</system>\n",
                        tool_name, description
                    ));
                }
            }
        }

        history
    }

    /// Mark server protocols as documented in this conversation
    pub fn mark_server_protocols_documented(&mut self, protocols: &[String]) {
        for protocol in protocols {
            if Self::valid_documented_protocol(protocol)
                && self.documented_server_protocols.len() < Self::MAX_DOCUMENTED_PROTOCOLS
            {
                self.documented_server_protocols.insert(protocol.clone());
            }
        }
    }

    /// Mark client protocols as documented in this conversation
    pub fn mark_client_protocols_documented(&mut self, protocols: &[String]) {
        for protocol in protocols {
            if Self::valid_documented_protocol(protocol)
                && self.documented_client_protocols.len() < Self::MAX_DOCUMENTED_PROTOCOLS
            {
                self.documented_client_protocols.insert(protocol.clone());
            }
        }
    }

    /// Protocol identifiers carry neither markup nor arbitrary document content.
    pub fn valid_documented_protocol(protocol: &str) -> bool {
        !protocol.is_empty()
            && protocol.len() <= 128
            && protocol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    /// Get all documented server protocols
    pub fn get_documented_server_protocols(&self) -> &HashSet<String> {
        &self.documented_server_protocols
    }

    /// Get all documented client protocols
    pub fn get_documented_client_protocols(&self) -> &HashSet<String> {
        &self.documented_client_protocols
    }

    /// Clear all conversation history
    pub fn clear_history(&mut self) {
        self.messages.clear();
        self.current_size = 0;
        self.truncated = false;
        self.last_interaction = Utc::now();
    }

    /// Get the current number of messages
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}
