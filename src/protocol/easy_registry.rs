//! Easy protocol registry
//!
//! This module provides a centralized registry for "Easy" protocols that act as
//! translation layers between network events and simplified LLM prompts.

use crate::llm::actions::Easy;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

/// Global easy protocol registry mapping protocol names to easy protocol implementations
pub struct EasyRegistry {
    /// Maps easy protocol name (e.g., "http-easy") to easy protocol implementation
    protocols: HashMap<String, Arc<dyn Easy>>,
    /// Maps underlying protocol event type IDs to easy protocol name
    /// Used for routing events: e.g., "http_request" -> "http-easy"
    event_routing: HashMap<String, String>,
}

impl EasyRegistry {
    /// Create a new easy protocol registry
    fn new() -> Self {
        let mut registry = Self {
            protocols: HashMap::new(),
            event_routing: HashMap::new(),
        };

        // Register every easy protocol this platform builds
        registry.register_protocols();
        registry.build_event_routing();

        registry
    }

    /// Register all available easy protocols based on compiled features
    fn register_protocols(&mut self) {
        self.register(Arc::new(crate::easy::http::HttpEasyProtocol));
    }

    /// Register a new easy protocol
    #[allow(dead_code)]
    fn register(&mut self, protocol: Arc<dyn Easy>) {
        let name = protocol.protocol_name().to_string();
        self.protocols.insert(name, protocol);
    }

    /// Build event routing map from event type IDs to easy protocol names
    fn build_event_routing(&mut self) {
        for (protocol_name, protocol) in &self.protocols {
            for event_type_id in protocol.get_handled_event_type_ids() {
                self.event_routing
                    .insert(event_type_id.to_string(), protocol_name.clone());
            }
        }
    }

    /// Get a protocol by name (e.g., "http-easy")
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Easy>> {
        self.protocols.get(name).cloned()
    }

    /// Get easy protocol that handles a specific event type ID
    ///
    /// Returns None if no easy protocol is registered to handle this event type.
    /// Used by EventHandler to route events to easy protocols.
    pub fn get_by_event_type(&self, event_type_id: &str) -> Option<Arc<dyn Easy>> {
        self.event_routing
            .get(event_type_id)
            .and_then(|protocol_name| self.get_by_name(protocol_name))
    }

    /// Get all registered easy protocol names
    pub fn get_all_names(&self) -> Vec<String> {
        self.protocols.keys().cloned().collect()
    }

    /// Get all registered easy protocols
    pub fn get_all(&self) -> Vec<Arc<dyn Easy>> {
        self.protocols.values().cloned().collect()
    }
}

/// Global easy protocol registry instance
pub static EASY_REGISTRY: LazyLock<EasyRegistry> = LazyLock::new(EasyRegistry::new);
