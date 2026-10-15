//! Easy protocol implementations
//!
//! This module contains "easy" protocol implementations that provide simplified
//! LLM interaction for "dumb models" where the LLM responds in natural language
//! (Markdown) instead of JSON actions.
//!
//! Easy protocols act as translation layers between network events and simplified
//! LLM prompts, using existing Server/Client protocols underneath.

pub mod http;
