//! Tool call definitions and execution for LLM
//!
//! This module provides tools that the LLM can invoke to gather information
//! before generating its final response. Tools include file reading and web search.

use super::{ActionDefinition, Parameter};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use tracing::{debug, error, warn};

/// Maximum file size to read (1MB)
const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// Default number of lines for head/tail
const DEFAULT_LINES: usize = 50;

/// Tool actions that the LLM can invoke
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolAction {
    /// Read a file from the filesystem
    ReadFile {
        /// Path to the file (relative to working directory or absolute)
        path: String,

        /// Read mode: full, head, tail, or grep
        #[serde(default = "default_read_mode")]
        mode: String,

        /// Number of lines for head/tail mode
        #[serde(default)]
        lines: Option<usize>,

        /// Regex pattern for grep mode
        #[serde(default)]
        pattern: Option<String>,

        /// Lines of context before match (grep -B)
        #[serde(default)]
        context_before: Option<usize>,

        /// Lines of context after match (grep -A)
        #[serde(default)]
        context_after: Option<usize>,
    },

    /// Fetch a URL or search the web using DuckDuckGo
    WebSearch {
        /// URL to fetch or search query
        query: String,
    },

    /// Get detailed documentation for a specific protocol (DEPRECATED - use ReadDocumentation)
    ReadBaseStackDocs {
        /// Protocol name (e.g., "http", "ssh", "tor")
        protocol: String,
    },

    /// Get detailed server protocol documentation (DEPRECATED - use ReadDocumentation)
    ReadServerDocumentation {
        /// Server protocol names (e.g., ["HTTP", "SSH", "TOR"])
        #[serde(default)]
        protocols: Vec<String>,
        /// Single protocol (backwards compatibility, use protocols instead)
        #[serde(default)]
        protocol: Option<String>,
    },

    /// Get detailed client protocol documentation (DEPRECATED - use ReadDocumentation)
    ReadClientDocumentation {
        /// Client protocol names (e.g., ["http", "ssh", "tor"])
        #[serde(default)]
        protocols: Vec<String>,
        /// Single protocol (backwards compatibility, use protocols instead)
        #[serde(default)]
        protocol: Option<String>,
    },

    /// Get detailed protocol documentation for servers and/or clients
    ReadDocumentation {
        /// Protocol names to look up (e.g., ["http", "ssh", "dns"])
        #[serde(default)]
        protocols: Vec<String>,
        /// Single protocol (backwards compatibility)
        #[serde(default)]
        protocol: Option<String>,
    },

    /// List available models from Ollama
    ListModels,

    /// Generate random data (strings, numbers, UUIDs, etc.)
    GenerateRandom {
        /// Type of random data to generate
        data_type: String,

        /// Optional: length for strings/arrays
        #[serde(default)]
        length: Option<usize>,

        /// Optional: minimum value for numbers
        #[serde(default)]
        min: Option<f64>,

        /// Optional: maximum value for numbers
        #[serde(default)]
        max: Option<f64>,

        /// Optional: character set for strings (alphanumeric, hex, base64, letters, digits)
        #[serde(default)]
        charset: Option<String>,

        /// Optional: array of choices to pick from
        #[serde(default)]
        choices: Option<Vec<serde_json::Value>>,

        /// Optional: number of items to pick from choices
        #[serde(default)]
        count: Option<usize>,
    },

    /// List all scheduled tasks
    ListTasks,

    /// Execute a SQL query on a database
    #[cfg(feature = "sqlite")]
    ExecuteSql {
        /// Database ID (from create_database response or list_databases)
        database_id: u32,

        /// SQL query to execute
        query: String,
    },

    /// List all active SQLite databases with their schemas
    #[cfg(feature = "sqlite")]
    ListDatabases,
}

fn default_read_mode() -> String {
    "full".to_string()
}

/// The single source of truth for which action names are *tools*.
///
/// A tool gathers information, returns its result to the model, and causes the model to be
/// invoked again with that result. Everything that has to agree on "is this a tool?" reads
/// this list:
///
/// * [`ToolAction::is_tool_action`] — routes a returned action to the tool loop at runtime.
/// * [`ToolAction::from_json`] — accepts a tool name for parsing.
/// * [`crate::llm::actions::ActionDefinition::is_tool`] — partitions the prompt into the
///   "Available Tools" and "Available Actions" sections, whose boilerplate makes opposite
///   promises about re-invocation.
///
/// Keeping these on one list is what prevents the prompt from advertising a re-invocation
/// the runtime will not perform (or vice versa). Adding a variant to [`ToolAction`] means
/// adding its name here.
pub const TOOL_ACTION_NAMES: &[&str] = &[
    "read_file",
    "web_search",
    "read_base_stack_docs",
    "read_server_documentation",
    "read_client_documentation",
    "read_documentation",
    "list_models",
    "generate_random",
    "list_tasks",
    "execute_sql",
    "list_databases",
];

/// Whether `name` is a tool — see [`TOOL_ACTION_NAMES`].
pub fn is_tool_name(name: &str) -> bool {
    TOOL_ACTION_NAMES.contains(&name)
}

impl ToolAction {
    /// Merge protocols array with optional single protocol (for backwards compatibility)
    fn merge_protocols(protocols: &[String], protocol: &Option<String>) -> Vec<String> {
        let mut result = protocols.to_vec();
        if let Some(p) = protocol {
            if !result.contains(p) {
                result.push(p.clone());
            }
        }
        result
    }

    /// Parse from JSON value
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        // Check if the tool type is recognized first
        if let Some(action_type) = value.get("type").and_then(|t| t.as_str()) {
            if !is_tool_name(action_type) {
                anyhow::bail!(
                    "Unknown tool type: '{}'. Valid tools: {}",
                    action_type,
                    TOOL_ACTION_NAMES.join(", ")
                );
            }
        }

        serde_json::from_value(value.clone()).context("Malformed tool action")
    }

    /// Check if a JSON value is a tool action
    pub fn is_tool_action(value: &serde_json::Value) -> bool {
        value
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(is_tool_name)
    }

    /// Get a brief description of this tool action for logging
    pub fn describe(&self) -> String {
        match self {
            ToolAction::ReadFile {
                path,
                mode,
                lines,
                pattern,
                ..
            } => {
                let mut desc = format!("read_file: {}", path);
                match mode.as_str() {
                    "head" => desc.push_str(&format!(
                        " (head, {} lines)",
                        lines.unwrap_or(DEFAULT_LINES)
                    )),
                    "tail" => desc.push_str(&format!(
                        " (tail, {} lines)",
                        lines.unwrap_or(DEFAULT_LINES)
                    )),
                    "grep" => {
                        if let Some(p) = pattern {
                            desc.push_str(&format!(" (grep: {})", p));
                        }
                    }
                    _ => desc.push_str(" (full)"),
                }
                desc
            }
            ToolAction::WebSearch { query } => {
                format!("web_search: \"{}\"", query)
            }
            ToolAction::ReadBaseStackDocs { protocol } => {
                format!("read_base_stack_docs: \"{}\"", protocol)
            }
            ToolAction::ReadServerDocumentation {
                protocols,
                protocol,
            } => {
                let all_protocols = Self::merge_protocols(protocols, protocol);
                format!("read_server_documentation: {:?}", all_protocols)
            }
            ToolAction::ReadClientDocumentation {
                protocols,
                protocol,
            } => {
                let all_protocols = Self::merge_protocols(protocols, protocol);
                format!("read_client_documentation: {:?}", all_protocols)
            }
            ToolAction::ReadDocumentation {
                protocols,
                protocol,
            } => {
                let all_protocols = Self::merge_protocols(protocols, protocol);
                format!("read_documentation: {:?}", all_protocols)
            }
            ToolAction::ListModels => "list_models: query available Ollama models".to_string(),
            ToolAction::GenerateRandom {
                data_type,
                length,
                min,
                max,
                ..
            } => {
                let mut desc = format!("generate_random: {}", data_type);
                if let Some(len) = length {
                    desc.push_str(&format!(" (length: {})", len));
                }
                if let Some(min_val) = min {
                    desc.push_str(&format!(" (min: {})", min_val));
                }
                if let Some(max_val) = max {
                    desc.push_str(&format!(" (max: {})", max_val));
                }
                desc
            }
            ToolAction::ListTasks => "list_tasks: list all scheduled tasks".to_string(),
            #[cfg(feature = "sqlite")]
            ToolAction::ExecuteSql { database_id, query } => {
                format!("execute_sql: db-{} query=\"{}\"", database_id, query)
            }
            #[cfg(feature = "sqlite")]
            ToolAction::ListDatabases => "list_databases: list all databases".to_string(),
        }
    }
}

/// Result of executing a tool
#[derive(Debug, Clone, Serialize)]
pub struct ToolResult {
    /// Name of the tool that was executed
    pub tool: String,

    /// Brief description of what was executed
    pub description: String,

    /// Result of the tool execution (success or error message)
    pub result: String,

    /// Whether the tool execution was successful
    pub success: bool,

    /// Number of lines/items in result (for logging)
    pub result_size: usize,
}

impl ToolResult {
    /// Create a successful tool result
    pub fn success(
        tool: impl Into<String>,
        description: impl Into<String>,
        result: impl Into<String>,
    ) -> Self {
        let result_str = result.into();
        let result_size = result_str.lines().count();
        Self {
            tool: tool.into(),
            description: description.into(),
            result: result_str,
            success: true,
            result_size,
        }
    }

    /// Create a failed tool result
    pub fn error(
        tool: impl Into<String>,
        description: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            description: description.into(),
            result: error.into(),
            success: false,
            result_size: 0,
        }
    }

    /// Format for inclusion in LLM prompt
    pub fn to_prompt_text(&self) -> String {
        if self.success {
            format!(
                "Tool '{}' ({}) returned {} lines:\n{}",
                self.tool, self.description, self.result_size, self.result
            )
        } else {
            format!(
                "Tool '{}' ({}) error:\n{}",
                self.tool, self.description, self.result
            )
        }
    }

    /// Get a brief summary for logging
    pub fn summary(&self) -> String {
        if self.success {
            format!("{} ({} lines)", self.description, self.result_size)
        } else {
            format!("{} (error)", self.description)
        }
    }
}

/// Execute a read_file tool action
pub async fn execute_read_file(
    path: &str,
    mode: &str,
    lines: Option<usize>,
    pattern: Option<&str>,
    context_before: Option<usize>,
    context_after: Option<usize>,
) -> ToolResult {
    use tracing::info;

    info!("🔧 Tool: read_file - path={}, mode={}", path, mode);
    debug!("Executing read_file tool: path={}, mode={}", path, mode);

    // Resolve path (support both relative and absolute)
    let path_buf = PathBuf::from(path);
    let resolved_path = if path_buf.is_absolute() {
        path_buf
    } else {
        // Resolve relative to current working directory
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(&path_buf),
            Err(e) => {
                error!("Failed to get current working directory: {}", e);
                return ToolResult::error(
                    "read_file",
                    format!("{} ({})", path, mode),
                    format!("Failed to resolve path: {}", e),
                );
            }
        }
    };

    // Security check: ensure path exists and is a file
    if !resolved_path.exists() {
        warn!("File not found: {}", resolved_path.display());
        info!("  ✗ File not found: {}", path);
        return ToolResult::error(
            "read_file",
            format!("{} ({})", path, mode),
            format!("File not found: {}", path),
        );
    }

    if !resolved_path.is_file() {
        warn!("Path is not a file: {}", resolved_path.display());
        info!("  ✗ Path is not a file: {}", path);
        return ToolResult::error(
            "read_file",
            format!("{} ({})", path, mode),
            format!("Path is not a file: {}", path),
        );
    }

    // Check file size
    match std::fs::metadata(&resolved_path) {
        Ok(metadata) => {
            if metadata.len() > MAX_FILE_SIZE {
                warn!("File too large: {} bytes", metadata.len());
                info!(
                    "  ✗ File too large: {} bytes (max: {} bytes)",
                    metadata.len(),
                    MAX_FILE_SIZE
                );
                return ToolResult::error(
                    "read_file",
                    format!("{} ({})", path, mode),
                    format!(
                        "File too large: {} bytes (max: {} bytes)",
                        metadata.len(),
                        MAX_FILE_SIZE
                    ),
                );
            }
        }
        Err(e) => {
            error!("Failed to read file metadata: {}", e);
            info!("  ✗ Failed to read file metadata: {}", e);
            return ToolResult::error(
                "read_file",
                format!("{} ({})", path, mode),
                format!("Failed to read file metadata: {}", e),
            );
        }
    }

    // Read file contents
    let contents = match crate::utils::file_io::read_text_async(
        &resolved_path,
        MAX_FILE_SIZE as usize,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read file: {}", e);
            info!("  ✗ Failed to read file: {}", e);
            return ToolResult::error(
                "read_file",
                format!("{} ({})", path, mode),
                format!("Failed to read file: {}", e),
            );
        }
    };

    // Process based on mode
    let result = match mode {
        "full" => {
            debug!("Read full file: {} bytes", contents.len());
            info!("  ✓ Read full file: {} bytes", contents.len());
            contents
        }
        "head" => {
            let n = lines.unwrap_or(DEFAULT_LINES);
            let result: Vec<&str> = contents.lines().take(n).collect();
            debug!("Read head: {} lines", result.len());
            info!("  ✓ Read head: {} lines", result.len());
            result.join("\n")
        }
        "tail" => {
            let n = lines.unwrap_or(DEFAULT_LINES);
            let all_lines: Vec<&str> = contents.lines().collect();
            let start = all_lines.len().saturating_sub(n);
            let result = &all_lines[start..];
            debug!("Read tail: {} lines", result.len());
            info!("  ✓ Read tail: {} lines", result.len());
            result.join("\n")
        }
        "grep" => {
            if let Some(pat) = pattern {
                match grep_with_context(&contents, pat, context_before, context_after) {
                    Ok(result) => {
                        let line_count = result.lines().count();
                        debug!("Grep found {} matching lines", line_count);
                        info!("  ✓ Grep found {} matching lines", line_count);
                        result
                    }
                    Err(e) => {
                        error!("Grep failed: {}", e);
                        info!("  ✗ Grep failed: {}", e);
                        return ToolResult::error(
                            "read_file",
                            format!("{} (grep: {})", path, pat),
                            format!("Grep failed: {}", e),
                        );
                    }
                }
            } else {
                return ToolResult::error(
                    "read_file",
                    format!("{} (grep)", path),
                    "Grep mode requires 'pattern' parameter".to_string(),
                );
            }
        }
        _ => {
            return ToolResult::error(
                "read_file",
                format!("{} ({})", path, mode),
                format!("Invalid mode: '{}'. Use: full, head, tail, or grep", mode),
            );
        }
    };

    let description = match mode {
        "full" => format!("{} (full)", path),
        "head" => format!("{} (head, {} lines)", path, lines.unwrap_or(DEFAULT_LINES)),
        "tail" => format!("{} (tail, {} lines)", path, lines.unwrap_or(DEFAULT_LINES)),
        "grep" => format!("{} (grep: {})", path, pattern.unwrap_or("")),
        _ => format!("{} ({})", path, mode),
    };

    ToolResult::success("read_file", description, result)
}

/// Perform grep with context lines
fn grep_with_context(
    text: &str,
    pattern: &str,
    before: Option<usize>,
    after: Option<usize>,
) -> Result<String> {
    let regex = Regex::new(pattern).context("Invalid regex pattern")?;
    let lines: Vec<&str> = text.lines().collect();
    let before_lines = before.unwrap_or(0);
    let after_lines = after.unwrap_or(0);

    let mut result_lines = Vec::new();
    let mut matched_indices = std::collections::HashSet::new();

    // Find all matching lines and their context
    for (i, line) in lines.iter().enumerate() {
        if regex.is_match(line) {
            // Add context before
            let start = i.saturating_sub(before_lines);
            for idx in start..i {
                matched_indices.insert(idx);
            }

            // Add matching line
            matched_indices.insert(i);

            // Add context after
            let end = (i + after_lines + 1).min(lines.len());
            for idx in (i + 1)..end {
                matched_indices.insert(idx);
            }
        }
    }

    // Convert to sorted vector and build result
    let mut indices: Vec<usize> = matched_indices.into_iter().collect();
    indices.sort_unstable();

    for idx in indices {
        result_lines.push(lines[idx]);
    }

    Ok(result_lines.join("\n"))
}

/// Execute a web_search tool action
pub async fn execute_web_search(query: &str) -> ToolResult {
    #[cfg(target_arch = "wasm32")]
    {
        return ToolResult::error(
            "web_search",
            query.to_string(),
            "web search is not available in the browser build".to_string(),
        );
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use tracing::info;

        info!("🔧 Tool: web_search - query=\"{}\"", query);
        debug!("Executing web_search tool for query: {}", query);

        // Check if query is a URL - if so, fetch it directly
        if query.trim().starts_with("http://") || query.trim().starts_with("https://") {
            return fetch_url(query.trim()).await;
        }

        // Otherwise, use DuckDuckGo HTML search (no API key required)
        use url::form_urlencoded;
        let encoded_query = form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
        let url = format!("https://html.duckduckgo.com/html/?q={}", encoded_query);

        let client = {
            let builder =
                reqwest::Client::builder().user_agent("Mozilla/5.0 (compatible; NetGet/1.0)");
            // fetch() has no request timeout; reqwest's wasm builder has no method for one.
            #[cfg(not(target_arch = "wasm32"))]
            let builder = builder.timeout(std::time::Duration::from_secs(10));
            builder.build().unwrap_or_default()
        };

        match client.get(&url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("Web search failed with status: {}", response.status());
                    info!("  ✗ Search failed with status: {}", response.status());
                    return ToolResult::error(
                        "web_search",
                        query.to_string(),
                        format!("Search failed with status: {}", response.status()),
                    );
                }

                match crate::client::http_fetch::read_response_text(response, 8 * 1024 * 1024).await
                {
                    Ok(html) => {
                        // Parse search results from HTML
                        let results = parse_duckduckgo_results(&html);
                        if results.is_empty() {
                            info!("  ⚠ No results found");
                            ToolResult::success(
                                "web_search",
                                query.to_string(),
                                "No results found.",
                            )
                        } else {
                            debug!("Found {} search results", results.len());
                            info!("  ✓ Found {} search results", results.len());
                            let formatted = format_search_results(&results);
                            ToolResult::success("web_search", query.to_string(), formatted)
                        }
                    }
                    Err(e) => {
                        error!("Failed to read search response: {}", e);
                        info!("  ✗ Failed to read response: {}", e);
                        ToolResult::error(
                            "web_search",
                            query.to_string(),
                            format!("Failed to read response: {}", e),
                        )
                    }
                }
            }
            Err(e) => {
                error!("Web search request failed: {}", e);
                info!("  ✗ Request failed: {}", e);
                ToolResult::error(
                    "web_search",
                    query.to_string(),
                    format!("Request failed: {}", e),
                )
            }
        }
    }
}

/// Fetch a URL directly and convert HTML to text
async fn fetch_url(url: &str) -> ToolResult {
    #[cfg(target_arch = "wasm32")]
    {
        return ToolResult::error(
            "web_search",
            url.to_string(),
            "fetching URLs is not available in the browser build".to_string(),
        );
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use tracing::info;

        info!("🔧 Tool: web_search (fetch URL) - {}", url);
        debug!("Fetching URL directly: {}", url);

        let client = {
            let builder =
                reqwest::Client::builder().user_agent("Mozilla/5.0 (compatible; NetGet/1.0)");
            // fetch() has no request timeout; reqwest's wasm builder has no method for one.
            #[cfg(not(target_arch = "wasm32"))]
            let builder = builder.timeout(std::time::Duration::from_secs(15));
            builder.build().unwrap_or_default()
        };

        match client.get(url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("URL fetch failed with status: {}", response.status());
                    info!("  ✗ HTTP {}", response.status());
                    return ToolResult::error(
                        "web_search",
                        url.to_string(),
                        format!("Failed to fetch URL: HTTP {}", response.status()),
                    );
                }

                match crate::client::http_fetch::read_response_text(response, 8 * 1024 * 1024).await
                {
                    Ok(html) => {
                        // Convert HTML to plain text
                        let text = html2text::from_read(html.as_bytes(), 120);

                        if text.trim().is_empty() {
                            info!("  ⚠ URL fetched but no text content found");
                            ToolResult::success(
                                "web_search",
                                url.to_string(),
                                "URL fetched but no text content found.",
                            )
                        } else {
                            // Truncate to reasonable length (10000 chars)
                            let truncated = crate::utils::truncate_with_notice(&text, 10000);

                            debug!("Fetched URL: {} chars", truncated.len());
                            info!("  ✓ Fetched URL: {} chars", truncated.len());
                            ToolResult::success("web_search", url.to_string(), truncated)
                        }
                    }
                    Err(e) => {
                        error!("Failed to read URL response: {}", e);
                        info!("  ✗ Failed to read response: {}", e);
                        ToolResult::error(
                            "web_search",
                            url.to_string(),
                            format!("Failed to read response: {}", e),
                        )
                    }
                }
            }
            Err(e) => {
                error!("URL fetch request failed: {}", e);
                info!("  ✗ Request failed: {}", e);
                ToolResult::error(
                    "web_search",
                    url.to_string(),
                    format!("Request failed: {}", e),
                )
            }
        }
    }
}

/// Search result entry
#[derive(Debug, Clone)]
struct SearchResult {
    title: String,
    url: String,
    snippet: String,
}

/// Parse DuckDuckGo HTML results
fn parse_duckduckgo_results(html: &str) -> Vec<SearchResult> {
    let mut results = Vec::new();

    // Simple HTML parsing - look for result blocks
    // DuckDuckGo HTML has results in <div class="result"> blocks
    for result_block in html.split(r#"<div class="result"#) {
        // Extract title from <a class="result__a">
        let title = extract_between(result_block, r#"class="result__a""#, "</a>")
            .and_then(|s| extract_between(&s, ">", "<"))
            .map(|s| decode_html_entities(&s))
            .unwrap_or_default();

        // Extract URL from href
        let url = extract_between(result_block, r#"href="//"#, r#"""#)
            .map(|s| format!("https://{}", s))
            .or_else(|| {
                extract_between(result_block, r#"href="https://"#, r#"""#)
                    .map(|s| format!("https://{}", s))
            })
            .unwrap_or_default();

        // Extract snippet from <a class="result__snippet">
        let snippet = extract_between(result_block, r#"class="result__snippet""#, "</a>")
            .and_then(|s| extract_between(&s, ">", "<"))
            .map(|s| decode_html_entities(&s))
            .unwrap_or_default();

        if !title.is_empty() || !snippet.is_empty() {
            results.push(SearchResult {
                title,
                url,
                snippet,
            });
        }

        // Limit to top 5 results
        if results.len() >= 5 {
            break;
        }
    }

    results
}

/// Extract text between two delimiters
fn extract_between(text: &str, start: &str, end: &str) -> Option<String> {
    let start_idx = text.find(start)? + start.len();
    let remaining = &text[start_idx..];
    let end_idx = remaining.find(end)?;
    Some(remaining[..end_idx].to_string())
}

/// Decode common HTML entities
fn decode_html_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Format search results for LLM
fn format_search_results(results: &[SearchResult]) -> String {
    let mut formatted = String::from("Search results:\n\n");
    for (i, result) in results.iter().enumerate() {
        formatted.push_str(&format!("{}. {}\n", i + 1, result.title));
        if !result.url.is_empty() {
            formatted.push_str(&format!("   URL: {}\n", result.url));
        }
        if !result.snippet.is_empty() {
            formatted.push_str(&format!("   {}\n", result.snippet));
        }
        formatted.push('\n');
    }
    formatted
}

/// Execute a list_models tool action
pub async fn execute_list_models() -> ToolResult {
    #[cfg(target_arch = "wasm32")]
    {
        return ToolResult::error(
            "list_models",
            "query available models".to_string(),
            "the browser build has no Ollama to list models from".to_string(),
        );
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use tracing::info;

        info!("🔧 Tool: list_models - querying Ollama for available models");
        debug!("Executing list_models tool");

        // Create Ollama client
        let client = crate::llm::ollama_client::OllamaClient::new("http://localhost:11434");

        match client.list_models().await {
            Ok(models) => {
                if models.is_empty() {
                    info!("  ⚠ No models found in Ollama");
                    ToolResult::success(
                        "list_models",
                        "query available models".to_string(),
                        "No models found. Please pull a model using 'ollama pull <model-name>'.",
                    )
                } else {
                    let model_count = models.len();
                    let formatted = format!(
                        "Available Ollama models ({} total):\n\n{}\n\nYou can use any of these models with the change_model action.",
                        model_count,
                        models.join("\n")
                    );
                    debug!("Found {} models", model_count);
                    info!("  ✓ Found {} models", model_count);
                    ToolResult::success(
                        "list_models",
                        "query available models".to_string(),
                        formatted,
                    )
                }
            }
            Err(e) => {
                error!("Failed to list models: {}", e);
                info!("  ✗ Failed to list models: {}", e);
                ToolResult::error(
                    "list_models",
                    "query available models".to_string(),
                    format!("Failed to list models: {}. Is Ollama running?", e),
                )
            }
        }
    }
}

/// Execute a generate_random tool action
pub async fn execute_generate_random(
    data_type: &str,
    length: Option<usize>,
    min: Option<f64>,
    max: Option<f64>,
    charset: Option<&str>,
    choices: Option<&[serde_json::Value]>,
    count: Option<usize>,
) -> ToolResult {
    use rand::Rng;
    use tracing::info;

    info!("🔧 Tool: generate_random - type={}", data_type);
    debug!("Generating random data: type={}", data_type);

    let mut rng = rand::thread_rng();

    let result = match data_type {
        // UUID v4
        "uuid" | "uuid4" => {
            let uuid = uuid::Uuid::new_v4();
            info!("  ✓ Generated UUID: {}", uuid);
            uuid.to_string()
        }

        // Random integer
        "integer" | "int" => {
            let min_val = min.unwrap_or(0.0) as i64;
            let max_val = max.unwrap_or(100.0) as i64;
            if min_val >= max_val {
                return ToolResult::error(
                    "generate_random",
                    format!("{} (int)", data_type),
                    "min must be less than max".to_string(),
                );
            }
            let value = rng.gen_range(min_val..=max_val);
            info!("  ✓ Generated integer: {}", value);
            value.to_string()
        }

        // Random float
        "float" | "number" => {
            let min_val = min.unwrap_or(0.0);
            let max_val = max.unwrap_or(1.0);
            if min_val >= max_val {
                return ToolResult::error(
                    "generate_random",
                    format!("{} (float)", data_type),
                    "min must be less than max".to_string(),
                );
            }
            let value: f64 = rng.gen_range(min_val..=max_val);
            info!("  ✓ Generated float: {}", value);
            value.to_string()
        }

        // Random string
        "string" => {
            let len = length.unwrap_or(16);
            let chars: Vec<char> = match charset.unwrap_or("alphanumeric") {
                "hex" => "0123456789abcdef",
                "digits" => "0123456789",
                "letters" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "lowercase" => "abcdefghijklmnopqrstuvwxyz",
                "uppercase" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                _ => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            }
            .chars()
            .collect();

            let result: String = (0..len)
                .map(|_| {
                    let idx = rng.gen_range(0..chars.len());
                    chars[idx]
                })
                .collect();
            info!("  ✓ Generated string: {} chars", len);
            result
        }

        // Random hex bytes (as hex string)
        "hex" | "hex_bytes" => {
            let len = length.unwrap_or(16);
            let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let hex_string = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            info!("  ✓ Generated hex bytes: {} bytes", len);
            hex_string
        }

        // Random base64 string
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            let len = length.unwrap_or(16);
            let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let b64 = general_purpose::STANDARD.encode(&bytes);
            info!("  ✓ Generated base64: {} bytes", len);
            b64
        }

        // Random word (lorem ipsum style)
        "word" => {
            const WORDS: &[&str] = &[
                "lorem",
                "ipsum",
                "dolor",
                "sit",
                "amet",
                "consectetur",
                "adipiscing",
                "elit",
                "sed",
                "do",
                "eiusmod",
                "tempor",
                "incididunt",
                "ut",
                "labore",
                "et",
                "dolore",
                "magna",
                "aliqua",
                "enim",
                "ad",
                "minim",
                "veniam",
                "quis",
                "nostrud",
                "exercitation",
                "ullamco",
                "laboris",
                "nisi",
                "aliquip",
                "ex",
                "ea",
                "commodo",
                "consequat",
                "duis",
                "aute",
                "irure",
                "in",
                "reprehenderit",
                "voluptate",
                "velit",
                "esse",
                "cillum",
                "fugiat",
                "nulla",
                "pariatur",
                "excepteur",
                "sint",
                "occaecat",
                "cupidatat",
                "non",
                "proident",
                "sunt",
                "culpa",
                "qui",
                "officia",
                "deserunt",
                "mollit",
                "anim",
                "id",
                "est",
                "laborum",
            ];
            let word = WORDS[rng.gen_range(0..WORDS.len())];
            info!("  ✓ Generated word: {}", word);
            word.to_string()
        }

        // Random sentence
        "sentence" => {
            const WORDS: &[&str] = &[
                "lorem",
                "ipsum",
                "dolor",
                "sit",
                "amet",
                "consectetur",
                "adipiscing",
                "elit",
                "sed",
                "do",
                "eiusmod",
                "tempor",
                "incididunt",
                "ut",
                "labore",
                "et",
                "dolore",
                "magna",
                "aliqua",
            ];
            let word_count = length.unwrap_or(10);
            let sentence: Vec<String> = (0..word_count)
                .map(|i| {
                    let word = WORDS[rng.gen_range(0..WORDS.len())];
                    if i == 0 {
                        let mut s = word.to_string();
                        s[0..1].make_ascii_uppercase();
                        s
                    } else {
                        word.to_string()
                    }
                })
                .collect();
            let result = format!("{}.", sentence.join(" "));
            info!("  ✓ Generated sentence: {} words", word_count);
            result
        }

        // Random paragraph
        "paragraph" => {
            const WORDS: &[&str] = &[
                "lorem",
                "ipsum",
                "dolor",
                "sit",
                "amet",
                "consectetur",
                "adipiscing",
                "elit",
                "sed",
                "do",
                "eiusmod",
                "tempor",
                "incididunt",
                "ut",
                "labore",
                "et",
                "dolore",
                "magna",
                "aliqua",
                "enim",
                "ad",
                "minim",
                "veniam",
                "quis",
                "nostrud",
            ];
            let sentence_count = length.unwrap_or(5);
            let paragraph: Vec<String> = (0..sentence_count)
                .map(|_| {
                    let word_count = rng.gen_range(5..15);
                    let sentence_words: Vec<String> = (0..word_count)
                        .map(|i| {
                            let word = WORDS[rng.gen_range(0..WORDS.len())];
                            if i == 0 {
                                let mut s = word.to_string();
                                s[0..1].make_ascii_uppercase();
                                s
                            } else {
                                word.to_string()
                            }
                        })
                        .collect();
                    format!("{}.", sentence_words.join(" "))
                })
                .collect();
            info!("  ✓ Generated paragraph: {} sentences", sentence_count);
            paragraph.join(" ")
        }

        // Random email
        "email" => {
            let username_len = length.unwrap_or(8);
            let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
            let username: String = (0..username_len)
                .map(|_| {
                    let idx = rng.gen_range(0..chars.len());
                    chars[idx]
                })
                .collect();
            let domains = &["example.com", "test.com", "demo.org", "sample.net"];
            let domain = domains[rng.gen_range(0..domains.len())];
            let email = format!("{}@{}", username, domain);
            info!("  ✓ Generated email: {}", email);
            email
        }

        // Random IPv4 address
        "ipv4" | "ip" => {
            let ip = format!(
                "{}.{}.{}.{}",
                rng.gen_range(1..=255),
                rng.gen_range(0..=255),
                rng.gen_range(0..=255),
                rng.gen_range(1..=255)
            );
            info!("  ✓ Generated IPv4: {}", ip);
            ip
        }

        // Random IPv6 address
        "ipv6" => {
            let segments: Vec<String> = (0..8)
                .map(|_| format!("{:04x}", rng.gen_range(0..=0xffff)))
                .collect();
            let ip = segments.join(":");
            info!("  ✓ Generated IPv6: {}", ip);
            ip
        }

        // Random MAC address
        "mac" | "mac_address" => {
            let octets: Vec<String> = (0..6)
                .map(|_| format!("{:02x}", rng.gen_range(0..=255)))
                .collect();
            let mac = octets.join(":");
            info!("  ✓ Generated MAC address: {}", mac);
            mac
        }

        // Random port number
        "port" => {
            let min_port = min.unwrap_or(1024.0) as u16;
            let max_port = max.unwrap_or(65535.0) as u16;
            let port = rng.gen_range(min_port..=max_port);
            info!("  ✓ Generated port: {}", port);
            port.to_string()
        }

        // Random timestamp (Unix timestamp)
        "timestamp" | "unix_timestamp" => {
            use crate::utils::clock::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Generate random timestamp within ±1 year from now
            let one_year = 365 * 24 * 60 * 60;
            let min_time = min
                .map(|m| m as u64)
                .unwrap_or(now.saturating_sub(one_year));
            let max_time = max
                .map(|m| m as u64)
                .unwrap_or(now.saturating_add(one_year));
            let timestamp = rng.gen_range(min_time..=max_time);
            info!("  ✓ Generated timestamp: {}", timestamp);
            timestamp.to_string()
        }

        // Random date (ISO 8601 format)
        "date" | "iso_date" => {
            use crate::utils::clock::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let one_year = 365 * 24 * 60 * 60;
            let min_time = min
                .map(|m| m as u64)
                .unwrap_or(now.saturating_sub(one_year));
            let max_time = max.map(|m| m as u64).unwrap_or(now + one_year);
            let timestamp = rng.gen_range(min_time..=max_time);

            // Convert to date
            let days_since_epoch = timestamp / (24 * 60 * 60);
            let year = 1970 + (days_since_epoch / 365);
            let day_of_year = days_since_epoch % 365;
            let month = (day_of_year / 30) + 1;
            let day = (day_of_year % 30) + 1;

            let date = format!("{:04}-{:02}-{:02}", year, month.min(12), day.min(28));
            info!("  ✓ Generated date: {}", date);
            date
        }

        // Random boolean
        "boolean" | "bool" => {
            let value = rng.gen_bool(0.5);
            info!("  ✓ Generated boolean: {}", value);
            value.to_string()
        }

        // Pick random choice from list
        "choice" => {
            if let Some(choice_list) = choices {
                if choice_list.is_empty() {
                    return ToolResult::error(
                        "generate_random",
                        "choice".to_string(),
                        "choices array cannot be empty".to_string(),
                    );
                }
                let idx = rng.gen_range(0..choice_list.len());
                let choice = &choice_list[idx];
                info!("  ✓ Picked random choice: {}", choice);
                serde_json::to_string(choice).unwrap_or_else(|_| choice.to_string())
            } else {
                return ToolResult::error(
                    "generate_random",
                    "choice".to_string(),
                    "choices parameter is required for choice type".to_string(),
                );
            }
        }

        // Pick multiple random choices from list
        "choices" | "sample" => {
            if let Some(choice_list) = choices {
                if choice_list.is_empty() {
                    return ToolResult::error(
                        "generate_random",
                        "choices".to_string(),
                        "choices array cannot be empty".to_string(),
                    );
                }
                let pick_count = count.unwrap_or(1).min(choice_list.len());
                let mut indices: Vec<usize> = (0..choice_list.len()).collect();
                use rand::seq::SliceRandom;
                indices.shuffle(&mut rng);

                let picked: Vec<String> = indices[..pick_count]
                    .iter()
                    .map(|&i| {
                        serde_json::to_string(&choice_list[i])
                            .unwrap_or_else(|_| choice_list[i].to_string())
                    })
                    .collect();

                info!("  ✓ Picked {} random choices", pick_count);
                format!("[{}]", picked.join(", "))
            } else {
                return ToolResult::error(
                    "generate_random",
                    "choices".to_string(),
                    "choices parameter is required for choices type".to_string(),
                );
            }
        }

        _ => {
            return ToolResult::error(
                "generate_random",
                data_type.to_string(),
                format!(
                    "Unknown data type: '{}'. Valid types: uuid, integer, float, string, hex, base64, word, sentence, paragraph, email, ipv4, ipv6, mac, port, timestamp, date, boolean, choice, choices",
                    data_type
                ),
            );
        }
    };

    ToolResult::success("generate_random", data_type.to_string(), result)
}

/// Get action definition for read_file tool
pub fn read_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "read_file".to_string(),
        description: "Read the contents of a file from the local filesystem. Supports multiple read modes: full (entire file), head (first N lines), tail (last N lines), or grep (search with regex pattern). Use this to access configuration files, schemas, RFCs, or other reference documents.".to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "Path to the file (relative to current directory or absolute)".to_string(),
                required: true,
            },
            Parameter {
                name: "mode".to_string(),
                type_hint: "string".to_string(),
                description: "Read mode: 'full' (default), 'head', 'tail', or 'grep'".to_string(),
                required: false,
            },
            Parameter {
                name: "lines".to_string(),
                type_hint: "number".to_string(),
                description: "Number of lines for head/tail mode (default: 50)".to_string(),
                required: false,
            },
            Parameter {
                name: "pattern".to_string(),
                type_hint: "string".to_string(),
                description: "Regex pattern for grep mode (required for grep)".to_string(),
                required: false,
            },
            Parameter {
                name: "context_before".to_string(),
                type_hint: "number".to_string(),
                description: "Lines of context before match in grep mode (like grep -B)".to_string(),
                required: false,
            },
            Parameter {
                name: "context_after".to_string(),
                type_hint: "number".to_string(),
                description: "Lines of context after match in grep mode (like grep -A)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "read_file",
            "path": "schema.json",
            "mode": "full"
        }),
        log_template: None,
    }
}

/// Get action definition for web_search tool
pub fn web_search_action() -> ActionDefinition {
    ActionDefinition {
        name: "web_search".to_string(),
        description: "Fetch web pages or search the web. If query starts with http:// or https://, fetches that URL directly and returns the page content as text. Otherwise, searches DuckDuckGo and returns top 5 results. Use this to read RFCs, protocol specifications, or documentation. Note: This makes external network requests.".to_string(),
        parameters: vec![Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "URL to fetch (e.g., 'https://datatracker.ietf.org/doc/html/rfc7168') or search query (e.g., 'RFC 959 FTP protocol specification')".to_string(),
            required: true,
        }],
        example: json!({
            "type": "web_search",
            "query": "https://datatracker.ietf.org/doc/html/rfc7168"
        }),
        log_template: None,
    }
}

/// Get protocol documentation action definition (DEPRECATED - use read_server_documentation_action or read_client_documentation_action)
pub fn read_base_stack_docs_action() -> ActionDefinition {
    ActionDefinition {
        name: "read_base_stack_docs".to_string(),
        description: "Get detailed documentation for a specific network protocol. Returns comprehensive information including description, startup parameters, examples, and keywords. Use this before starting a server to understand protocol configuration options.".to_string(),
        parameters: vec![Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Protocol name (e.g., 'http', 'ssh', 'tor', 'dns'). Use lowercase.".to_string(),
            required: true,
        }],
        example: json!({
            "type": "read_base_stack_docs",
            "protocol": "tor"
        }),
        log_template: None,
    }
}

/// Get unified protocol documentation action definition
///
/// This unified tool replaces both `read_server_documentation` and `read_client_documentation`.
/// It looks up protocols in both server and client registries and explains when to use each mode.
///
/// Lists every protocol available to the model with no operator floor; a prompt applies the
/// operator's settings through [`read_documentation_action_for`] (via
/// `common::restrict_protocol_lists`).
pub fn read_documentation_action() -> ActionDefinition {
    read_documentation_action_for(false, None)
}

/// `read_documentation`, listing only the protocols the operator allows:
/// `include_disabled` and `min_stability` are the `--include-disabled-protocols` /
/// `--min-stability` settings, under which startup refuses anything below the floor.
pub fn read_documentation_action_for(
    include_disabled: bool,
    min_stability: Option<crate::protocol::metadata::DevelopmentState>,
) -> ActionDefinition {
    let server_protocols = super::common::all_base_stacks(include_disabled, min_stability);

    let client_registry = &crate::protocol::client_registry::CLIENT_REGISTRY;
    let mut client_protocols: Vec<String> = client_registry
        .list_protocols()
        .into_iter()
        .filter(|name| match client_registry.get(name) {
            Some(client) => {
                let meta = client.metadata();
                (include_disabled || meta.is_available_to_llm())
                    && min_stability.map(|min| meta.state >= min).unwrap_or(true)
            }
            None => true,
        })
        .collect();
    client_protocols.sort();

    let list = |names: &[String]| {
        if names.is_empty() {
            "None".to_string()
        } else {
            names.join(", ")
        }
    };

    ActionDefinition {
        name: "read_documentation".to_string(),
        description: format!(
            r#"Get the documentation of one or more protocols, server and client side. For each it gives the event ids the protocol raises (with their fields), the actions that answer them (with parameters and examples), its startup parameters, and its history and batching defaults. Read it before writing event_handlers or startup_params for a protocol: both must use the names it gives.

**Server protocols**: {}

**Client protocols**: {}"#,
            list(&server_protocols),
            list(&client_protocols)
        ),
        parameters: vec![Parameter {
            name: "protocols".to_string(),
            type_hint: "array".to_string(),
            description: "Protocol names to document, at most 5 per call (more is refused). \
                Each returns its server and client documentation where both exist."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "read_documentation",
            "protocols": ["http"]
        }),
        log_template: None,
    }
}

/// Get list models action definition
pub fn list_models_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_models".to_string(),
        description: "List all available Ollama models that can be used for LLM generation. Returns a list of model names that can be used with the change_model action. Use this to discover which models are available before switching models.".to_string(),
        parameters: vec![],
        example: json!({
            "type": "list_models"
        }),
        log_template: None,
    }
}

/// Get generate_random action definition
pub fn generate_random_action() -> ActionDefinition {
    ActionDefinition {
        name: "generate_random".to_string(),
        description: "Generate random data of various types. IMPORTANT: LLMs cannot generate truly random data - you MUST use this tool whenever you need random/mock data for responses. Supports: UUIDs, numbers, strings, emails, IPs, dates, lorem ipsum text, and more. This tool returns the random value which you can then use in your response.".to_string(),
        parameters: vec![
            Parameter {
                name: "data_type".to_string(),
                type_hint: "string".to_string(),
                description: "Type of random data: uuid, integer, float, string, hex, base64, word, sentence, paragraph, email, ipv4, ipv6, mac, port, timestamp, date, boolean, choice, choices".to_string(),
                required: true,
            },
            Parameter {
                name: "length".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: Length for strings (default: 16), number of words for sentences (default: 10), or sentences for paragraphs (default: 5)".to_string(),
                required: false,
            },
            Parameter {
                name: "min".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: Minimum value for integer/float (default: 0 for int, 0.0 for float), or min timestamp".to_string(),
                required: false,
            },
            Parameter {
                name: "max".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: Maximum value for integer/float (default: 100 for int, 1.0 for float), or max timestamp".to_string(),
                required: false,
            },
            Parameter {
                name: "charset".to_string(),
                type_hint: "string".to_string(),
                description: "Optional: Character set for strings - alphanumeric (default), hex, digits, letters, lowercase, uppercase".to_string(),
                required: false,
            },
            Parameter {
                name: "choices".to_string(),
                type_hint: "array".to_string(),
                description: "Optional: Array of values to choose from (required for choice/choices types)".to_string(),
                required: false,
            },
            Parameter {
                name: "count".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: Number of items to pick for 'choices' type (default: 1)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "generate_random",
            "data_type": "uuid"
        }),
        log_template: None,
    }
}

/// Get action definition for list_tasks
pub fn list_tasks_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_tasks".to_string(),
        description: "List all currently scheduled tasks. Returns information about all one-shot and recurring tasks, including their status, next execution time, and configuration.".to_string(),
        parameters: vec![],
        example: json!({
            "type": "list_tasks"
        }),
        log_template: None,
    }
}

/// Get action definition for execute_sql
#[cfg(feature = "sqlite")]
pub fn execute_sql_action() -> ActionDefinition {
    ActionDefinition {
        name: "execute_sql".to_string(),
        description: "Execute a SQL query on a database. Supports DDL (CREATE/ALTER/DROP), DML (INSERT/UPDATE/DELETE), and DQL (SELECT). Returns results as JSON with columns and rows for SELECT queries, or affected row count for modifications.".to_string(),
        parameters: vec![
            Parameter {
                name: "database_id".to_string(),
                type_hint: "number".to_string(),
                description: "Database ID (from create_database response or list_databases). Format: db-N → use N.".to_string(),
                required: true,
            },
            Parameter {
                name: "query".to_string(),
                type_hint: "string".to_string(),
                description: "SQL query to execute. Use standard SQLite syntax. Be careful with semicolons (only one statement per execute_sql).".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "execute_sql",
            "database_id": 1,
            "query": "SELECT * FROM files WHERE path LIKE '/home/%'"
        }),
        log_template: None,
    }
}

/// Get action definition for list_databases
#[cfg(feature = "sqlite")]
pub fn list_databases_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_databases".to_string(),
        description: "List all active SQLite databases with their schemas, table information, and row counts. Use this to discover available databases and understand their structure before querying.".to_string(),
        parameters: vec![],
        example: json!({
            "type": "list_databases"
        }),
        log_template: None,
    }
}

/// Get all tool action definitions
pub fn get_all_tool_actions(
    web_search_mode: crate::state::app_state::WebSearchMode,
) -> Vec<ActionDefinition> {
    use crate::state::app_state::WebSearchMode;

    let mut actions = vec![
        generate_random_action(), // Put first - LLMs need this for mock data
        read_file_action(),
        read_documentation_action(), // Unified tool for both server and client docs
        list_tasks_action(),
    ];

    // Add SQLite tools if feature is enabled
    #[cfg(feature = "sqlite")]
    {
        actions.push(execute_sql_action());
        actions.push(list_databases_action());
    }

    // Include web search tool for both ON and ASK modes (not for OFF)
    match web_search_mode {
        WebSearchMode::On | WebSearchMode::Ask => {
            actions.push(web_search_action());
        }
        WebSearchMode::Off => {
            // Don't include web search tool
        }
    }

    actions
}

/// Tools for scheduled tasks scoped to an already-running server or client.
///
/// The legacy name is retained for callers. Immediate network-event responses
/// exclude these tools through `PromptBuilder::advertised_network_event_actions`;
/// scheduled tasks may still read files, query SQLite, or gather other information.
/// Documentation tools for opening new instances belong to operator conversations.
pub fn get_network_event_tool_actions(
    web_search_mode: crate::state::app_state::WebSearchMode,
) -> Vec<ActionDefinition> {
    use crate::state::app_state::WebSearchMode;

    let mut actions = vec![
        generate_random_action(),
        read_file_action(),
        list_tasks_action(),
    ];

    // Add SQLite tools if feature is enabled
    #[cfg(feature = "sqlite")]
    {
        actions.push(execute_sql_action());
        actions.push(list_databases_action());
    }

    // Include web search tool for both ON and ASK modes (not for OFF)
    match web_search_mode {
        WebSearchMode::On | WebSearchMode::Ask => {
            actions.push(web_search_action());
        }
        WebSearchMode::Off => {
            // Don't include web search tool
        }
    }

    actions
}

/// Execute a tool action
pub async fn execute_tool(
    action: &ToolAction,
    approval_tx: Option<
        &tokio::sync::mpsc::UnboundedSender<crate::state::app_state::WebApprovalRequest>,
    >,
    web_search_mode: crate::state::app_state::WebSearchMode,
    _state: Option<&crate::state::AppState>,
) -> ToolResult {
    use crate::state::app_state::{WebApprovalRequest, WebApprovalResponse, WebSearchMode};

    match action {
        ToolAction::ReadFile {
            path,
            mode,
            lines,
            pattern,
            context_before,
            context_after,
        } => {
            execute_read_file(
                path,
                mode,
                *lines,
                pattern.as_deref(),
                *context_before,
                *context_after,
            )
            .await
        }
        ToolAction::WebSearch { query } => {
            // Check if approval is needed (ASK mode)
            if web_search_mode == WebSearchMode::Ask {
                if let Some(tx) = approval_tx {
                    debug!("Web search in ASK mode, requesting approval for: {}", query);

                    // Create oneshot channel for response
                    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

                    // Send approval request to UI
                    let request = WebApprovalRequest {
                        url: query.to_string(),
                        response_tx,
                    };

                    if let Err(e) = tx.send(request) {
                        error!("Failed to send web approval request: {}", e);
                        return ToolResult::error(
                            "web_search",
                            query.to_string(),
                            "Failed to request approval for web search".to_string(),
                        );
                    }

                    // Wait for user response
                    match response_rx.await {
                        Ok(WebApprovalResponse::Allow) => {
                            debug!("User approved web search");
                            // Proceed with search
                            execute_web_search(query).await
                        }
                        Ok(WebApprovalResponse::AlwaysAllow) => {
                            debug!("User chose always allow (note: mode switch happens in UI)");
                            // UI will switch mode to ON, proceed with this search
                            execute_web_search(query).await
                        }
                        Ok(WebApprovalResponse::Deny) => {
                            debug!("User denied web search");
                            ToolResult::error(
                                "web_search",
                                query.to_string(),
                                "Web search denied by user".to_string(),
                            )
                        }
                        Err(e) => {
                            error!("Failed to receive approval response: {}", e);
                            ToolResult::error(
                                "web_search",
                                query.to_string(),
                                "Approval request was cancelled".to_string(),
                            )
                        }
                    }
                } else {
                    error!("Web search in ASK mode but no approval channel available");
                    ToolResult::error(
                        "web_search",
                        query.to_string(),
                        "Cannot request approval: approval channel not configured".to_string(),
                    )
                }
            } else {
                // ON mode - proceed directly
                execute_web_search(query).await
            }
        }
        ToolAction::ReadBaseStackDocs { protocol } => render_documentation(
            "read_base_stack_docs",
            std::slice::from_ref(protocol),
            DocModes::Both,
            _state,
        ),
        ToolAction::ReadServerDocumentation {
            protocols,
            protocol,
        } => {
            let all_protocols = ToolAction::merge_protocols(protocols, protocol);
            render_documentation(
                "read_server_documentation",
                &all_protocols,
                DocModes::ServerOnly,
                _state,
            )
        }
        ToolAction::ReadClientDocumentation {
            protocols,
            protocol,
        } => {
            let all_protocols = ToolAction::merge_protocols(protocols, protocol);
            render_documentation(
                "read_client_documentation",
                &all_protocols,
                DocModes::ClientOnly,
                _state,
            )
        }
        ToolAction::ReadDocumentation {
            protocols,
            protocol,
        } => {
            let all_protocols = ToolAction::merge_protocols(protocols, protocol);
            render_documentation("read_documentation", &all_protocols, DocModes::Both, _state)
        }
        ToolAction::ListModels => execute_list_models().await,
        ToolAction::GenerateRandom {
            data_type,
            length,
            min,
            max,
            charset,
            choices,
            count,
        } => {
            execute_generate_random(
                data_type,
                *length,
                *min,
                *max,
                charset.as_deref(),
                choices.as_deref(),
                *count,
            )
            .await
        }
        ToolAction::ListTasks => {
            if let Some(state) = _state {
                execute_list_tasks(state).await
            } else {
                ToolResult::error(
                    "list_tasks",
                    "".to_string(),
                    "State not available".to_string(),
                )
            }
        }
        #[cfg(feature = "sqlite")]
        ToolAction::ExecuteSql { database_id, query } => {
            if let Some(state) = _state {
                execute_execute_sql(state, *database_id, query).await
            } else {
                ToolResult::error(
                    "execute_sql",
                    query.to_string(),
                    "State not available".to_string(),
                )
            }
        }
        #[cfg(feature = "sqlite")]
        ToolAction::ListDatabases => {
            if let Some(state) = _state {
                execute_list_databases(state).await
            } else {
                ToolResult::error(
                    "list_databases",
                    "".to_string(),
                    "State not available".to_string(),
                )
            }
        }
    }
}

/// Which halves of a protocol a documentation tool describes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DocModes {
    /// Server and client, whichever exist — `read_documentation` and `read_base_stack_docs`.
    Both,
    /// `read_server_documentation`.
    ServerOnly,
    /// `read_client_documentation`.
    ClientOnly,
}

/// Most protocols one documentation call may ask for.
const MAX_DOC_PROTOCOLS: usize = 5;

/// Render the documentation tools' output: every requested protocol in the requested modes,
/// then the `open_server` / `open_client` examples for what was found.
///
/// All four documentation tools land here, so the model reads one format whichever it calls.
/// What each mode says about the protocol itself — events with their fields, actions with
/// their parameters, startup parameters with their defaults — is rendered by
/// `crate::protocol::docs`, the renderers MCP's `get_protocol_docs` uses too.
fn render_documentation(
    tool_name: &str,
    protocols: &[String],
    modes: DocModes,
    state: Option<&crate::state::AppState>,
) -> ToolResult {
    use tracing::info;

    if protocols.is_empty() {
        return ToolResult::error(
            tool_name,
            "no protocols".to_string(),
            "No protocols specified. Provide at least one protocol name in the 'protocols' array."
                .to_string(),
        );
    }

    if protocols.len() > MAX_DOC_PROTOCOLS {
        return ToolResult::error(
            tool_name,
            format!("{} protocols requested", protocols.len()),
            format!(
                "Too many protocols requested ({}). Maximum is {} per call. Please retry with {} or fewer protocols. Requested: {:?}",
                protocols.len(),
                MAX_DOC_PROTOCOLS,
                MAX_DOC_PROTOCOLS,
                protocols
            ),
        );
    }

    info!("🔧 Tool: {} - protocols={:?}", tool_name, protocols);

    let state: &crate::state::AppState = match state {
        Some(state) => state,
        None => crate::protocol::docs::fresh_state(),
    };
    let server_registry = crate::protocol::server_registry::registry();
    let client_registry = &crate::protocol::client_registry::CLIENT_REGISTRY;

    let mut body = String::new();
    // (name as the model should write it, well-known port to reach it on)
    let mut found_servers: Vec<String> = Vec::new();
    let mut found_clients: Vec<(String, Option<u16>)> = Vec::new();
    let mut not_found = Vec::new();

    for protocol in protocols {
        // Exact registry key first (e.g. "HTTP", "S3"), then keyword resolution, so
        // mixed-case keys ("DynamoDB") and keyword forms ("dynamo", "s3 bucket") resolve.
        let server = server_registry.get(&protocol.to_uppercase()).or_else(|| {
            server_registry
                .parse_from_str(protocol)
                .and_then(|name| server_registry.get(&name))
        });
        let client = client_registry.get(&protocol.to_lowercase()).or_else(|| {
            client_registry
                .parse_from_str(protocol)
                .and_then(|name| client_registry.get(&name))
        });

        let server = server.filter(|_| modes != DocModes::ClientOnly);
        let client = client.filter(|_| modes != DocModes::ServerOnly);
        if server.is_none() && client.is_none() {
            warn!("Protocol '{}' not found for {}", protocol, tool_name);
            not_found.push(protocol.clone());
            continue;
        }

        if let Some(server) = &server {
            let name = server.protocol_name().to_lowercase();
            render_server_mode(&mut body, server.as_ref(), state);
            found_servers.push(name);
        }

        if let Some(client) = &client {
            let name = client.protocol_name().to_lowercase();
            render_client_mode(&mut body, &name, client.as_ref(), state);
            // A client reaches a server of its protocol, so the server's declared port is
            // where one listens; a client-only protocol may declare its own.
            let port = server_registry
                .parse_from_str(&name)
                .and_then(|n| server_registry.get(&n))
                .and_then(|s| s.metadata().well_known_port)
                .or(client.metadata().well_known_port);
            found_clients.push((name, port));
        }
    }

    if found_servers.is_empty() && found_clients.is_empty() {
        let kind = match modes {
            DocModes::Both => "protocols",
            DocModes::ServerOnly => "server protocols",
            DocModes::ClientOnly => "client protocols",
        };
        return ToolResult::error(
            tool_name,
            protocols.join(", "),
            format!(
                "No {kind} found for {:?}. The read_documentation action's description lists \
                 every server and client protocol in this build; use a name from there.",
                not_found
            ),
        );
    }

    let mut result = String::new();
    result.push_str("# Protocol Documentation\n\n");
    if modes == DocModes::Both {
        result.push_str("## CRITICAL: When to Use Server vs Client Mode\n\n");
        result.push_str(
            "**Server Mode (open_server)** - Use when the user wants to HOST/SERVE content:\n",
        );
        result.push_str("- Keywords: \"serve\", \"host\", \"listen\", \"start a server\", \"create a server\", \"run a server\", \"open server\", \"provide\", \"respond to\"\n");
        result.push_str("- You LISTEN on a port and RESPOND to incoming requests\n");
        result.push_str("- User wants to PROVIDE a service that others connect to\n");
        result.push_str("- Examples: \"host a website\", \"start HTTP server\", \"create DNS server\", \"run FTP server\"\n\n");
        result.push_str("**Client Mode (open_client)** - Use when the user wants to CONNECT to an existing remote server:\n");
        result.push_str("- Keywords: \"connect to\", \"fetch from\", \"query\", \"access\", \"call\", \"request from\", \"get from\", \"send to\", \"send a\"\n");
        result.push_str("- You CONNECT to a remote server and SEND requests to it\n");
        result.push_str("- User wants to ACCESS a service that someone else is running\n");
        result.push_str("- Examples: \"connect to Redis at localhost:6379\", \"fetch from API\", \"query database\"\n\n");
        result.push_str("**⚠️ IMPORTANT**: If the user says \"serve\", \"host\", or \"provide\" content, use `open_server` even if they mistakenly say \"client\".\n");
        result.push_str("The ACTION (serving content) matters more than the word choice.\n\n");
        result.push_str("---\n\n");
    }
    result.push_str(&body);

    result.push_str("## Enabled Actions\n\n");
    if !found_servers.is_empty() && !found_clients.is_empty() {
        result.push_str(
            "**⚠️ BEFORE CHOOSING**: Re-read the user's request. What do they want to DO?\n",
        );
        result.push_str("- If they want to SERVE/HOST/PROVIDE content → use `open_server`\n");
        result.push_str(
            "- If they want to CONNECT TO/FETCH FROM a remote server → use `open_client`\n",
        );
        result.push_str("- The ACTION matters, not the words. \"serve recipes\" = server, even if user says \"client\"\n\n");
    }

    if !found_servers.is_empty() {
        result.push_str("### open_server (For SERVING content)\n\n");
        result.push_str("Use when: User wants to HOST content, SERVE data, LISTEN for connections, or PROVIDE a service. `open_server` is now enabled for the protocols above. Leave `port` out to listen on the protocol's well-known port (its **Port** line above); give one only when the user names it.\n\n");
        for protocol in &found_servers {
            let example = json!({
                "type": "open_server",
                "protocol": protocol,
                "instruction": "Handle incoming requests",
            });
            result.push_str(&format!(
                "**Example for {} server:**\n```json\n{}\n```\n\n",
                protocol,
                serde_json::to_string_pretty(&example).unwrap_or_default()
            ));
        }
    }

    if !found_clients.is_empty() {
        result.push_str("### open_client (For CONNECTING to remote servers)\n\n");
        result.push_str("Use when: User wants to CONNECT TO an existing server, FETCH data, QUERY a database, or ACCESS a remote service. `open_client` is now enabled for the protocols above. `remote_addr` is the `host:port` the user names; the examples use the protocol's well-known port on this machine.\n\n");
        for (protocol, port) in &found_clients {
            let remote_addr = match port {
                Some(port) => format!("127.0.0.1:{port}"),
                None => "127.0.0.1:9000".to_string(),
            };
            let example = json!({
                "type": "open_client",
                "protocol": protocol,
                "remote_addr": remote_addr,
                "instruction": "Connect and interact",
            });
            result.push_str(&format!(
                "**Example for {} client:**\n```json\n{}\n```\n\n",
                protocol,
                serde_json::to_string_pretty(&example).unwrap_or_default()
            ));
            if port.is_none() {
                result.push_str("This protocol has no well-known port: use the port the server you are connecting to listens on.\n\n");
            }
        }
    }

    if !not_found.is_empty() {
        result.push_str(&format!(
            "\n**Note:** The following protocols were not found: {:?}\n",
            not_found
        ));
    }

    let all_found: Vec<String> = found_servers
        .iter()
        .cloned()
        .chain(found_clients.iter().map(|(n, _)| n.clone()))
        .collect();
    info!(
        "  ✓ Retrieved docs for {:?} ({} bytes)",
        all_found,
        result.len()
    );

    ToolResult::success(tool_name, all_found.join(", "), result)
}

/// The facts and description shared by both modes' headers.
fn render_mode_header<P: crate::llm::actions::protocol_trait::Protocol + ?Sized>(
    out: &mut String,
    p: &P,
) {
    let metadata = p.metadata();
    out.push_str(&format!("**Stack:** {}\n", p.stack_name()));
    out.push_str(&format!("**Group:** {}\n", p.group_name()));
    out.push_str(&format!("**Maturity:** {}\n", metadata.state.as_str()));
    out.push_str(&format!(
        "**Privilege required:** {}\n",
        metadata.privilege_requirement.description()
    ));
}

/// The parts of a mode's documentation after its facts: description, startup parameters,
/// example prompt, keywords and notes.
fn render_mode_description<P: crate::llm::actions::protocol_trait::Protocol + ?Sized>(
    out: &mut String,
    p: &P,
) {
    let metadata = p.metadata();
    out.push_str(&format!(
        "**History:** {}\n**Batching:** {}\n\n",
        metadata.history.describe(),
        metadata.batching.describe()
    ));

    out.push_str("## Description\n\n");
    out.push_str(&format!("{}\n\n", p.description()));

    let startup_params = p.get_startup_parameters();
    if !startup_params.is_empty() {
        out.push_str("## Startup Parameters\n\nPassed as `startup_params`; a key not listed here is an error.\n\n");
        for param in &startup_params {
            crate::protocol::docs::render_startup_param(out, param);
        }
        out.push('\n');
    }

    out.push_str("## Example Prompt\n\n");
    out.push_str(&format!("{}\n\n", p.example_prompt()));

    if !p.keywords().is_empty() {
        out.push_str("## Keywords\n\n");
        out.push_str(&format!("{}\n\n", p.keywords().join(", ")));
    }

    if let Some(notes) = metadata.notes {
        out.push_str("## Notes\n\n");
        out.push_str(&format!("{}\n\n", notes));
    }
}

/// Events with their fields, then the response actions and the instance's own actions with
/// their parameters. `events_intro` / `own_intro` are the mode's framing.
fn render_mode_reference<P: crate::llm::actions::protocol_trait::Protocol + ?Sized>(
    out: &mut String,
    p: &P,
    state: &crate::state::AppState,
    own_heading: &str,
    own_intro: &str,
) {
    use crate::protocol::docs::{instance_only_actions, render_action, render_event};

    let events = p.get_event_types();
    if !events.is_empty() {
        let ids: Vec<String> = events.iter().map(|e| format!("`{}`", e.id)).collect();
        out.push_str(&format!(
            "## Events ({}) — valid `event_pattern` values for event handlers\n\n",
            ids.join(", ")
        ));
        for event in &events {
            render_event(out, event, "###");
        }
    }

    let sync_actions = p.get_sync_actions();
    if !sync_actions.is_empty() {
        out.push_str("## Response Actions\n\nThe action objects that answer an event — what you, a script (inside `{\"actions\":[…]}`) or a static handler (`handler.actions`) return.\n\n");
        for action in &sync_actions {
            render_action(out, action, "###");
        }
    }

    let own = instance_only_actions(p, &sync_actions, state);
    if !own.is_empty() {
        out.push_str(&format!("## {own_heading}\n\n{own_intro}\n\n"));
        for action in &own {
            render_action(out, action, "###");
        }
    }
}

fn render_server_mode(
    out: &mut String,
    server: &dyn crate::llm::actions::protocol_trait::Server,
    state: &crate::state::AppState,
) {
    let metadata = server.metadata();
    out.push_str(&format!("# {} (Server Mode)\n\n", server.protocol_name()));
    out.push_str("**Mode:** Server - listens for incoming connections\n");
    render_mode_header(out, server);
    let interface_bound = server
        .default_binding()
        .is_some_and(|b| b.interface.is_some());
    if interface_bound {
        out.push_str("**Binding:** interface-bound — it captures on a network interface (`interface`), not a port\n");
    } else {
        out.push_str(&format!(
            "**Port:** {}\n",
            crate::protocol::docs::well_known_port_text(&metadata)
        ));
    }
    out.push_str(&format!(
        "**When the model cannot answer:** {}\n",
        crate::protocol::docs::failure_mode_text(metadata.failure_mode)
    ));
    render_mode_description(out, server);

    // Concrete `open_server` examples for THIS protocol in each handler mode, from its own
    // `get_startup_examples()`. Shown only for the protocol the model asked about, so it
    // costs nothing on the always-on system prompt.
    out.push_str(&crate::protocol::docs::server_startup_examples_text(
        server.get_startup_examples(),
    ));

    render_mode_reference(
        out,
        server,
        state,
        "Server-level Actions",
        "Not tied to one event: what you can do on a running server of this protocol on your own initiative.",
    );
    out.push_str("\n---\n\n");
}

fn render_client_mode(
    out: &mut String,
    name: &str,
    client: &dyn crate::llm::actions::client_trait::Client,
    state: &crate::state::AppState,
) {
    out.push_str(&format!("# {} (Client Mode)\n\n", name));
    out.push_str("**Mode:** Client - connects to remote servers\n");
    render_mode_header(out, client);
    render_mode_description(out, client);
    render_mode_reference(
        out,
        client,
        state,
        "Client Actions",
        "What the client can do on its own initiative, such as sending a request.",
    );
    out.push_str("\n---\n\n");
}

/// Execute list_tasks tool
async fn execute_list_tasks(state: &crate::state::AppState) -> ToolResult {
    use tracing::info;

    info!("🔧 Tool: list_tasks - listing all scheduled tasks");

    let tasks = state.get_all_tasks().await;
    if tasks.is_empty() {
        ToolResult::success(
            "list_tasks",
            "no tasks".to_string(),
            "No scheduled tasks".to_string(),
        )
    } else {
        let task_count = tasks.len();
        let mut result = format!("{} scheduled task(s):\n", task_count);
        for task in &tasks {
            result.push_str(&format!("  {}\n", task.format_for_prompt()));
        }

        info!("  ✓ Listed {} task(s)", task_count);
        ToolResult::success("list_tasks", task_count.to_string(), result)
    }
}

/// Execute execute_sql tool
#[cfg(feature = "sqlite")]
async fn execute_execute_sql(
    state: &crate::state::AppState,
    database_id: u32,
    query: &str,
) -> ToolResult {
    use tracing::info;

    info!(
        "🔧 Tool: execute_sql - db-{} query=\"{}\"",
        database_id, query
    );

    let db_id = crate::state::DatabaseId::new(database_id);

    match state.execute_sql(db_id, query).await {
        Ok(result) => {
            let formatted = result.format();

            // Get updated database info
            let db_info = if let Some(db) = state.get_database(db_id).await {
                format!("\nDatabase: {}", db.schema_summary())
            } else {
                String::new()
            };

            let output = format!("Query result:\n{}{}", formatted, db_info);

            info!("  ✓ Query executed successfully");
            ToolResult::success("execute_sql", query.to_string(), output)
        }
        Err(e) => {
            let error_msg = format!("SQL error: {}", e);
            info!("  ✗ Query failed: {}", e);
            ToolResult::error("execute_sql", query.to_string(), error_msg)
        }
    }
}

/// Execute list_databases tool
#[cfg(feature = "sqlite")]
async fn execute_list_databases(state: &crate::state::AppState) -> ToolResult {
    use tracing::info;

    info!("🔧 Tool: list_databases - listing all databases");

    let databases = state.get_all_databases().await;
    if databases.is_empty() {
        ToolResult::success(
            "list_databases",
            "no databases".to_string(),
            "No databases".to_string(),
        )
    } else {
        let db_count = databases.len();
        let mut result = format!("{} database(s):\n", db_count);
        for db in &databases {
            result.push_str(&format!("  {}\n", db.schema_summary()));
        }

        info!("  ✓ Listed {} database(s)", db_count);
        ToolResult::success("list_databases", db_count.to_string(), result)
    }
}
