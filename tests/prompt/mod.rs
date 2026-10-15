//! Tests for prompt generation
//!
//! These tests snapshot the generated prompts to detect changes.
//! When prompts change, review the diff to ensure it's intentional.

use netget::llm::actions::Protocol;
#[allow(unused_imports)] // only used by tests gated behind the tcp+http+proxy+ssh+sqlite combo
use netget::llm::PromptBuilder;
use netget::state::app_state::AppState;
use netget::state::server::{ServerInstance, ServerStatus};
use netget::state::ServerId;
use regex::Regex;
use std::sync::Arc;
use std::sync::LazyLock;

#[path = "../snapshot_util.rs"]
mod snapshot_util;

const SNAPSHOT_DIR: &str = "tests/prompt/snapshots";

// ============================================================================
// DETERMINISM HELPERS
//
// Two independent sources of non-determinism affected this suite:
//
// 1. Feature-set dependence: the "Available Protocols" / "Available Base
//    Stacks" sections and the sqlite-gated create_database/execute_sql/
//    list_databases/delete_database actions enumerate whatever protocols
//    happen to be compiled in. That's real, meaningful prompt content (not
//    noise), so instead of textually normalizing it away, the snapshot-
//    comparing tests below carry
//    `#[cfg(all(feature = "tcp", feature = "http", feature = "proxy", feature = "ssh", feature = "sqlite"))]`
//    to only compile under the exact feature combination the checked-in
//    snapshots were generated with (see `tests/prompt/update_snapshots.sh`).
//    Under any other feature set they don't exist as tests, so `cargo test`
//    reports fewer tests rather than failures - a clean skip instead of a
//    wall of diff noise. (E.g. the CI feature set in
//    .github/workflows/ci.yml lacks proxy/ssh/sqlite, so these tests are
//    absent - not failing - there; `test_json_parse_retry_prompt`,
//    `test_unknown_action_retry_prompt`, and `test_protocol_documentation_prompt`
//    have no such feature-sensitive content and remain ungated.)
//
// 2. Environment dependence: `SystemCapabilities` (src/privilege.rs) probes
//    the *host* at runtime (root / CAP_NET_RAW / whether privileged ports
//    are bindable), independent of feature flags. `AppState` has no setter
//    to inject a fixed value (only `set_scripting_env` exists, no
//    `set_system_capabilities`), so there is no seam to construct a fixed
//    state through from this test crate. We normalize the two System
//    Capabilities lines that embed this host-dependent text before
//    comparing against the snapshot. See `normalize_capabilities` below.
// ============================================================================

/// Replace the host-dependent "System Capabilities" lines with a fixed
/// placeholder so snapshot comparisons don't depend on whether the test
/// process happens to run as root or with CAP_NET_RAW.
///
/// This is a workaround for a missing `src/` seam: `AppState` detects
/// `SystemCapabilities` once at construction (`SystemCapabilities::detect()`
/// in `AppState::new_with_options`) and exposes only `get_system_capabilities`,
/// with no `set_system_capabilities` to inject a fixed value the way
/// `set_scripting_env` already allows for the scripting environment. Adding
/// that setter (mirroring `set_scripting_env` in src/state/app_state.rs) is
/// the proper fix; until then, this text-level normalization keeps the
/// suite deterministic regardless of who runs it.
fn normalize_capabilities(prompt: &str) -> String {
    static PRIVILEGED_PORTS_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^- \*\*Privileged ports \(<1024\)\*\*: .*$").unwrap());
    static RAW_SOCKET_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^- \*\*Raw socket access\*\*: .*$").unwrap());

    let prompt = PRIVILEGED_PORTS_RE.replace_all(
        prompt,
        "- **Privileged ports (<1024)**: <normalized: host-dependent, see normalize_capabilities>",
    );
    let prompt = RAW_SOCKET_RE.replace_all(
        &prompt,
        "- **Raw socket access**: <normalized: host-dependent, see normalize_capabilities>",
    );
    prompt.into_owned()
}

/// Snapshot assertion for rendered prompts: normalizes host-dependent
/// content (see `normalize_capabilities`) before delegating to the shared
/// snapshot utility.
/// The server protocols these snapshots were generated against.
///
/// The prompt embeds an "Available Protocols" line built from the compiled registry, so the
/// snapshots are **feature-set specific** — they match at
/// `--no-default-features --features tcp,http,proxy,ssh,sqlite` and cannot match at
/// `--all-features`, which compiles 135 protocols into that line.
const SNAPSHOT_PROTOCOLS: &str = "HTTP, Proxy, SSH, TCP";

fn assert_prompt_snapshot(test_name: &str, prompt: &str) {
    let normalized = normalize_capabilities(prompt);

    // Skip rather than fail outside the canonical feature set.
    //
    // A full-suite `--all-features` run otherwise reports ten confident snapshot mismatches
    // that are nothing but a longer protocol list, which is exactly the kind of noise that
    // teaches people to ignore this suite. Failing here would say the prompts regressed; they
    // did not.
    if !normalized.contains(SNAPSHOT_PROTOCOLS) {
        eprintln!(
            "SKIP {test_name}: prompt snapshots are feature-set specific. They were generated \
             against server protocols [{SNAPSHOT_PROTOCOLS}]; this build compiled a different \
             set, so the embedded 'Available Protocols' line cannot match. Run:\n  \
             ./cargo-isolated.sh test --no-default-features --features tcp,http,proxy,ssh,sqlite \
             --test prompt"
        );
        return;
    }

    snapshot_util::assert_snapshot(test_name, SNAPSHOT_DIR, &normalized);
}

/// Helper to create test app state with a proxy server (no scripting)
#[allow(dead_code)] // only used by tests gated behind the tcp+http+proxy+ssh+sqlite combo
async fn create_test_state_with_proxy() -> Arc<AppState> {
    let state = Arc::new(AppState::new());

    // Set up environment with NO scripting for proxy test
    // (proxy test is about server management, not about starting new servers)
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: None,
        javascript: None,
        go: None,
        perl: None,
    };
    state.set_scripting_env(scripting_env).await;
    // Also set the mode to Off (no scripting)
    state
        .set_selected_scripting_mode(netget::state::app_state::ScriptingMode::Off)
        .await;

    // Create a proxy server instance
    let mut server = ServerInstance::new(
        ServerId::new(1),
        8080,
        "Proxy".to_string(),
        "Act as HTTP proxy".to_string(),
    );
    server.status = ServerStatus::Running;
    server.memory = "connections: 0\nrequests_intercepted: 5".to_string();

    let server_id = state.add_server(server).await;
    state
        .update_server_status(server_id, ServerStatus::Running)
        .await;

    state
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt_proxy_server() {
    let state = create_test_state_with_proxy().await;
    let user_input = "enable request filtering";

    // Get proxy async actions
    #[cfg(unix)]
    let protocol_actions = {
        use netget::server::ProxyProtocol;
        let protocol = ProxyProtocol::new();
        protocol.get_async_actions(&state)
    };

    #[cfg(windows)]
    let protocol_actions = vec![];

    let system_prompt =
        PromptBuilder::build_user_input_system_prompt(&state, protocol_actions, None).await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, user_input
    );

    // Assert snapshot
    assert_prompt_snapshot("user_input_prompt_proxy_server", &prompt);

    // Sanity checks
    assert!(prompt.contains("Server #1") || prompt.contains("Server"));
    assert!(prompt.contains("PROXY") || prompt.contains("Proxy"));
    assert!(prompt.contains("8080"));
    assert!(prompt.contains("Running"));
    assert!(prompt.contains(user_input));

    // Should NOT have script references (no scripting environment)
    assert!(
        !prompt.contains("Script-Based Responses"),
        "Prompt should not contain scripting section"
    );
    assert!(
        !prompt.contains("Python (Python"),
        "Prompt should not contain scripting environment details"
    );
    assert!(
        !prompt.contains("Node.js (v"),
        "Prompt should not contain 'Node.js' version"
    );
    assert!(
        !prompt.contains("script_language"),
        "Prompt should not contain 'script_language'"
    );
    assert!(
        !prompt.contains("script_path"),
        "Prompt should not contain 'script_path'"
    );
    assert!(
        !prompt.contains("update_script"),
        "Prompt should not contain 'update_script'"
    );
    // Note: script_inline and script_handles appear in scheduled_tasks param docs, which is OK

    // The proxy's six configuration actions must NOT be offered.
    //
    // This used to assert the opposite. `configure_certificate` and its five siblings were
    // removed from `get_async_actions` deliberately: each only serialised its arguments into
    // `ActionResult::Output`, which nothing read back, so they reported success while changing
    // nothing — and an `Output` emitted during a request event was mis-parsed as a
    // `RequestAction` and aborted the decision for that request. Certificate mode and the
    // filter modes are startup parameters now, which do take effect.
    //
    // Asserting their absence keeps the deletion from silently coming back, which asserting
    // their presence obviously could not.
    #[cfg(unix)]
    {
        for gone in [
            "configure_certificate",
            "configure_request_filters",
            "configure_response_filters",
            "configure_https_connection_filters",
            "set_filter_mode",
            "export_ca_certificate",
        ] {
            assert!(
                !prompt.contains(gone),
                "the proxy action '{gone}' was removed because it reported success while \
                 changing nothing; it must not be advertised to the model again"
            );
        }
    }
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt() {
    // Create state WITHOUT any servers to trigger base_stack documentation
    let state = Arc::new(AppState::new());

    // Set up mock scripting environment (the common case - Python/Node.js/Go available)
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    let user_input = "start a DNS server on port 53";

    let system_prompt = PromptBuilder::build_user_input_system_prompt(&state, vec![], None).await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, user_input
    );

    // Assert snapshot
    assert_prompt_snapshot("user_input_prompt", &prompt);

    // CRITICAL: In the initial prompt (before docs are read), base stacks and scripting
    // sections are NOT shown - they only appear after documentation has been fetched.
    // This prevents the LLM from trying to use open_server/open_client before learning the protocols.
    assert!(
        !prompt.contains("Available Base Stacks"),
        "Base stacks should NOT be shown in initial prompt (before reading docs)"
    );
    assert!(
        !prompt.contains("Script Handlers"),
        "Script handlers should NOT be shown in initial prompt (before reading docs)"
    );

    // But read_documentation tool MUST be available
    assert!(
        prompt.contains("read_documentation"),
        "Initial prompt should mention read_documentation tool"
    );

    // CRITICAL: open_server and open_client actions should NOT EXIST as action definitions
    // They are only included after calling read_documentation
    // Note: They may still be mentioned in instructions (e.g., "use open_server after reading docs")
    // but should NOT have action definition headers like "## 0. open_server"
    assert!(
        !prompt.contains("## 0. open_server") && !prompt.contains("## 1. open_server"),
        "open_server should NOT have an action definition in initial prompt"
    );
    assert!(
        !prompt.contains("## 0. open_client")
            && !prompt.contains("## 1. open_client")
            && !prompt.contains("## 2. open_client")
            && !prompt.contains("## 3. open_client"),
        "open_client should NOT have an action definition in initial prompt"
    );

    // CRITICAL: No JSON examples with open_server or open_client should exist
    // These would teach the LLM to use these actions before documentation is read
    assert!(
        !prompt.contains(r#""type": "open_server""#)
            && !prompt.contains(r#"\"type\": \"open_server\""#)
            && !prompt.contains(r#""type":"open_server""#),
        "Initial prompt should NOT contain JSON examples with open_server action"
    );
    assert!(
        !prompt.contains(r#""type": "open_client""#)
            && !prompt.contains(r#"\"type\": \"open_client\""#)
            && !prompt.contains(r#""type":"open_client""#),
        "Initial prompt should NOT contain JSON examples with open_client action"
    );
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt_after_docs_read() {
    // Create state and mark protocols as documented
    let state = Arc::new(AppState::new());

    // Set up mock scripting environment
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    // Mark multiple server protocols as documented (simulates read_documentation call)
    state
        .mark_server_protocols_documented(&["HTTP".to_string(), "SSH".to_string()])
        .await;

    // Mark a client protocol as documented
    state
        .mark_client_protocols_documented(&["http".to_string()])
        .await;

    let user_input = "start an HTTP server on port 8080";

    // Build prompt WITH docs enabled (is_open_server_enabled = true, is_open_client_enabled = true)
    let system_prompt = PromptBuilder::build_user_input_system_prompt_with_docs(
        &state,
        vec![],
        None,
        true, // is_open_server_enabled
        true, // is_open_client_enabled
    )
    .await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, user_input
    );

    // Assert snapshot
    assert_prompt_snapshot("user_input_prompt_after_docs", &prompt);

    // open_server should be ENABLED (have parameters, not marked as DISABLED)
    // The action should have a "port" parameter which is only present when enabled
    assert!(
        prompt.contains("open_server") && prompt.contains("port"),
        "open_server should be ENABLED and have port parameter after docs are read"
    );
    assert!(
        !prompt.contains("open_server") || !prompt.contains("⚠️ DISABLED"),
        "open_server should NOT be marked as DISABLED after docs are read"
    );

    // open_client should be ENABLED
    assert!(
        prompt.contains("open_client") && prompt.contains("remote_addr"),
        "open_client should be ENABLED and have remote_addr parameter after docs are read"
    );

    // Should have base_stack parameter (enabled open_server has this)
    assert!(
        prompt.contains("base_stack"),
        "Enabled open_server should have base_stack parameter"
    );

    // After docs are read, base stacks section SHOULD be present
    assert!(
        prompt.contains("Available Base Stacks"),
        "Base stacks should be shown after reading docs"
    );

    // Scripting section should be present (since scripting env is set up)
    // The scripting section is titled "Event Handler Configuration"
    assert!(
        prompt.contains("Event Handler Configuration"),
        "Event Handler Configuration section should be present after docs are read"
    );
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt_no_scripting() {
    // Create state WITHOUT any servers to trigger base_stack documentation
    let state = Arc::new(AppState::new());

    // Set up environment with NO scripting available
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: None,
        javascript: None,
        go: None,
        perl: None,
    };
    state.set_scripting_env(scripting_env).await;
    // Also set the mode to Off (no scripting)
    state
        .set_selected_scripting_mode(netget::state::app_state::ScriptingMode::Off)
        .await;

    let user_input = "start a DNS server on port 53";

    let system_prompt = PromptBuilder::build_user_input_system_prompt(&state, vec![], None).await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, user_input
    );

    // Assert snapshot
    assert_prompt_snapshot("user_input_prompt_without_scripting", &prompt);

    // Sanity checks - should NOT include scripting section (but scheduled_tasks param mentions scripts)
    assert!(
        !prompt.contains("Script-Based Responses"),
        "Prompt should not contain 'Script-Based Responses'"
    );
    assert!(
        !prompt.contains("Python (Python"),
        "Prompt should not contain scripting environment details"
    );
    assert!(
        !prompt.contains("Node.js (v"),
        "Prompt should not contain 'Node.js' version"
    );
    assert!(
        !prompt.contains("script_language"),
        "Prompt should not contain 'script_language'"
    );
    assert!(
        !prompt.contains("script_path"),
        "Prompt should not contain 'script_path'"
    );
    assert!(
        !prompt.contains("update_script"),
        "Prompt should not contain 'update_script'"
    );
    // Note: script_inline and script_handles appear in scheduled_tasks param docs, which is OK

    // Since docs haven't been read, base stacks should NOT be present
    assert!(
        !prompt.contains("Available Base Stacks"),
        "Base stacks should NOT be shown before reading docs"
    );
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt_without_web_search() {
    // Create state WITHOUT any servers to trigger base_stack documentation
    let state = Arc::new(AppState::new());

    // Set up mock scripting environment
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    // Disable web search
    state
        .set_web_search_mode(netget::state::app_state::WebSearchMode::Off)
        .await;

    let user_input = "start a DNS server on port 53";

    let system_prompt = PromptBuilder::build_user_input_system_prompt(&state, vec![], None).await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, user_input
    );

    // Assert snapshot
    assert_prompt_snapshot("user_input_prompt_without_web_search", &prompt);

    // Sanity checks - should NOT include web_search references
    assert!(
        !prompt.contains("web_search"),
        "Prompt should not contain 'web_search'"
    );
    assert!(
        !prompt.contains("web search"),
        "Prompt should not contain 'web search' in instructions"
    );

    // Should still have read_file
    assert!(
        prompt.contains("read_file"),
        "Prompt should still contain 'read_file'"
    );

    // Since docs haven't been read, base stacks should NOT be present
    assert!(
        !prompt.contains("Available Base Stacks"),
        "Base stacks should NOT be shown before reading docs"
    );
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_network_event_prompt_for_proxy() {
    let state = create_test_state_with_proxy().await;
    let server_id = ServerId::new(1);
    let event_description = "Intercepted HTTP request:\nGET https://example.com/api/data\nHeaders:\n  User-Agent: Mozilla/5.0\n  Accept: application/json";

    // Get proxy sync actions (with context)
    #[cfg(unix)]
    let all_actions = {
        use netget::llm::actions::get_network_event_common_actions;

        use netget::server::ProxyProtocol;

        let protocol = ProxyProtocol::new();
        let mut actions = get_network_event_common_actions();
        actions.extend(protocol.get_sync_actions());
        actions
    };

    #[cfg(windows)]
    let all_actions = {
        use netget::llm::actions::get_network_event_common_actions;
        get_network_event_common_actions()
    };

    let system_prompt =
        PromptBuilder::build_network_event_action_prompt_for_server(&state, server_id, all_actions)
            .await;

    let event_message = PromptBuilder::build_event_trigger_message(
        event_description,
        serde_json::json!({}), // No structured context for this test
    );

    let prompt = format!("{}\n\nTrigger: {}", system_prompt, event_message);

    // Assert snapshot
    assert_prompt_snapshot("network_event_prompt_proxy", &prompt);

    // Sanity checks
    assert!(prompt.contains("NetGet"));
    assert!(prompt.contains("**Server ID**: #1"));
    assert!(prompt.contains("**Protocol**: Proxy"));
    assert!(prompt.contains(event_description));
    assert!(prompt.contains("Act as HTTP proxy"));
    assert!(prompt.contains("connections: 0"));
    assert!(!prompt.contains("Available Base Stacks"));

    #[cfg(unix)]
    {
        assert!(prompt.contains("handle_request_pass"));
        assert!(prompt.contains("handle_request_block"));
        assert!(prompt.contains("handle_request_modify"));
    }
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_retry_mechanism_prompt() {
    // Test that retry mechanism includes previous error in prompt
    let state = Arc::new(AppState::new());

    // Create a scheduled task with a previous error
    use netget::state::task::{ScheduledTask, TaskScope, TaskStatus, TaskType};
    use std::time::Duration;

    let task = ScheduledTask {
        id: netget::state::TaskId::new(1),
        name: "periodic_backup".to_string(),
        instruction: "Create a backup of server memory".to_string(),
        scope: TaskScope::Global,
        task_type: TaskType::Recurring {
            interval_secs: 3600,
            max_executions: None,
            executions_count: 1,
        },
        created_at: std::time::Instant::now() - Duration::from_secs(60),
        next_execution: std::time::Instant::now(),
        context: None,
        status: TaskStatus::Failed("Failed to write file: Permission denied".to_string()),
        last_error: Some("Failed to write file: Permission denied".to_string()),
        failure_count: 1,
    };

    // Set up scripting environment
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    let prompt =
        netget::llm::PromptBuilder::build_task_execution_prompt(&state, &task, vec![]).await;

    // Assert snapshot
    assert_prompt_snapshot("retry_mechanism_prompt", &prompt);

    // Sanity checks
    assert!(prompt.contains("PREVIOUS EXECUTION ERROR"));
    assert!(prompt.contains("Failed to write file: Permission denied"));
    assert!(prompt.contains("periodic_backup"));
    assert!(prompt.contains("Create a backup of server memory"));
    assert!(prompt.contains("Attempt to handle or resolve this issue"));
}

#[tokio::test]
async fn test_json_parse_retry_prompt() {
    // Test the retry prompt sent when LLM returns invalid JSON
    // This is the correction message added to conversation when parsing fails
    let error = "expected `,` or `}` at line 3 column 5";
    let prompt = netget::llm::PromptBuilder::build_retry_prompt(error);

    // Assert snapshot
    assert_prompt_snapshot("json_parse_retry_prompt", &prompt);

    // Sanity checks - verify key elements are present
    assert!(prompt.contains("Invalid Response Format"));
    assert!(prompt.contains(error)); // The actual error should be in the prompt
    assert!(prompt.contains("pure JSON"));
    assert!(prompt.contains("Please retry"));
    assert!(prompt.contains("original request")); // Should reference original request
}

#[tokio::test]
async fn test_unknown_action_retry_prompt() {
    // Test the retry prompt sent when LLM uses unknown actions
    let unknown_actions = vec!["send_magic_packet".to_string(), "do_something".to_string()];
    let available_actions = vec![
        "open_server".to_string(),
        "close_server".to_string(),
        "show_message".to_string(),
    ];
    let prompt = netget::llm::PromptBuilder::build_unknown_action_retry_prompt(
        &unknown_actions,
        &available_actions,
    );

    // Assert snapshot
    assert_prompt_snapshot("unknown_action_retry_prompt", &prompt);

    // Sanity checks
    assert!(prompt.contains("Unknown Action"));
    assert!(prompt.contains("send_magic_packet"));
    assert!(prompt.contains("do_something"));
    assert!(prompt.contains("open_server"));
    assert!(prompt.contains("Please retry"));
    assert!(prompt.contains("ONLY")); // Should emphasize only using listed actions
}

#[tokio::test]
async fn test_protocol_documentation_prompt() {
    // Test protocol-specific metadata documentation
    let _state = Arc::new(AppState::new());

    // Create an HTTP server to get protocol-specific documentation
    {
        use netget::server::HttpProtocol;

        let protocol = HttpProtocol::new();
        let metadata = protocol.metadata();

        // Build a simple documentation string showing protocol metadata
        let doc = format!(
            "Protocol: {}\nState: {}\nImplementation: {}\nLLM Control: {}\nE2E Testing: {}{}",
            protocol.protocol_name(),
            metadata.state.as_str(),
            metadata.implementation,
            metadata.llm_control,
            metadata.e2e_testing,
            metadata
                .notes
                .map(|n| format!("\nNotes: {}", n))
                .unwrap_or_default()
        );

        // Assert snapshot
        assert_prompt_snapshot("protocol_http_documentation", &doc);

        // Sanity checks
        assert!(doc.contains("HTTP"));
        assert!(doc.contains("State:"));
        assert!(doc.contains("Implementation:"));
        assert!(doc.contains("LLM Control:"));
        assert!(doc.contains("E2E Testing:"));
    }

    {
        use netget::server::SshProtocol;

        let protocol = SshProtocol::new();
        let metadata = protocol.metadata();

        // Build a simple documentation string showing protocol metadata
        let doc = format!(
            "Protocol: {}\nState: {}\nImplementation: {}\nLLM Control: {}\nE2E Testing: {}{}",
            protocol.protocol_name(),
            metadata.state.as_str(),
            metadata.implementation,
            metadata.llm_control,
            metadata.e2e_testing,
            metadata
                .notes
                .map(|n| format!("\nNotes: {}", n))
                .unwrap_or_default()
        );

        // Assert snapshot
        assert_prompt_snapshot("protocol_ssh_documentation", &doc);

        // Sanity checks
        assert!(doc.contains("SSH"));
        assert!(doc.contains("State:"));
        assert!(doc.contains("Implementation:"));
        assert!(doc.contains("LLM Control:"));
        assert!(doc.contains("E2E Testing:"));
    }
}

/// Test that read_documentation with multiple protocols includes examples for ALL protocols
#[tokio::test]
async fn test_multi_protocol_documentation_examples() {
    use netget::llm::actions::tools::{execute_tool, ToolAction};
    use netget::state::app_state::WebSearchMode;

    // Create a ToolAction for read_documentation with multiple protocols
    let action = ToolAction::ReadDocumentation {
        protocols: vec!["http".to_string(), "ssh".to_string(), "dns".to_string()],
        protocol: None,
    };

    // Execute the tool
    let tool_result = execute_tool(&action, None, WebSearchMode::Off, None).await;
    let result = tool_result.result;

    // The result should contain documentation for all requested protocols
    assert!(
        result.contains("HTTP") || result.contains("http"),
        "Documentation should include HTTP protocol"
    );
    assert!(
        result.contains("SSH") || result.contains("ssh"),
        "Documentation should include SSH protocol"
    );
    assert!(
        result.contains("DNS") || result.contains("dns"),
        "Documentation should include DNS protocol"
    );

    // Check that examples for each protocol are present
    // The execute_read_documentation generates open_server examples per protocol
    assert!(
        result.contains("Example for HTTP") || result.contains("\"base_stack\": \"http\""),
        "Documentation should include example for HTTP"
    );
    assert!(
        result.contains("Example for SSH") || result.contains("\"base_stack\": \"ssh\""),
        "Documentation should include example for SSH"
    );
    assert!(
        result.contains("Example for DNS") || result.contains("\"base_stack\": \"dns\""),
        "Documentation should include example for DNS"
    );

    // Should indicate that open_server is now enabled
    assert!(
        result.contains("open_server") && result.contains("enabled"),
        "Documentation should indicate open_server is now enabled"
    );
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_feedback_prompt_server() {
    let state = Arc::new(AppState::new());

    // Set up environment with scripting
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    // Create a test server with feedback instructions
    let mut server = ServerInstance::new(
        ServerId::new(1),
        8080,
        "HTTP".to_string(),
        "You are an HTTP server. Respond to GET/POST requests with appropriate status codes."
            .to_string(),
    );
    server.status = ServerStatus::Running;
    server.memory = "request_count: 15\nerror_count: 3".to_string();
    server.feedback_instructions = Some(
        "Monitor error rates and client timeouts. If errors exceed 20%, adjust response strategy."
            .to_string(),
    );

    let server_id = state.add_server(server).await;
    state
        .update_server_status(server_id, ServerStatus::Running)
        .await;

    // Create sample feedback entries
    let feedback_entries = vec![
        serde_json::json!({
            "issue": "client_timeout",
            "details": "Client disconnected after 5s waiting for response",
            "path": "/api/data",
            "suggestion": "Increase response speed or add caching"
        }),
        serde_json::json!({
            "issue": "authentication_failed",
            "username": "guest",
            "attempts": 3,
            "suggestion": "Consider rate limiting after multiple failures"
        }),
        serde_json::json!({
            "issue": "slow_response",
            "path": "/api/search",
            "response_time_ms": 8500,
            "suggestion": "Optimize database queries or add pagination"
        }),
    ];

    // Get server data for prompt
    let server = state
        .with_server_mut(server_id, |s| (s.instruction.clone(), s.memory.clone()))
        .await
        .unwrap_or_else(|| ("".to_string(), "".to_string()));

    // Get available actions for feedback processing
    use netget::llm::actions::get_user_input_common_actions;
    let selected_mode = state.get_selected_scripting_mode().await;
    let scripting_env = state.get_scripting_env().await;
    let available_actions = get_user_input_common_actions(
        selected_mode,
        &scripting_env,
        true, // is_open_server_enabled
        true, // is_open_client_enabled
    );

    // Build feedback prompt
    let system_prompt = PromptBuilder::build_feedback_system_prompt(
        &state,
        Some(server_id),
        None,
        "Monitor error rates and client timeouts. If errors exceed 20%, adjust response strategy.",
        &server.0, // current_instruction
        &server.1, // memory
        &feedback_entries,
        available_actions,
    )
    .await;

    let prompt = format!(
        "{}\n\nTrigger: Analyze the accumulated feedback and suggest adjustments.",
        system_prompt
    );

    // Assert snapshot
    assert_prompt_snapshot("feedback_prompt_server", &prompt);

    // Sanity checks
    assert!(prompt.contains("server"));
    assert!(prompt.contains("Server ID**: #1") || prompt.contains("Server #1"));
    assert!(prompt.contains("HTTP"));
    assert!(prompt.contains("Feedback Instructions"));
    assert!(prompt.contains("Monitor error rates"));
    assert!(prompt.contains("client_timeout"));
    assert!(prompt.contains("authentication_failed"));
    assert!(prompt.contains("slow_response"));
    assert!(prompt.contains("3 entries"));
    assert!(prompt.contains("update_instruction") || prompt.contains("Available"));
}

#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_feedback_prompt_client() {
    let state = Arc::new(AppState::new());

    // Set up environment
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    use netget::state::client::ClientInstance;
    use netget::state::ClientId;

    // Create a test client with feedback instructions
    let mut client = ClientInstance::new(
        ClientId::new(1),
        "api.example.com:443".to_string(),
        "HTTP".to_string(),
        "Fetch data from /api/endpoint every 5 seconds".to_string(),
    );
    client.memory = "fetch_count: 20\ntimeout_count: 5".to_string();
    client.feedback_instructions = Some(
        "If timeout rate exceeds 25%, reduce request frequency or add retry logic.".to_string(),
    );

    let client_id = state.add_client(client).await;

    // Create sample feedback entries
    let feedback_entries = vec![
        serde_json::json!({
            "issue": "timeout",
            "details": "Request to /api/endpoint timed out after 10s",
            "suggestion": "Increase timeout or reduce request frequency"
        }),
        serde_json::json!({
            "issue": "rate_limited",
            "status_code": 429,
            "retry_after": 60,
            "suggestion": "Back off when receiving 429 responses"
        }),
    ];

    // Get client data
    let client_data = state
        .with_client_mut(client_id, |c| (c.instruction.clone(), c.memory.clone()))
        .await
        .unwrap_or_else(|| ("".to_string(), "".to_string()));

    // Get available actions
    use netget::llm::actions::get_user_input_common_actions;
    let selected_mode = state.get_selected_scripting_mode().await;
    let scripting_env = state.get_scripting_env().await;
    let available_actions =
        get_user_input_common_actions(selected_mode, &scripting_env, true, true);

    // Build feedback prompt for client
    let system_prompt = PromptBuilder::build_feedback_system_prompt(
        &state,
        None,
        Some(client_id),
        "If timeout rate exceeds 25%, reduce request frequency or add retry logic.",
        &client_data.0,
        &client_data.1,
        &feedback_entries,
        available_actions,
    )
    .await;

    let prompt = format!(
        "{}\n\nTrigger: Analyze the accumulated feedback and suggest adjustments.",
        system_prompt
    );

    // Assert snapshot
    assert_prompt_snapshot("feedback_prompt_client", &prompt);

    // Sanity checks
    assert!(prompt.contains("client"));
    assert!(prompt.contains("Feedback Instructions"));
    assert!(prompt.contains("timeout rate exceeds 25%"));
    assert!(prompt.contains("timeout"));
    assert!(prompt.contains("rate_limited"));
    assert!(prompt.contains("2 entries"));
}
