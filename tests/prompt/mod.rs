//! Tests for prompt generation
//!
//! These tests snapshot the generated prompts to detect changes.
//! When prompts change, review the diff to ensure it's intentional.
//!
//! Regenerate every snapshot from the current code (then READ the diff — a regenerated
//! snapshot proves nothing by itself):
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 ./cargo-isolated.sh test --test prompt --test prompt_snapshots
//! ```
//!
//! or `tests/prompt/update_snapshots.sh`, which runs exactly that.

use netget::llm::actions::Protocol;
#[allow(unused_imports)]
// the Unix+sqlite tests use it; see `prompt_snapshots_need_unix_and_sqlite`
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

/// Every snapshot this suite compares, which is every `*.snap.md` in [`SNAPSHOT_DIR`].
/// `snapshot_comparison_is_live` holds the directory, this list and the calls in this file
/// to each other, so a snapshot cannot sit on disk with nothing comparing it.
const SNAPSHOTS: &[&str] = &[
    "feedback_prompt_client",
    "feedback_prompt_server",
    "json_parse_retry_prompt",
    "network_event_prompt_proxy",
    "protocol_http_documentation",
    "protocol_http_mcp_documentation",
    "protocol_ssh_documentation",
    "protocol_ssh_mcp_documentation",
    "retry_mechanism_prompt",
    "unknown_action_retry_prompt",
    "user_input_prompt",
    "user_input_prompt_docs_gate",
    "user_input_prompt_proxy_server",
    "user_input_prompt_without_scripting",
    "user_input_prompt_without_web_search",
];

// ============================================================================
// DETERMINISM
//
// A snapshot must say the same thing on every build and every machine, and must still
// compare everything the test exists for: the prompts' structure, instructions, action
// definitions and wording. Three kinds of content are not that, and each is replaced by a
// fixed placeholder before comparison:
//
// 1. The compiled protocol registry. Every build compiles every protocol (there are no
//    protocol features), and protocols are added continuously, so the lists enumerating
//    the registry change with every new protocol. Snapshotting them would make every
//    protocol addition a prompt-snapshot diff, which teaches people to regenerate without
//    reading. See `normalize_registry_lists` for exactly which four spots are replaced and
//    the check each one gets instead, so the normalisation cannot hide an empty or broken
//    list.
//
//    What is deliberately KEPT: per-protocol action definitions that a test asks for by
//    name (the proxy's sync actions in `network_event_prompt_proxy`) and the HTTP / SSH
//    documentation in `protocol_*_documentation` — what `read_documentation` and MCP's
//    `get_protocol_docs` return. Those change only when that protocol changes,
//    and when they do the diff is something a reviewer should see.
//
// 2. The host. `SystemCapabilities` (src/privilege.rs) probes the machine at runtime
//    (root / CAP_NET_RAW / privileged ports), and `AppState` has no seam to inject a fixed
//    value. See `normalize_capabilities`.
//
// 3. The build's platform and optional capabilities. The proxy is Unix-only and the SQLite
//    actions exist only with the `sqlite` feature (on by default). Tests that render those
//    are gated on `all(unix, feature = "sqlite")`, and a build without either FAILS
//    `prompt_snapshots_need_unix_and_sqlite` rather than quietly running fewer tests.
//
// This suite used to skip instead: it compared nothing unless the prompt carried the
// protocol list of one long-gone feature combination, which no build has produced since
// protocols stopped being features, so every test printed SKIP and passed.
// `snapshot_comparison_is_live` exists so that cannot happen again.
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

/// Panic unless a comma-separated registry list names every protocol in `must_name`.
///
/// This is what stands in for the snapshot where a list is normalised: the list must still
/// be a real list of the registry, not empty, not an error, not a stray sentence.
fn check_registry_list(what: &str, list: &str, separator: &str, must_name: &[&str]) {
    let entries: Vec<&str> = list.split(separator).map(str::trim).collect();
    assert!(
        entries.len() >= 50,
        "{what}: expected the compiled registry (hundreds of protocols), got {} entr(ies): {list:?}",
        entries.len()
    );
    for name in must_name {
        assert!(
            entries.contains(name),
            "{what}: the registry list does not name {name}: {list:?}"
        );
    }
}

/// Replace the parts of a prompt that enumerate the compiled protocol registry with fixed
/// placeholders, checking each list is a plausible registry list before discarding it.
///
/// The four spots, and nothing else:
/// - `read_documentation`'s `**Server protocols**:` and `**Client protocols**:` lines;
/// - `open_server`'s `protocol` parameter, whose description ends `Available: <list>`;
/// - the body of the `## Available Base Stacks` section (group headings and one
///   `Name (keywords)` line per protocol), up to the next `#` or `##` heading.
///
/// The heading and the text around each list stay in the snapshot, so moving, rewording
/// or dropping any of these sections is still a diff.
fn normalize_registry_lists(prompt: &str) -> String {
    static SERVER_LIST_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^(\*\*Server protocols\*\*: )(.*)$").unwrap());
    static CLIENT_LIST_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^(\*\*Client protocols\*\*: )(.*)$").unwrap());
    static OPEN_SERVER_PROTOCOL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?m)^(- `protocol` \(string, required\): .*? Available: )(.*)$").unwrap()
    });

    let prompt = SERVER_LIST_RE.replace_all(prompt, |c: &regex::Captures| {
        check_registry_list(
            "read_documentation server list",
            &c[2],
            ",",
            &["HTTP", "Proxy", "SSH", "TCP"],
        );
        format!("{}<normalized: compiled server registry>", &c[1])
    });
    let prompt = CLIENT_LIST_RE.replace_all(&prompt, |c: &regex::Captures| {
        check_registry_list(
            "read_documentation client list",
            &c[2],
            ",",
            &["HTTP", "SSH", "TCP"],
        );
        format!("{}<normalized: compiled client registry>", &c[1])
    });
    let prompt = OPEN_SERVER_PROTOCOL_RE.replace_all(&prompt, |c: &regex::Captures| {
        check_registry_list(
            "open_server protocol parameter",
            &c[2],
            ",",
            &["HTTP", "Proxy", "SSH", "TCP"],
        );
        format!("{}<normalized: compiled server registry>", &c[1])
    });

    normalize_base_stacks(&prompt)
}

/// Replace the body of `## Available Base Stacks` (see `normalize_registry_lists`).
fn normalize_base_stacks(prompt: &str) -> String {
    const HEADING: &str = "## Available Base Stacks\n";
    let Some(start) = prompt.find(HEADING) else {
        return prompt.to_string();
    };
    let body_start = start + HEADING.len();
    let rest = &prompt[body_start..];
    // The section ends at the next `# ` or `## ` heading or `---` rule; `### ` group
    // headings are its body.
    let mut body_len = rest.len();
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.starts_with("# ") || line.starts_with("## ") || line.trim_end() == "---" {
            body_len = offset;
            break;
        }
        offset += line.len();
    }
    let body = &rest[..body_len];

    let groups = body.lines().filter(|l| l.starts_with("### ")).count();
    let stacks: Vec<&str> = body
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("### "))
        .collect();
    assert!(
        groups >= 5 && stacks.len() >= 50,
        "Available Base Stacks: expected the compiled registry grouped under ### headings, \
         got {groups} group(s) and {} stack line(s):\n{body}",
        stacks.len()
    );
    for name in ["HTTP", "Proxy", "SSH", "TCP"] {
        assert!(
            stacks
                .iter()
                .any(|l| *l == name || l.starts_with(&format!("{name} ("))),
            "Available Base Stacks does not list {name}:\n{body}"
        );
    }

    format!(
        "{}\n<normalized: compiled base stacks, grouped>\n\n{}",
        &prompt[..body_start],
        &rest[body_len..]
    )
}

/// Everything build- or host-dependent, replaced; everything else, untouched.
fn normalize_prompt(prompt: &str) -> String {
    normalize_registry_lists(&normalize_capabilities(prompt))
}

fn assert_prompt_snapshot(test_name: &str, prompt: &str) {
    assert!(
        SNAPSHOTS.contains(&test_name),
        "snapshot '{test_name}' is not in SNAPSHOTS; add it there"
    );
    snapshot_util::assert_snapshot(test_name, SNAPSHOT_DIR, &normalize_prompt(prompt));
}

/// A build that cannot render the Unix+sqlite prompts fails here instead of running fewer
/// snapshot tests and passing.
#[test]
// A runtime failure, not a `const` assert: a compile error would take down the
// ungated tests in this target as well.
#[allow(clippy::assertions_on_constants)]
fn prompt_snapshots_need_unix_and_sqlite() {
    assert!(
        cfg!(all(unix, feature = "sqlite", feature = "mcp-stdio")),
        "the prompt snapshots render the Unix-only proxy, the sqlite actions and MCP's \
         protocol documentation; this build lacks unix, the `sqlite` feature or the \
         `mcp-stdio` feature, so part of tests/prompt would not compare anything. Build \
         with the default features on a Unix host."
    );
}

/// The prompt `test_user_input_prompt` snapshots: no servers, every scripting runtime.
async fn build_user_input_prompt() -> String {
    let state = Arc::new(AppState::new());
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    let system_prompt = PromptBuilder::build_user_input_system_prompt(&state, vec![], None).await;
    format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, "start a DNS server on port 53"
    )
}

/// The guard against this suite going quiet again.
///
/// It proves, from inside the suite, that a snapshot comparison really happens on this
/// build, through the same `assert_prompt_snapshot` every test uses: the real user-input
/// prompt passes it, and the same prompt with one phrase of its instructions changed makes
/// it panic with a diff naming the change. A skip anywhere on that path (normalisation,
/// `assert_prompt_snapshot`, `snapshot_util`) turns the second half into a pass and fails
/// this test; the old skip fired on every build for months. It also holds the snapshot
/// directory, `SNAPSHOTS` and the `assert_prompt_snapshot` calls in this file to the same
/// set, so no snapshot sits on disk with nothing comparing it.
#[tokio::test]
async fn snapshot_comparison_is_live() {
    let prompt = build_user_input_prompt().await;
    let normalized = normalize_prompt(&prompt);

    // The placeholders must actually have been applied, or the comparison is against a
    // registry dump and will churn with every new protocol.
    for placeholder in [
        "**Server protocols**: <normalized: compiled server registry>",
        "**Client protocols**: <normalized: compiled client registry>",
        "Available: <normalized: compiled server registry>",
    ] {
        assert!(
            normalized.contains(placeholder),
            "normalisation did not apply: {placeholder:?} is missing from the prompt"
        );
    }

    // The directory, the list and the calls must agree.
    let mut on_disk: Vec<String> = std::fs::read_dir(SNAPSHOT_DIR)
        .expect("snapshot directory")
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".snap.md")?;
            (!stem.ends_with(".actual")).then(|| stem.to_string())
        })
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = SNAPSHOTS.iter().map(|s| s.to_string()).collect();
    listed.sort();
    assert_eq!(
        on_disk, listed,
        "{SNAPSHOT_DIR} and SNAPSHOTS disagree: every snapshot on disk must be compared"
    );
    let source = include_str!("mod.rs");
    for name in SNAPSHOTS {
        assert!(
            source.contains(&format!("assert_prompt_snapshot(\"{name}\"")),
            "no test calls assert_prompt_snapshot(\"{name}\", …)"
        );
    }

    // Regenerating writes whatever it is given, so the comparison half cannot run then.
    if snapshot_util::update_requested() {
        return;
    }

    assert_prompt_snapshot("user_input_prompt", &prompt);

    const PHRASE: &str = "interprets user commands";
    const CHANGED: &str = "ignores user commands";
    assert!(
        prompt.contains(PHRASE),
        "the user-input prompt no longer contains {PHRASE:?}; pick another phrase for this guard"
    );
    let mutated = prompt.replacen(PHRASE, CHANGED, 1);
    eprintln!("snapshot_comparison_is_live: the mismatch report below is expected");
    let outcome =
        std::panic::catch_unwind(|| assert_prompt_snapshot("user_input_prompt", &mutated));

    // assert_prompt_snapshot leaves the mutant as the .actual file; remove it, and only it.
    let actual_path = format!("{SNAPSHOT_DIR}/user_input_prompt.actual.snap.md");
    if std::fs::read_to_string(&actual_path).ok() == Some(normalize_prompt(&mutated)) {
        let _ = std::fs::remove_file(&actual_path);
    }

    let panic = outcome.expect_err(
        "a one-phrase change to the prompt passed assert_prompt_snapshot: the snapshot \
         comparison is not happening",
    );
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        message.contains(CHANGED),
        "the mismatch report should show the changed line, got:\n{message}"
    );
}

/// Helper to create test app state with a proxy server (no scripting)
#[allow(dead_code)] // only used by the Unix+sqlite tests
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
    // No servers, every scripting runtime: the prompt an operator's first turn renders.
    // The documentation gate is off in the shipped build
    // (`events::handler::REQUIRE_DOCS_FOR_OPEN_ACTIONS`), so open_server and open_client
    // are offered from the start and this is the production prompt.
    let prompt = build_user_input_prompt().await;

    assert_prompt_snapshot("user_input_prompt", &prompt);

    for offered in [
        "## 0. open_server",
        "open_client",
        "update_server",
        "read_documentation",
    ] {
        assert!(
            prompt.contains(offered),
            "the operator prompt should offer {offered}"
        );
    }
    assert!(
        prompt.contains("Available Base Stacks") && prompt.contains("# Event Handlers"),
        "the protocol menu and the event handler guidance belong in the production prompt"
    );
    assert!(
        !prompt.contains("NOT AVAILABLE YET") && !prompt.contains("are not offered yet"),
        "nothing should be described as gated when the gate is off"
    );

    // Acting on "the first server" is not offered here: there is no instance in context.
    for gone in [
        "## 1. update_instruction",
        ". update_instruction\n",
        ". set_memory\n",
        ". append_memory\n",
    ] {
        assert!(
            !prompt.contains(gone),
            "the operator prompt offers {gone:?}"
        );
    }

    // Every LLM handler example carries the instruction parse_event_handlers requires.
    assert!(
        !prompt.contains(r#"{"type": "llm"}"#),
        "an LLM handler example without 'instruction' is refused at startup"
    );
    // Script languages are the tokens the executor accepts, with the installed versions.
    assert!(
        prompt.contains("`python` (Python 3.11.0)")
            && prompt.contains("`javascript` (Node.js v20.0.0)"),
        "script languages should be listed as accepted tokens"
    );
}

/// The documentation-gated variant (`REQUIRE_DOCS_FOR_OPEN_ACTIONS = true`): no
/// open_server / open_client definitions or examples, and the instructions say why.
#[cfg(all(unix, feature = "sqlite"))]
#[tokio::test]
async fn test_user_input_prompt_docs_gate() {
    let state = Arc::new(AppState::new());
    let scripting_env = netget::scripting::ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.38.0".to_string()),
    };
    state.set_scripting_env(scripting_env).await;

    let system_prompt =
        PromptBuilder::build_user_input_system_prompt_with_docs(&state, vec![], None, false, false)
            .await;
    let prompt = format!(
        "{}\n\nTrigger: User input: \"{}\"",
        system_prompt, "start a DNS server on port 53"
    );

    assert_prompt_snapshot("user_input_prompt_docs_gate", &prompt);

    assert!(
        prompt.contains("are not offered yet") && prompt.contains("read_documentation"),
        "the gated prompt should say to read the documentation first"
    );
    assert!(
        !prompt.contains(". open_server\n") && !prompt.contains(". open_client\n"),
        "open_server / open_client should have no definition before the docs are read"
    );
    for example in [
        r#""type": "open_server""#,
        r#""type":"open_server""#,
        r#""type": "open_client""#,
        r#""type":"open_client""#,
    ] {
        assert!(
            !prompt.contains(example),
            "the gated prompt should not teach {example} before it is offered"
        );
    }
    assert!(
        !prompt.contains("Available Base Stacks"),
        "Base stacks should NOT be shown before reading docs"
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
    // With scripting Off no script handler type is offered anywhere, including in the
    // event_handlers parameters and the event handler guidance.
    for script in [
        r#""type": "script""#,
        "script_inline",
        "script_handles",
        "script_runtime",
    ] {
        assert!(
            !prompt.contains(script),
            "Prompt should not offer scripts with scripting Off: found {script:?}"
        );
    }
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

    let set = netget::llm::PromptBuilder::task_action_set(&state, &task).await;
    let prompt = netget::llm::PromptBuilder::build_task_execution_prompt(&state, &task, &set).await;

    // Assert snapshot
    assert_prompt_snapshot("retry_mechanism_prompt", &prompt);

    // A task is not a network event and not an operator command: its preamble says what
    // actually happened.
    assert!(prompt.contains("A scheduled task has fired"));
    assert!(!prompt.contains("in response to a network event"));
    assert!(!prompt.contains("You are handling a network event"));
    assert!(!prompt.contains("interprets user commands"));

    // Sanity checks
    assert!(prompt.contains("## Previous Execution Error"));
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

/// What the model reads when it calls `read_documentation` for one protocol: the real tool
/// output, not a summary of the protocol's metadata assembled here.
async fn read_documentation_output(protocol: &str) -> String {
    use netget::llm::actions::tools::{execute_tool, ToolAction};
    use netget::state::app_state::WebSearchMode;

    let action = ToolAction::ReadDocumentation {
        protocols: vec![protocol.to_string()],
        protocol: None,
    };
    let result = execute_tool(&action, None, WebSearchMode::Off, None).await;
    assert!(
        result.success,
        "read_documentation({protocol}) failed: {}",
        result.result
    );
    result.result
}

/// Replace the `start_server` `port` line of MCP's documentation, which resolves the default
/// port against this process's privilege and what is bound right now.
#[cfg(any(feature = "mcp-stdio", feature = "mcp-http"))]
fn normalize_mcp_port_line(doc: &str) -> String {
    static PORT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^- `port` \(number\) — listen port\..*$").unwrap());
    assert!(
        PORT_RE.is_match(doc),
        "MCP documentation no longer has the `port` argument line this normalises"
    );
    PORT_RE
        .replace_all(
            doc,
            "- `port` (number) — listen port. <normalized: resolved against this host's privilege and bound ports>",
        )
        .into_owned()
}

#[tokio::test]
async fn test_protocol_documentation_prompt() {
    let http = read_documentation_output("http").await;

    // What a script handler needs and what the model used to be denied: the event's field
    // names, the response action's parameters, startup parameter defaults, and an
    // open_server example that leaves the port to the protocol.
    assert!(
        http.contains("- `path` (string"),
        "http_request's `path` field"
    );
    assert!(
        http.contains("- `query_string` ("),
        "http_request's `query_string` field"
    );
    assert!(
        http.contains("### `send_http_response`"),
        "the response action, with its parameters"
    );
    assert!(
        http.contains("well-known port 80"),
        "the port an omitted `port` means"
    );
    assert!(
        http.contains("\"protocol\": \"http\""),
        "open_server names the protocol"
    );
    assert!(
        !http.contains("base_stack"),
        "open_server's parameter is `protocol`"
    );
    assert!(
        !http.contains("\"port\": 8080"),
        "no example pins an invented developer port"
    );
    assert!(
        http.contains("\"remote_addr\": \"127.0.0.1:80\""),
        "the client example reaches localhost on the well-known port"
    );

    let ssh = read_documentation_output("ssh").await;
    assert!(ssh.contains("well-known port 22"));
    assert!(
        ssh.contains(", default: `"),
        "SSH declares startup parameter defaults"
    );

    assert_prompt_snapshot("protocol_http_documentation", &http);
    assert_prompt_snapshot("protocol_ssh_documentation", &ssh);
}

/// What an MCP caller reads from `get_protocol_docs`, through the same renderers.
#[cfg(any(feature = "mcp-stdio", feature = "mcp-http"))]
#[tokio::test]
async fn test_protocol_mcp_documentation() {
    let state = AppState::new();
    let mcp_doc = |protocol: &'static str| {
        let state = &state;
        async move {
            let doc = netget::mcp_stdio::docs::render_protocol_docs(protocol, state)
                .await
                .unwrap_or_else(|| panic!("{protocol} is compiled in"));
            normalize_mcp_port_line(&doc)
        }
    };
    // The two surfaces describe the event the same way, because one renderer writes both.
    let in_app = read_documentation_output("http").await;
    let mcp = netget::mcp_stdio::docs::render_protocol_docs("http", &state)
        .await
        .unwrap();
    let field_line = in_app
        .lines()
        .find(|l| l.starts_with("- `path` ("))
        .expect("in-app docs list the `path` field");
    assert!(
        mcp.contains(field_line),
        "MCP renders the same field line: {field_line}"
    );

    assert_prompt_snapshot("protocol_http_mcp_documentation", &mcp_doc("http").await);
    assert_prompt_snapshot("protocol_ssh_mcp_documentation", &mcp_doc("ssh").await);
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
        result.contains("Example for http server") && result.contains("\"protocol\": \"http\""),
        "Documentation should include example for HTTP"
    );
    assert!(
        result.contains("Example for ssh server") && result.contains("\"protocol\": \"ssh\""),
        "Documentation should include example for SSH"
    );
    assert!(
        result.contains("Example for dns server") && result.contains("\"protocol\": \"dns\""),
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

    // The feedback vocabulary: this server only
    use netget::llm::feedback::{get_feedback_actions, FeedbackTarget};
    let available_actions = get_feedback_actions(FeedbackTarget::Server(server_id));

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
    assert!(prompt.contains("**server #1**: HTTP"), "{prompt}");
    assert!(
        prompt.contains("`update_server` with `server_id` 1"),
        "{prompt}"
    );
    // The instruction and memory appear once each, fenced
    assert_eq!(prompt.matches("Respond to GET/POST requests").count(), 1);
    assert_eq!(prompt.matches("error_count: 3").count(), 1);
    // Nothing that opens, closes or restarts anything is on offer
    for absent in [
        "open_server",
        "close_server",
        "close_all_servers",
        "open_client",
        "close_connection_by_id",
        "update_server_instruction",
        "update_client_instruction",
        "create_database",
        "No servers currently running",
        "## Running Servers",
    ] {
        assert!(!prompt.contains(absent), "{absent} in:\n{prompt}");
    }
    assert!(!prompt.contains("sent to the peer"), "{prompt}");
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

    // The feedback vocabulary: this client only
    use netget::llm::feedback::{get_feedback_actions, FeedbackTarget};
    let available_actions = get_feedback_actions(FeedbackTarget::Client(client_id));

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
    // The client itself is shown, not an empty server list
    assert!(
        prompt.contains("**client #1**: HTTP, connected to api.example.com:443"),
        "{prompt}"
    );
    assert!(prompt.contains("Fetch data from /api/endpoint every 5 seconds"));
    assert!(prompt.contains("timeout_count: 5"));
    assert!(
        prompt.contains("`update_client` with `client_id` 1"),
        "{prompt}"
    );
    assert!(prompt.contains("## 1. update_client"), "{prompt}");
    for absent in [
        "No servers currently running",
        "update_server",
        "append_to_log",
        "open_client",
        "reconnect_client",
    ] {
        assert!(!prompt.contains(absent), "{absent} in:\n{prompt}");
    }
}

/// Current State names every id an operator action takes: each server's live connections
/// (for `close_connection_by_id` and connection-scoped tasks) and every client (for
/// `close_client`, `update_client`, `reconnect_client`, client-scoped tasks).
#[tokio::test]
async fn operator_current_state_lists_connections_and_clients() {
    use netget::server::connection::ConnectionId;
    use netget::state::client::ClientInstance;
    use netget::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    use netget::state::ClientId;
    use netget::utils::clock::Instant;

    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(1),
            7000,
            "TCP".to_string(),
            "echo".to_string(),
        ))
        .await;
    let connection = |id: u32, status: ConnectionStatus| ConnectionState {
        id: ConnectionId::new(id),
        remote_addr: format!("127.0.0.1:{}", 50000 + id).parse().unwrap(),
        local_addr: "127.0.0.1:7000".parse().unwrap(),
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        last_activity: Instant::now(),
        status,
        status_changed_at: Instant::now(),
        protocol_info: ProtocolConnectionInfo::new(serde_json::json!({})),
    };
    state
        .add_connection_to_server(server_id, connection(7, ConnectionStatus::Active))
        .await;
    state
        .add_connection_to_server(server_id, connection(8, ConnectionStatus::Closed))
        .await;
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(2),
            "127.0.0.1:6379".to_string(),
            "redis".to_string(),
            "PING".to_string(),
        ))
        .await;

    let prompt = PromptBuilder::build_user_input_system_prompt(&state, vec![], None).await;

    assert!(
        prompt.contains("live connections: `conn-7` from 127.0.0.1:50007"),
        "a live connection should be listed with its id:\n{prompt}"
    );
    assert!(
        !prompt.contains("conn-8"),
        "a closed connection should not be offered as closable"
    );
    assert!(
        prompt.contains(&format!(
            "- Client #{}: **redis** to 127.0.0.1:6379",
            client_id.as_u32()
        )),
        "running clients should be listed with their ids:\n{prompt}"
    );

    // The id the prompt shows is the id close_connection_by_id accepts.
    for id in [
        serde_json::json!("conn-7"),
        serde_json::json!(7),
        serde_json::json!("7"),
    ] {
        let action = netget::llm::CommonAction::from_json(
            &serde_json::json!({"type": "close_connection_by_id", "connection_id": id}),
        )
        .expect("close_connection_by_id should accept the listed connection id");
        assert!(matches!(
            action,
            netget::llm::CommonAction::CloseConnectionById { connection_id: 7 }
        ));
    }
}
