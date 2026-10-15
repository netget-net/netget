//! End-to-end Git Smart HTTP tests for NetGet
//!
//! This test spawns a NetGet Git server and validates clone operations
//! using both the system `git` command (realistic) and direct HTTP requests.
//!
//! Mocks answer the `git_repository` action (see `src/server/git/actions.rs`). Both
//! `git_info_refs` and `git_upload_pack` MUST be mocked with the *same* repository content
//! for a given repository: a clone is two separate HTTP requests, and if the second answer
//! disagrees with the first, the SHA advertised by `info/refs` does not match the commit
//! actually inside the pack and `git clone` fails with "did not send all necessary objects".


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use anyhow;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Helper to create a unique temporary directory for git operations
fn create_temp_dir() -> E2EResult<TempDir> {
    Ok(tempfile::tempdir()?)
}

/// Helper to run system git command
fn run_git_command(args: &[&str], cwd: Option<&std::path::Path>) -> E2EResult<String> {
    let mut cmd = Command::new("git");
    cmd.args(args);

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git command failed: {}", stderr).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse a pkt-line stream into one entry per line: `Some(payload)` for a data line, `None`
/// for a flush-pkt (`0000`). Panics (failing the test with a clear message) on any framing
/// that a real Git client would also reject: a truncated length header, a length shorter than
/// the 4-byte header it includes, or a payload that runs past the end of the buffer. This is
/// what makes the assertion "well-formed pkt-line" rather than just "didn't crash".
fn parse_pkt_lines(body: &[u8]) -> Vec<Option<Vec<u8>>> {
    let mut lines = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        assert!(
            offset + 4 <= body.len(),
            "pkt-line stream truncated: {} trailing byte(s), need at least 4 for a length header",
            body.len() - offset
        );
        let header = std::str::from_utf8(&body[offset..offset + 4])
            .expect("pkt-line length header must be ASCII hex");
        let len = usize::from_str_radix(header, 16)
            .unwrap_or_else(|e| panic!("pkt-line length header {header:?} is not valid hex: {e}"));
        offset += 4;

        if len == 0 {
            lines.push(None);
            continue;
        }
        assert!(
            len >= 4,
            "pkt-line length {len} is smaller than the 4-byte header it must include"
        );
        let payload_len = len - 4;
        assert!(
            offset + payload_len <= body.len(),
            "pkt-line declares {payload_len} payload byte(s) but only {} remain",
            body.len() - offset
        );
        lines.push(Some(body[offset..offset + payload_len].to_vec()));
        offset += payload_len;
    }

    lines
}

#[tokio::test]
async fn test_git_clone_with_system_git() -> E2EResult<()> {
    println!("\n=== E2E Test: Git Clone with System Git Command ===");

    // Exactly the same `git_repository` content answers both git_info_refs and
    // git_upload_pack, which is what makes a real clone possible (see module docs).
    // Covers a nested path (src/main.rs) and the executable bit (bin/run.sh), both called
    // out as verified behavior in src/server/git/CLAUDE.md.
    let repo_action = serde_json::json!([{
        "type": "git_repository",
        "branch": "main",
        "commit_message": "Initial commit from NetGet",
        "author_name": "NetGet Test",
        "author_email": "netget-test@localhost",
        "files": [
            {"path": "README.md", "content": "# Test Repository\n\nServed by NetGet.\n"},
            {"path": "src/main.rs", "content": "fn main() {\n    println!(\"Hello from NetGet Git!\");\n}\n"},
            {"path": "bin/run.sh", "content": "#!/bin/sh\necho hello\n", "executable": true}
        ]
    }]);

    let prompt = "listen on port {AVAILABLE_PORT} via git.\n\nServe repository 'test-repo'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("git")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Git",
                    "instruction": "Git Smart HTTP server for test-repo"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: reference discovery (first request of the clone)
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "test-repo")
            .respond_with_actions(repo_action.clone())
            .expect_calls(1)
            .and()
            // Mock 3: object transfer (second request of the clone) - SAME content as above
            .on_event("git_upload_pack")
            .and_event_data_contains("repository", "test-repo")
            .respond_with_actions(repo_action.clone())
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    let port = server.port;
    println!("Git server started on port {}", port);

    // Wait for the socket, not a fixed interval: `start_netget_server` returns when
    // startup is *parsed*, not when the listener is bound, and under --test-threads a
    // 500ms guess is a connection refused rather than a slow test.
    server.wait_for_log("Git server listening on", 30).await?;

    let temp_dir = create_temp_dir()?;
    let clone_path = temp_dir.path().join("test-repo");

    println!("Cloning http://127.0.0.1:{}/test-repo", port);

    let clone_url = format!("http://127.0.0.1:{}/test-repo", port);
    let clone_path_str = clone_path.to_str().unwrap().to_string();
    let clone_result = timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            run_git_command(&["clone", &clone_url, &clone_path_str], None)
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        }),
    )
    .await;

    // The clone MUST succeed: the whole point of the git_repository redesign (commit
    // 67c14fd6) was to make a real `git clone` work, unlike the old base64-pack-from-the-model
    // design which could not. A failure here is a real regression, not an "acceptable for MVP"
    // outcome.
    let clone_output = clone_result
        .map_err(|_| "git clone timed out after 30s")?
        .map_err(|e| format!("git clone task panicked: {e}"))?
        .map_err(|e| format!("git clone failed: {e}"))?;
    println!("Clone succeeded: {}", clone_output);

    assert!(
        clone_path.join(".git").exists(),
        "clone must have a .git directory"
    );

    // Assert through git itself wherever possible, per the protocol author's own verification
    // approach (git clone / git fsck / hash-object against the real binary).
    let fsck_output = run_git_command(&["fsck", "--full"], Some(&clone_path))?;
    println!("git fsck: {:?}", fsck_output);

    let log_subject = run_git_command(&["log", "-1", "--format=%s"], Some(&clone_path))?;
    assert_eq!(
        log_subject.trim(),
        "Initial commit from NetGet",
        "commit message must be exactly what the git_repository action specified"
    );

    let branch = run_git_command(&["branch", "--show-current"], Some(&clone_path))?;
    assert_eq!(branch.trim(), "main", "checked-out branch must be 'main'");

    // Exact file content, not merely "exists" or "contains a keyword".
    let readme_via_git = run_git_command(&["show", "HEAD:README.md"], Some(&clone_path))?;
    assert_eq!(
        readme_via_git, "# Test Repository\n\nServed by NetGet.\n",
        "README.md content must match exactly what was described"
    );

    let readme_on_disk = std::fs::read_to_string(clone_path.join("README.md"))?;
    assert_eq!(readme_on_disk, "# Test Repository\n\nServed by NetGet.\n");

    let main_rs = std::fs::read_to_string(clone_path.join("src/main.rs"))?;
    assert_eq!(
        main_rs, "fn main() {\n    println!(\"Hello from NetGet Git!\");\n}\n",
        "nested path src/main.rs must survive the clone with exact content"
    );

    // Executable bit: verified behavior per src/server/git/CLAUDE.md ("the executable bit ...
    // survive"). Unix-only; the bit has no meaning on Windows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(clone_path.join("bin/run.sh"))?
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o111,
            0,
            "bin/run.sh should be checked out executable, got mode {:o}",
            mode
        );
    }

    // Wait for the exchange the mocks describe before asserting on it; `verify_mocks`
    // remains the thing that asserts.
    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("\n✓ Git clone genuinely succeeded with correct content");
    Ok(())
}

#[tokio::test]
async fn test_git_info_refs_endpoint() -> E2EResult<()> {
    println!("\n=== E2E Test: Git info/refs Endpoint ===");

    let prompt = "listen on port {AVAILABLE_PORT} via git.\n\nServe repository 'simple-repo'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("git")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Git",
                    "instruction": "Git server for simple-repo"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: reference discovery
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "simple-repo")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "git_repository",
                    "branch": "main",
                    "files": [{"path": "README.md", "content": "# Simple Repo\n"}]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    let port = server.port;
    println!("Git server started on port {}", port);

    // Wait for the socket, not a fixed interval: `start_netget_server` returns when
    // startup is *parsed*, not when the listener is bound, and under --test-threads a
    // 500ms guess is a connection refused rather than a slow test.
    server.wait_for_log("Git server listening on", 30).await?;

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/simple-repo/info/refs?service=git-upload-pack",
        port
    );

    let response = client.get(&url).send().await?;
    assert_eq!(response.status(), 200, "info/refs must return 200 OK");

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(
        content_type, "application/x-git-upload-pack-advertisement",
        "Content-Type must be exactly the Smart HTTP advertisement type"
    );

    let body_bytes = response.bytes().await?;
    println!("Response body length: {} bytes", body_bytes.len());

    // Well-formed pkt-line: parse_pkt_lines itself asserts framing invariants (valid hex
    // length headers, no truncation); the assertions below check the *shape* the Smart HTTP
    // spec requires for a reference advertisement with one branch.
    let lines = parse_pkt_lines(&body_bytes);
    assert_eq!(
        lines.len(),
        5,
        "expected [service-announcement, flush, HEAD-ref, branch-ref, flush], got {} pkt-lines: {:?}",
        lines.len(),
        lines
            .iter()
            .map(|l| l.as_ref().map(|p| String::from_utf8_lossy(p).to_string()))
            .collect::<Vec<_>>()
    );

    let service_line = lines[0]
        .as_ref()
        .expect("first pkt-line must be a data line (the service announcement)");
    assert_eq!(
        String::from_utf8_lossy(service_line),
        "# service=git-upload-pack\n"
    );

    assert!(lines[1].is_none(), "second pkt-line must be a flush-pkt");

    let head_line = lines[2]
        .as_ref()
        .expect("third pkt-line must be the HEAD ref line");
    let head_line_str = String::from_utf8_lossy(head_line);
    let (head_sha, head_rest) = head_line_str
        .split_once(' ')
        .expect("HEAD ref line must be '<sha> HEAD\\0<capabilities>\\n'");
    assert_eq!(head_sha.len(), 40, "object id must be 40 hex characters");
    assert!(
        head_sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "object id must be hex: {head_sha:?}"
    );
    assert!(
        head_rest.starts_with("HEAD\0"),
        "expected 'HEAD\\0<capabilities>', got {head_rest:?}"
    );
    assert!(
        head_rest.contains("symref=HEAD:refs/heads/main"),
        "capabilities must advertise which branch HEAD points at: {head_rest:?}"
    );

    let branch_line = lines[3]
        .as_ref()
        .expect("fourth pkt-line must be the branch ref line");
    let branch_line_str = String::from_utf8_lossy(branch_line);
    assert_eq!(
        branch_line_str.trim_end(),
        format!("{head_sha} refs/heads/main"),
        "branch ref line must repeat the same object id as the HEAD line"
    );

    assert!(
        lines[4].is_none(),
        "advertisement must end with a flush-pkt"
    );

    // Wait for the exchange the mocks describe before asserting on it; `verify_mocks`
    // remains the thing that asserts.
    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("\n✓ info/refs pkt-line advertisement is well-formed");
    Ok(())
}

#[tokio::test]
async fn test_git_repository_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: Git Repository Not Found ===");

    let prompt = "listen on port {AVAILABLE_PORT} via git.\n\nOnly 'existing-repo' exists.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("git")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Git",
                    "instruction": "Git server with only 'existing-repo'"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: request for a repository that does not exist -> git_error
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "nonexistent")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "git_error",
                    "message": "Repository not found",
                    "code": 404
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: request for the repository that does exist -> git_repository. Without
            // this, the test could pass even if the server refused *every* repository, which
            // would not prove the 404 was a decision rather than the server being broken.
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "existing-repo")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "git_repository",
                    "branch": "main",
                    "files": [{"path": "README.md", "content": "# Existing Repo\n"}]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    let port = server.port;
    println!("Git server started on port {}", port);

    // Wait for the socket, not a fixed interval: `start_netget_server` returns when
    // startup is *parsed*, not when the listener is bound, and under --test-threads a
    // 500ms guess is a connection refused rather than a slow test.
    server.wait_for_log("Git server listening on", 30).await?;

    let client = reqwest::Client::new();

    // The missing repository must be refused with exactly the code/message the git_error
    // action specified.
    let missing_url = format!(
        "http://127.0.0.1:{}/nonexistent/info/refs?service=git-upload-pack",
        port
    );
    let missing_response = client.get(&missing_url).send().await?;
    assert_eq!(
        missing_response.status(),
        404,
        "git_error with code=404 must produce an HTTP 404"
    );
    let missing_body = missing_response.text().await?;
    assert!(
        missing_body.contains("Repository not found"),
        "error body must contain the git_error message, got: {missing_body:?}"
    );

    // The repository that does exist must succeed - proves the server discriminates by name
    // rather than refusing everything.
    let existing_url = format!(
        "http://127.0.0.1:{}/existing-repo/info/refs?service=git-upload-pack",
        port
    );
    let existing_response = client.get(&existing_url).send().await?;
    assert_eq!(
        existing_response.status(),
        200,
        "the repository that does exist must succeed"
    );

    // Wait for the exchange the mocks describe before asserting on it; `verify_mocks`
    // remains the thing that asserts.
    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("\n✓ Repository not found handling validated");
    Ok(())
}

#[tokio::test]
async fn test_git_multiple_repositories() -> E2EResult<()> {
    println!("\n=== E2E Test: Git Multiple Repositories ===");

    let frontend_action = serde_json::json!([{
        "type": "git_repository",
        "branch": "main",
        "commit_message": "Frontend commit",
        "files": [{"path": "frontend.txt", "content": "frontend-only content\n"}]
    }]);
    let backend_action = serde_json::json!([{
        "type": "git_repository",
        "branch": "main",
        "commit_message": "Backend commit",
        "files": [{"path": "backend.txt", "content": "backend-only content\n"}]
    }]);

    let prompt =
        "listen on port {AVAILABLE_PORT} via git.\n\nServe repositories 'frontend' and 'backend'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("git")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Git",
                    "instruction": "Git server with frontend and backend repositories"
                }
            ]))
            .expect_calls(1)
            .and()
            // frontend: both events must agree
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "frontend")
            .respond_with_actions(frontend_action.clone())
            .expect_calls(1)
            .and()
            .on_event("git_upload_pack")
            .and_event_data_contains("repository", "frontend")
            .respond_with_actions(frontend_action.clone())
            .expect_calls(1)
            .and()
            // backend: both events must agree
            .on_event("git_info_refs")
            .and_event_data_contains("repository", "backend")
            .respond_with_actions(backend_action.clone())
            .expect_calls(1)
            .and()
            .on_event("git_upload_pack")
            .and_event_data_contains("repository", "backend")
            .respond_with_actions(backend_action.clone())
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    let port = server.port;
    println!("Git server started on port {}", port);

    // Wait for the socket, not a fixed interval: `start_netget_server` returns when
    // startup is *parsed*, not when the listener is bound, and under --test-threads a
    // 500ms guess is a connection refused rather than a slow test.
    server.wait_for_log("Git server listening on", 30).await?;

    let temp_dir = create_temp_dir()?;

    // Real clones, not just a byte-count comparison of two responses: this proves routing by
    // repository name actually produces two independently valid, distinct repositories.
    let frontend_path = temp_dir.path().join("frontend");
    let frontend_url = format!("http://127.0.0.1:{}/frontend", port);
    let frontend_path_str = frontend_path.to_str().unwrap().to_string();
    tokio::task::spawn_blocking(move || {
        run_git_command(&["clone", &frontend_url, &frontend_path_str], None)
            .map_err(|e| e.to_string())
    })
    .await?
    .map_err(|e| format!("frontend clone failed: {e}"))?;

    let backend_path = temp_dir.path().join("backend");
    let backend_url = format!("http://127.0.0.1:{}/backend", port);
    let backend_path_str = backend_path.to_str().unwrap().to_string();
    tokio::task::spawn_blocking(move || {
        run_git_command(&["clone", &backend_url, &backend_path_str], None)
            .map_err(|e| e.to_string())
    })
    .await?
    .map_err(|e| format!("backend clone failed: {e}"))?;

    let frontend_content = std::fs::read_to_string(frontend_path.join("frontend.txt"))?;
    assert_eq!(frontend_content, "frontend-only content\n");
    assert!(
        !frontend_path.join("backend.txt").exists(),
        "frontend clone must not contain backend's file"
    );

    let backend_content = std::fs::read_to_string(backend_path.join("backend.txt"))?;
    assert_eq!(backend_content, "backend-only content\n");
    assert!(
        !backend_path.join("frontend.txt").exists(),
        "backend clone must not contain frontend's file"
    );

    // Wait for the exchange the mocks describe before asserting on it; `verify_mocks`
    // remains the thing that asserts.
    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("\n✓ Multiple repositories validated with independent real clones");
    Ok(())
}

#[tokio::test]
async fn test_git_with_scripting() -> E2EResult<()> {
    println!("\n=== E2E Test: Git with Python Scripting ===");

    // The script answers both git_info_refs and git_upload_pack identically because it
    // ignores the event payload entirely and always returns the same repository - the
    // guaranteed-correct pattern the protocol's own CLAUDE.md recommends. Only the startup
    // call goes through the mock LLM; per-request handling happens in the spawned Python
    // process, never touching call_llm at all (src/llm/action_helper.rs tries the event
    // handler first). No mock rule is registered for git_info_refs/git_upload_pack, so if
    // scripting silently fell back to the LLM (e.g. python3 not found), the request would hit
    // "no mock rule matched" and the test would fail loudly instead of passing vacuously.
    let script_code = r##"
import json, sys
json.load(sys.stdin)  # consume stdin; the response does not depend on it
print(json.dumps({"actions": [{
    "type": "git_repository",
    "branch": "main",
    "commit_message": "Scripted commit",
    "files": [{"path": "README.md", "content": "# Scripted Repo\n"}]
}]}))
"##;

    let prompt = "listen on port {AVAILABLE_PORT} via git.\n\nServe repository 'scripted-repo' via a Python script.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup - the only call that goes through the (mock) LLM.
            .on_instruction_containing("listen on port")
            .and_instruction_containing("git")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Git",
                    "instruction": "Git server with Python scripting for scripted-repo",
                    "event_handlers": [{
                        "event_pattern": "*",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": script_code
                        }
                    }]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    let port = server.port;
    println!("Git server with scripting started on port {}", port);

    // Wait for the socket, not a fixed interval: `start_netget_server` returns when
    // startup is *parsed*, not when the listener is bound, and under --test-threads a
    // 500ms guess is a connection refused rather than a slow test.
    server.wait_for_log("Git server listening on", 30).await?;

    let client = reqwest::Client::new();

    println!("\n--- Testing scripted responses (should be fast, no LLM call) ---");
    // "The script answered, not the model" is asserted structurally rather than by the clock.
    //
    // There is deliberately no mock rule for git_info_refs or git_upload_pack, so a request
    // that reached call_llm would find no matching rule, the mock would answer HTTP 500, and
    // the status assertion below would fail. `verify_mocks` at the end additionally pins the
    // startup rule at exactly one call, so an extra model round-trip cannot hide.
    //
    // This loop used to assert `elapsed < 100ms` as a proxy for the same property. It was a
    // wall-clock bound in a suite that runs at --test-threads=100 on a 12-core machine, so it
    // failed intermittently while proving nothing the two checks above do not already prove:
    // a mocked model answers in single-digit milliseconds too, so the bound could not actually
    // distinguish a script from a mock. Timing is not evidence here; the absent rule is.
    for i in 1..=3 {
        let url = format!(
            "http://127.0.0.1:{}/scripted-repo/info/refs?service=git-upload-pack",
            port
        );
        let response = client.get(&url).send().await?;

        println!("Request {}: {}", i, response.status());
        assert_eq!(
            response.status(),
            200,
            "scripted request {i} must succeed; a 500 here means it fell through to the model,              which has no rule for this event"
        );
    }

    // Prove the script-driven pack is actually valid, not just that GETs return 200: a real
    // clone must succeed and contain the exact content the script emitted.
    println!("\n--- Verifying the scripted pack with a real git clone ---");
    let temp_dir = create_temp_dir()?;
    let clone_path = temp_dir.path().join("scripted-repo");
    let clone_url = format!("http://127.0.0.1:{}/scripted-repo", port);
    let clone_path_str = clone_path.to_str().unwrap().to_string();
    tokio::task::spawn_blocking(move || {
        run_git_command(&["clone", &clone_url, &clone_path_str], None).map_err(|e| e.to_string())
    })
    .await?
    .map_err(|e| format!("scripted-repo clone failed: {e}"))?;

    let readme = std::fs::read_to_string(clone_path.join("README.md"))?;
    assert_eq!(readme, "# Scripted Repo\n");

    let log_subject = run_git_command(&["log", "-1", "--format=%s"], Some(&clone_path))?;
    assert_eq!(log_subject.trim(), "Scripted commit");

    // Wait for the exchange the mocks describe before asserting on it; `verify_mocks`
    // remains the thing that asserts.
    server.wait_for_mocks(30).await;
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("\n✓ Scripting mode validated - fast responses and a genuinely valid clone");
    Ok(())
}
