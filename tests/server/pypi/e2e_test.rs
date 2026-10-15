//! E2E tests for PyPI protocol
//!
//! These tests verify PyPI server functionality by starting NetGet with PyPI prompts
//! and using the real pip command to install packages.

use crate::server::helpers::*;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_pypi_comprehensive() -> E2EResult<()> {
    // Single comprehensive server with scripting for all test cases
    let config = NetGetConfig::new(
        r#"listen on port 0 via pypi

You are a PyPI (Python Package Index) server implementing PEP 503 Simple Repository API.

AVAILABLE PACKAGES:
1. "hello-world" version 1.0.0
   - File: hello_world-1.0.0-py3-none-any.whl
   - SHA256: abc123def456 (dummy hash for testing)

2. "example-pkg" version 2.1.0
   - File: example_pkg-2.1.0-py3-none-any.whl
   - SHA256: 789xyz (dummy hash)

ENDPOINTS:

/simple/ or /simple (list all packages):
- Return HTML: <!DOCTYPE html><html><body><a href="hello-world/">hello-world</a><br><a href="example-pkg/">example-pkg</a></body></html>
- Content-Type: text/html

/simple/hello-world/ (list files for hello-world):
- Return HTML: <!DOCTYPE html><html><body><a href="../../packages/h/hello-world/hello_world-1.0.0-py3-none-any.whl#sha256=abc123def456">hello_world-1.0.0-py3-none-any.whl</a></body></html>
- Content-Type: text/html

/simple/example-pkg/ (list files for example-pkg):
- Return HTML: <!DOCTYPE html><html><body><a href="../../packages/e/example-pkg/example_pkg-2.1.0-py3-none-any.whl#sha256=789xyz">example_pkg-2.1.0-py3-none-any.whl</a></body></html>
- Content-Type: text/html

/packages/h/hello-world/hello_world-1.0.0-py3-none-any.whl (download wheel):
- Return a minimal valid Python wheel (zip file with PKG-INFO)
- Content-Type: application/zip
- The wheel should be a valid zip file containing at least:
  hello_world-1.0.0.dist-info/METADATA with:
  Metadata-Version: 2.1
  Name: hello-world
  Version: 1.0.0

/packages/e/example-pkg/example_pkg-2.1.0-py3-none-any.whl (download wheel):
- Return a minimal valid Python wheel
- Content-Type: application/zip

Any other package requests:
- Return 404 Not Found

Use scripting mode to handle all requests without LLM calls after initial setup.
"#,
    )
    .with_log_level("off")
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("pypi")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PyPI",
                    "instruction": "Serve hello-world and example-pkg packages"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2-6: PyPI requests - dynamic response based on path
            .on_event("pypi_request")
            .respond_with_actions_from_event(|event_data| {
                let path = event_data["path"].as_str().unwrap_or("");

                // A project this index does not serve gets a real 404. Without this
                // branch the `else` below answered `/simple/nonexistent-package/` with
                // the **package index** under a 200, so Test 5 — which is named for a
                // 404 — asked for a status the mock actively prevented, and then
                // asserted nothing so nobody noticed.
                if path.contains("nonexistent") {
                    return serde_json::json!([{
                        "type": "send_pypi_response",
                        "status": 404,
                        "headers": {"Content-Type": "text/html"},
                        "body": "<!DOCTYPE html><html><body>Not Found</body></html>"
                    }]);
                }

                let body = if path.contains("hello-world") {
                    // Package page for hello-world
                    r#"<!DOCTYPE html><html><body><a href="../../packages/h/hello-world/hello_world-1.0.0-py3-none-any.whl#sha256=abc123def456">hello_world-1.0.0-py3-none-any.whl</a></body></html>"#
                } else if path.contains("example-pkg") {
                    // Package page for example-pkg
                    r#"<!DOCTYPE html><html><body><a href="../../packages/e/example-pkg/example_pkg-2.1.0-py3-none-any.whl#sha256=789xyz">example_pkg-2.1.0-py3-none-any.whl</a></body></html>"#
                } else {
                    // Package index
                    r#"<!DOCTYPE html><html><body><a href="hello-world/">hello-world</a><br><a href="example-pkg/">example-pkg</a></body></html>"#
                };

                serde_json::json!([{
                    "type": "send_pypi_response",
                    "status": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": body
                }])
            })
            .expect_at_least(1)
            .expect_at_most(10)
            .and()
    });

    let test_state = timeout(Duration::from_secs(30), start_netget_server(config))
        .await
        .map_err(|_| "Server startup timeout")??;

    // Wait for server to be ready
    crate::helpers::wait_for_server_listening(&test_state, Duration::from_secs(30)).await?;

    let base_url = format!("http://127.0.0.1:{}/simple/", test_state.port);

    println!("✓ PyPI server started on port {}", test_state.port);
    println!("  Base URL: {}", base_url);

    // Test 1: Fetch package index with curl
    println!("\n[Test 1] Fetch package index (/simple/)");
    let base_url_clone = base_url.clone();
    let output = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("-s")
                .arg("--max-time")
                .arg("5")
                .arg(&base_url_clone)
                .output()
        }),
    )
    .await
    .map_err(|_| "curl timeout")??
    .expect("Failed to execute curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response:\n{}", response);
    assert!(
        response.contains("hello-world"),
        "Expected hello-world in package index"
    );
    assert!(
        response.contains("example-pkg"),
        "Expected example-pkg in package index"
    );
    println!("✓ Package index contains expected packages");

    // Test 2: Fetch hello-world package page
    println!("\n[Test 2] Fetch hello-world package page (/simple/hello-world/)");
    let hello_url = format!("http://127.0.0.1:{}/simple/hello-world/", test_state.port);
    let output = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("-s")
                .arg("--max-time")
                .arg("5")
                .arg(&hello_url)
                .output()
        }),
    )
    .await
    .map_err(|_| "curl timeout")??
    .expect("Failed to execute curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response:\n{}", response);
    assert!(
        response.contains("hello_world-1.0.0-py3-none-any.whl"),
        "Expected wheel file in package page"
    );
    println!("✓ hello-world package page contains wheel file");

    // Test 3: Fetch example-pkg package page
    println!("\n[Test 3] Fetch example-pkg package page (/simple/example-pkg/)");
    let example_url = format!("http://127.0.0.1:{}/simple/example-pkg/", test_state.port);
    let output = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("-s")
                .arg("--max-time")
                .arg("5")
                .arg(&example_url)
                .output()
        }),
    )
    .await
    .map_err(|_| "curl timeout")??
    .expect("Failed to execute curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response:\n{}", response);
    assert!(
        response.contains("example_pkg-2.1.0-py3-none-any.whl"),
        "Expected wheel file in package page"
    );
    println!("✓ example-pkg package page contains wheel file");

    // Test 4: pip resolves the project page this server served.
    //
    // Every arm of this step used to `println!` and continue — pip missing, pip
    // failing, pip timing out and pip returning the wrong thing were indistinguishable
    // from success, including the "success" arm, which said "! pip query completed but
    // may not have found package metadata". It cost 30 seconds and proved nothing.
    //
    // It now asserts, and it **fails rather than skips when pip is absent**: a loud skip
    // is still a silent pass on any runner without the binary, which is the shape that
    // let four maturity claims outlive their evidence. `tests/server/npm/e2e_test.rs`
    // is the precedent.
    //
    // Note what this does and does not buy. `pip index versions` is an experimental pip
    // subcommand and the wheel this test serves is a stub, so pip proves that a real,
    // independent PEP 503 client reached and parsed the project page — not that a real
    // install succeeds. PyPI therefore stays `Experimental`; the hard fail exists so the
    // suite cannot report having run this when it did not.
    println!("\n[Test 4] pip resolves hello-world from the served index");

    // Create a temporary directory for pip cache
    let temp_dir = std::env::temp_dir().join(format!("netget-pypi-test-{}", test_state.port));
    std::fs::create_dir_all(&temp_dir).ok();

    // Try to get package info (this will fail at download because wheel is likely invalid,
    // but it should at least successfully query the index and find the package)
    let base_url_for_pip = base_url.clone();
    let output = timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            Command::new("pip")
                .arg("index")
                .arg("versions")
                .arg("hello-world")
                .arg("--index-url")
                .arg(&base_url_for_pip)
                .env("PIP_NO_CACHE_DIR", "1")
                .output()
        }),
    )
    .await;

    match output {
        Ok(Ok(Ok(result))) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            println!("pip stdout:\n{}", stdout);
            println!("pip stderr:\n{}", stderr);

            // pip reached the index and parsed the project page: it either lists the
            // version it found in the PEP 503 anchor, or says the project has no
            // matching distribution — both mean the page was fetched and understood.
            // What it must not do is fail to reach the index at all.
            assert!(
                !stderr.contains("Could not fetch URL")
                    && !stderr.contains("Connection refused")
                    && !stderr.contains("Temporary failure"),
                "pip could not reach the NetGet index:\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(
                stdout.contains("hello-world")
                    || stdout.contains("1.0.0")
                    || stderr.contains("hello-world"),
                "pip reached the index but never mentioned the project it serves:\n\
                 stdout:\n{stdout}\nstderr:\n{stderr}"
            );
            println!("✓ pip resolved hello-world from the NetGet index");
        }
        Ok(Ok(Err(e))) => {
            // Fail, never skip: see the note above this step.
            panic!(
                "pip is not available ({e}): this step drives a real, independent PEP 503 \
                 client against NetGet's index, and skipping it would report a pass for a \
                 step that asserted nothing. Install Python 3 (`brew install python3`, or \
                 `apt-get install -y python3-pip`) and re-run."
            );
        }
        Ok(Err(e)) => {
            panic!("the pip task itself panicked, which is a test bug, not a missing pip: {e}");
        }
        Err(_) => {
            panic!(
                "pip did not return within 30s against a local index — that is a hang, \
                    not an absent binary"
            );
        }
    }

    // Test 5: Test 404 for non-existent package
    println!("\n[Test 5] Test 404 for non-existent package");
    let nonexistent_url = format!(
        "http://127.0.0.1:{}/simple/nonexistent-package/",
        test_state.port
    );
    let output = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("-s")
                .arg("-w")
                .arg("%{http_code}")
                .arg("-o")
                .arg("/dev/null")
                .arg("--max-time")
                .arg("5")
                .arg(&nonexistent_url)
                .output()
        }),
    )
    .await
    .map_err(|_| "curl timeout")??
    .expect("Failed to execute curl");

    let status_code = String::from_utf8_lossy(&output.stdout);
    println!("HTTP status code: {}", status_code);
    // Asserted, not printed. "we just check it responds" was not a check: any status,
    // including the 200-with-the-package-index this mock used to return, satisfied it.
    // A refusal the model makes deliberately must reach the client as a refusal.
    assert_eq!(
        status_code.trim(),
        "404",
        "a project the index does not serve must come back 404, not {status_code}"
    );
    println!("✓ Non-existent package answered 404");

    // Cleanup
    std::fs::remove_dir_all(&temp_dir).ok();

    println!("\n✓✓✓ All PyPI E2E tests passed!");

    timeout(Duration::from_secs(30), test_state.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    timeout(Duration::from_secs(30), test_state.stop())
        .await
        .map_err(|_| "Server stop timeout")??;
    Ok(())
}

#[tokio::test]
async fn test_pypi_single_package() -> E2EResult<()> {
    // Simpler test with just one package for quick verification
    let config = NetGetConfig::new(
        r#"listen on port 0 via pypi

Act as a minimal PyPI server with one package:

Package: "test-pkg" version 0.1.0

When client requests /simple/ or /simple:
Return: <!DOCTYPE html><html><body><a href="test-pkg/">test-pkg</a></body></html>

When client requests /simple/test-pkg/:
Return: <!DOCTYPE html><html><body><a href="../../packages/t/test-pkg/test_pkg-0.1.0-py3-none-any.whl">test_pkg-0.1.0-py3-none-any.whl</a></body></html>

Use scripting mode for zero LLM calls after setup.
"#,
    )
    .with_log_level("off")
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("pypi")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PyPI",
                    "instruction": "Serve test-pkg package"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: PyPI request
            .on_event("pypi_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pypi_response",
                    "status": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": "<!DOCTYPE html><html><body><a href=\"test-pkg/\">test-pkg</a></body></html>"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let test_state = timeout(Duration::from_secs(30), start_netget_server(config))
        .await
        .map_err(|_| "Server startup timeout")??;
    crate::helpers::wait_for_server_listening(&test_state, Duration::from_secs(30)).await?;

    let base_url = format!("http://127.0.0.1:{}/simple/", test_state.port);
    println!("✓ Minimal PyPI server started on port {}", test_state.port);

    // Test: Fetch package index
    println!("\n[Test] Fetch minimal package index");
    let output = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("-s")
                .arg("--max-time")
                .arg("5")
                .arg(&base_url)
                .output()
        }),
    )
    .await
    .map_err(|_| "curl timeout")??
    .expect("Failed to execute curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response:\n{}", response);
    assert!(
        response.contains("test-pkg"),
        "Expected test-pkg in package index"
    );
    println!("✓ Minimal PyPI server works correctly");

    timeout(Duration::from_secs(30), test_state.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    timeout(Duration::from_secs(30), test_state.stop())
        .await
        .map_err(|_| "Server stop timeout")??;
    Ok(())
}
