//! End-to-end Maven repository tests for NetGet
//!
//! These tests spawn the actual NetGet binary as a Maven repository
//! and validate Maven artifact serving using real HTTP requests and Maven CLI.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::fs;

#[tokio::test]
async fn test_maven_simple_artifact() -> E2EResult<()> {
    println!("\n=== E2E Test: Simple Maven Artifact ===");

    // PROMPT: Serve a simple Maven artifact
    let prompt = r#"listen on port {AVAILABLE_PORT} via maven.
Serve a library com.example:hello-world:1.0.0
For JAR requests, return a simple JAR file content with text: "Hello from Maven JAR"
For POM requests, return this POM:
<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>hello-world</artifactId>
  <version>1.0.0</version>
</project>
For maven-metadata.xml, list version 1.0.0 as the latest.
For SHA-1 checksum requests, return fake checksum: abc123
For other artifacts, return 404.
"#;

    // Start the server with mocks
    let server_config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen on port")
                .and_instruction_containing("maven")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Maven",
                        "instruction": "Serve a library com.example:hello-world:1.0.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: POM request
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "pom")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/xml",
                        "body": "<?xml version=\"1.0\"?>\n<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  <artifactId>hello-world</artifactId>\n  <version>1.0.0</version>\n</project>"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: SHA-1 checksum request (must come before JAR to match first)
                .on_event("maven_artifact_request")
                .and_event_data_contains("checksum_type", "sha1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "text/plain",
                        "body": "abc123"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: maven-metadata.xml request
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "xml")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_metadata",
                        "group_id": "com.example",
                        "artifact_id": "hello-world",
                        "versions": ["1.0.0"],
                        "latest": "1.0.0",
                        "release": "1.0.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 5: 404 for non-existent artifact (must come before JAR to match first)
                .on_event("maven_artifact_request")
                .and_event_data_contains("artifact_id", "nonexistent")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_error",
                        "status": 404,
                        "message": "Not Found"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 6: JAR request (generic, matches last)
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "Hello from Maven JAR"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    println!(
        "Server started: {} stack on port {}",
        server.stack, server.port
    );

    // Verify it's actually a Maven server
    assert_eq!(
        server.stack, "Maven",
        "Expected Maven server but got {}",
        server.stack
    );

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", server.port);

    // Test 1: Request the POM file
    println!("\n--- Test: Request POM file ---");
    let pom_url = format!(
        "{}/com/example/hello-world/1.0.0/hello-world-1.0.0.pom",
        base_url
    );
    let response = client.get(&pom_url).send().await?;

    assert_eq!(response.status(), 200, "POM request should return 200");
    let pom_content = response.text().await?;
    assert!(
        pom_content.contains("<groupId>com.example</groupId>"),
        "POM should contain groupId"
    );
    assert!(
        pom_content.contains("<artifactId>hello-world</artifactId>"),
        "POM should contain artifactId"
    );
    assert!(
        pom_content.contains("<version>1.0.0</version>"),
        "POM should contain version"
    );
    println!("✓ POM file validated");

    // Test 2: Request the JAR file
    println!("\n--- Test: Request JAR file ---");
    let jar_url = format!(
        "{}/com/example/hello-world/1.0.0/hello-world-1.0.0.jar",
        base_url
    );
    let response = client.get(&jar_url).send().await?;

    assert_eq!(response.status(), 200, "JAR request should return 200");
    let jar_content = response.text().await?;
    assert!(
        jar_content.contains("Hello from Maven JAR"),
        "JAR should contain expected text"
    );
    println!("✓ JAR file validated");

    // Test 3: Request maven-metadata.xml
    println!("\n--- Test: Request maven-metadata.xml ---");
    let metadata_url = format!("{}/com/example/hello-world/maven-metadata.xml", base_url);
    let response = client.get(&metadata_url).send().await?;

    assert_eq!(response.status(), 200, "Metadata request should return 200");
    let metadata_content = response.text().await?;
    assert!(
        metadata_content.contains("<version>1.0.0</version>"),
        "Metadata should list version"
    );
    assert!(
        metadata_content.contains("<latest>1.0.0</latest>")
            || metadata_content.contains("<versions>"),
        "Metadata should have version info"
    );
    println!("✓ maven-metadata.xml validated");

    // Test 4: Request a SHA-1 checksum
    println!("\n--- Test: Request SHA-1 checksum ---");
    let sha1_url = format!(
        "{}/com/example/hello-world/1.0.0/hello-world-1.0.0.jar.sha1",
        base_url
    );
    let response = client.get(&sha1_url).send().await?;

    assert_eq!(response.status(), 200, "SHA-1 request should return 200");
    let sha1_content = response.text().await?;
    assert!(
        sha1_content.contains("abc123"),
        "SHA-1 should contain expected hash"
    );
    println!("✓ SHA-1 checksum validated");

    // Test 5: Request a non-existent artifact (should be 404)
    println!("\n--- Test: Request non-existent artifact ---");
    let missing_url = format!(
        "{}/com/example/nonexistent/1.0.0/nonexistent-1.0.0.jar",
        base_url
    );
    let response = client.get(&missing_url).send().await?;

    assert_eq!(
        response.status(),
        404,
        "Non-existent artifact should return 404"
    );
    println!("✓ 404 for missing artifact validated");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_maven_multi_version() -> E2EResult<()> {
    println!("\n=== E2E Test: Maven Multi-Version Repository ===");

    // PROMPT: Serve multiple versions of an artifact
    let prompt = r#"listen on port {AVAILABLE_PORT} via maven.
Serve library com.example:mylib with three versions: 1.0.0, 1.0.1, and 1.1.0
For each version's JAR, return text: "mylib version X.X.X"
For each version's POM, return minimal POM with correct version number.
For maven-metadata.xml, list all three versions with 1.1.0 as latest.
For other artifacts, return 404.
"#;

    // Start the server with mocks
    let server_config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen on port")
                .and_instruction_containing("maven")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Maven",
                        "instruction": "Serve library com.example:mylib with three versions: 1.0.0, 1.0.1, and 1.1.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: maven-metadata.xml request
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "xml")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_metadata",
                        "group_id": "com.example",
                        "artifact_id": "mylib",
                        "versions": ["1.0.0", "1.0.1", "1.1.0"],
                        "latest": "1.1.0",
                        "release": "1.1.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: JAR request for version 1.0.0
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .and_event_data_contains("version", "1.0.0")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "mylib version 1.0.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: JAR request for version 1.0.1
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .and_event_data_contains("version", "1.0.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "mylib version 1.0.1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 5: JAR request for version 1.1.0
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .and_event_data_contains("version", "1.1.0")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "mylib version 1.1.0"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", server.port);

    // Test 1: Get maven-metadata.xml
    println!("\n--- Test: Get version listing ---");
    let metadata_url = format!("{}/com/example/mylib/maven-metadata.xml", base_url);
    let response = client.get(&metadata_url).send().await?;

    assert_eq!(response.status(), 200);
    let metadata = response.text().await?;
    assert!(metadata.contains("1.0.0"), "Should list version 1.0.0");
    assert!(metadata.contains("1.0.1"), "Should list version 1.0.1");
    assert!(metadata.contains("1.1.0"), "Should list version 1.1.0");
    println!("✓ All versions listed in metadata");

    // Test 2: Download specific version JAR files
    println!("\n--- Test: Download different version JARs ---");

    for version in &["1.0.0", "1.0.1", "1.1.0"] {
        let jar_url = format!(
            "{}/com/example/mylib/{}/mylib-{}.jar",
            base_url, version, version
        );
        let response = client.get(&jar_url).send().await?;

        assert_eq!(
            response.status(),
            200,
            "JAR for version {} should exist",
            version
        );
        let content = response.text().await?;
        assert!(
            content.contains("mylib") && content.contains(version),
            "JAR should identify version {}",
            version
        );
        println!("✓ Version {} JAR validated", version);
    }

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_maven_with_classifier() -> E2EResult<()> {
    println!("\n=== E2E Test: Maven Artifacts with Classifiers ===");

    // PROMPT: Serve artifacts with classifiers (sources, javadoc)
    let prompt = r#"listen on port {AVAILABLE_PORT} via maven.
Serve com.example:toolkit:2.0.0 with the following files:
- Main JAR: "Toolkit main code"
- Sources JAR (-sources classifier): "Toolkit source code"
- Javadoc JAR (-javadoc classifier): "Toolkit documentation"
- POM: Minimal POM with version 2.0.0
Return 404 for other artifacts.
"#;

    // Start the server with mocks
    let server_config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen on port")
                .and_instruction_containing("maven")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Maven",
                        "instruction": "Serve com.example:toolkit:2.0.0 with main, sources, and javadoc JARs"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Sources JAR request (must come first to match before non-classifier JAR)
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .and_event_data_contains("classifier", "sources")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "Toolkit source code"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Javadoc JAR request
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .and_event_data_contains("classifier", "javadoc")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "Toolkit documentation"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Main JAR request (no classifier - matches last)
                .on_event("maven_artifact_request")
                .and_event_data_contains("extension", "jar")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_maven_artifact",
                        "status": 200,
                        "content_type": "application/java-archive",
                        "body": "Toolkit main code"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", server.port);

    // Test 1: Main JAR (no classifier)
    println!("\n--- Test: Main JAR ---");
    let jar_url = format!("{}/com/example/toolkit/2.0.0/toolkit-2.0.0.jar", base_url);
    let response = client.get(&jar_url).send().await?;

    assert_eq!(response.status(), 200);
    let content = response.text().await?;
    assert!(
        content.contains("main") || content.contains("code"),
        "Should be main JAR"
    );
    println!("✓ Main JAR validated");

    // Test 2: Sources JAR
    println!("\n--- Test: Sources JAR ---");
    let sources_url = format!(
        "{}/com/example/toolkit/2.0.0/toolkit-2.0.0-sources.jar",
        base_url
    );
    let response = client.get(&sources_url).send().await?;

    assert_eq!(response.status(), 200);
    let content = response.text().await?;
    assert!(content.contains("source"), "Should be sources JAR");
    println!("✓ Sources JAR validated");

    // Test 3: Javadoc JAR
    println!("\n--- Test: Javadoc JAR ---");
    let javadoc_url = format!(
        "{}/com/example/toolkit/2.0.0/toolkit-2.0.0-javadoc.jar",
        base_url
    );
    let response = client.get(&javadoc_url).send().await?;

    assert_eq!(response.status(), 200);
    let content = response.text().await?;
    assert!(content.contains("doc"), "Should be javadoc JAR");
    println!("✓ Javadoc JAR validated");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// Drive the server with the **real `mvn` binary** and assert the artifact it wrote.
///
/// This test replaces one that could never have passed, and the reasons are worth
/// keeping because each one looks survivable on its own:
///
/// - it was `#[ignore]`d, so nothing ran it;
/// - it printed "Maven CLI not found, skipping test" and returned `Ok(())`, so on a
///   machine without `mvn` it was a green pass that asserted nothing;
/// - on the happy path it asserted **nothing at all** — `if success { println!("✓") }
///   else { println!("⚠ inconclusive") }`, so a total failure and a total success were
///   the same outcome;
/// - and it was started with `NetGetConfig::new(prompt)` and **no `.with_mock()`**,
///   which builds a strict empty mock where every LLM call 500s, so
///   `start_netget_server` could never even get its `open_server` action back.
///
/// `tests/server/maven/CLAUDE.md` nonetheless presented it as real-client evidence.
/// That is how a maturity claim outlives the thing that justified it.
///
/// **Two hard requirements, both deliberate**, following `npm`'s shape
/// (`tests/server/npm/e2e_test.rs::test_npm_with_real_cli`): the test *fails* rather
/// than skips when `mvn` is absent, and it fails with an explicit message when the
/// user's `~/.m2/repository` has never cached `maven-dependency-plugin`.
///
/// **Nothing external is contacted**, which took some arranging and is the reason the
/// original could not simply be un-ignored. `dependency:get` needs
/// `maven-dependency-plugin`, which a fresh `-Dmaven.repo.local` cannot resolve without
/// Maven Central. The way out is Maven 3.9's *split local repository*: writes go to a
/// throwaway head (`-Dmaven.repo.local`), reads fall back to the user's existing cache
/// (`-Dmaven.repo.local.tail`), so the plugin is found locally and never fetched. A
/// test-owned `settings.xml` then mirrors `*` at the NetGet port, which suppresses
/// `central` and any repository in the user's own settings — verified: the only
/// "Downloading from" line names 127.0.0.1. The user's real `~/.m2` is never written to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maven_cli_download() -> E2EResult<()> {
    println!("\n=== E2E Test: Real Maven CLI Download ===");

    // The mvn CLI *is* the evidence this test exists to produce. A machine without it
    // must say so, not report a silent pass.
    match tokio::process::Command::new("mvn")
        .arg("--version")
        .output()
        .await
    {
        Ok(out) if out.status.success() => println!(
            "{}",
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("mvn")
        ),
        Ok(out) => {
            return Err(format!(
                "`mvn --version` exited {}: this test's whole point is driving the real \
                 Maven CLI against NetGet's repository",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "the Maven CLI is not available ({e}): this test's whole point is driving \
                 the real `mvn` against NetGet's repository, and skipping it would leave \
                 Maven's real-client claim resting on nothing"
            )
            .into())
        }
    }

    // The split local repository's tail. Reads only — Maven writes into the head below.
    let tail_repo = dirs_home()?.join(".m2").join("repository");
    // The cached plugin, named by its full coordinates when invoked: the `dependency:` prefix
    // is resolved through plugin-group metadata from a repository, and with every repository
    // mirrored to NetGet that lookup sometimes failed ("No plugin found for prefix
    // 'dependency'") although the plugin itself was cached.
    let plugin_dir = tail_repo.join("org/apache/maven/plugins/maven-dependency-plugin");
    let plugin_version = std::fs::read_dir(&plugin_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let v = e.file_name().to_string_lossy().into_owned();
            e.path()
                .join(format!("maven-dependency-plugin-{v}.jar"))
                .is_file()
                .then_some(v)
        })
        .max_by_key(|v| {
            v.split(|c: char| !c.is_ascii_digit())
                .map(|n| n.parse::<u64>().unwrap_or(0))
                .collect::<Vec<_>>()
        });
    let Some(plugin_version) = plugin_version else {
        return Err(format!(
            "{} has no cached maven-dependency-plugin. This test resolves plugins from \
             that cache on purpose so it never contacts Maven Central; warm it once with \
             `mvn -B dependency:get -Dartifact=junit:junit:4.13.2` and re-run.",
            tail_repo.display()
        )
        .into());
    };
    let plugin = format!("org.apache.maven.plugins:maven-dependency-plugin:{plugin_version}");

    // The exact bytes served, and their SHA-1s computed by `shasum` — an implementation
    // NetGet does not own. Maven verifies the `.sha1` companion against what it received
    // and fails the resolution on a mismatch, so serving a checksum computed elsewhere is
    // what turns "Maven got 200s" into "Maven accepted the artifact".
    const POM_BODY: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n",
        "  <modelVersion>4.0.0</modelVersion>\n",
        "  <groupId>com.netget.test</groupId>\n",
        "  <artifactId>maven-test</artifactId>\n",
        "  <version>1.0.0</version>\n",
        "  <packaging>jar</packaging>\n",
        "</project>\n"
    );
    // A **real JAR**, not a text placeholder: a zip built by Python's `zipfile`, which
    // NetGet does not own, containing a manifest and one resource. This is what lets the
    // last step below ask Maven to *unpack* the artifact — a repository whose artifacts
    // have only ever been fetched and checksummed has not been shown to be usable, and
    // that was the one thing standing between this protocol and `Beta`.
    let jar_dir = tempfile::tempdir()?;
    let jar_path = build_real_jar(jar_dir.path())?;
    let jar_bytes = fs::read(&jar_path)?;
    assert_eq!(
        &jar_bytes[..2],
        b"PK",
        "the fixture must be a real zip, or `dependency:unpack` proves nothing"
    );
    let jar_base64 = base64_of(&jar_path)?;

    let pom_sha1 = external_sha1(POM_BODY.as_bytes())
        .ok_or("`shasum -a 1` is required to compute the checksums Maven verifies")?;
    let jar_sha1 = external_sha1(&jar_bytes)
        .ok_or("`shasum -a 1` is required to compute the checksums Maven verifies")?;

    // ONE rule that branches on the event, not several rules on the same event: rules
    // are first-match-wins, and Maven's request order is its own business.
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via maven.").with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("maven")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Maven",
                    "instruction": "Serve com.netget.test:maven-test:1.0.0"
                }]))
                .expect_calls(1)
                .and()
                .on_event("maven_artifact_request")
                .respond_with_actions_from_event(move |e| {
                    let extension = e["extension"].as_str().unwrap_or("");
                    let is_checksum = e["is_checksum"].as_bool().unwrap_or(false);
                    // The JAR goes out as `body_base64` because it is binary; everything
                    // else is UTF-8 text and goes out as `body`.
                    let (content_type, key, body) = match (extension, is_checksum) {
                        ("pom", false) => ("application/xml", "body", POM_BODY.to_string()),
                        ("pom", true) => ("text/plain", "body", pom_sha1.clone()),
                        ("jar", false) => (
                            "application/java-archive",
                            "body_base64",
                            jar_base64.clone(),
                        ),
                        ("jar", true) => ("text/plain", "body", jar_sha1.clone()),
                        _ => {
                            return serde_json::json!([{
                                "type": "send_maven_error",
                                "status": 404,
                                "message": "not served by this test"
                            }])
                        }
                    };
                    let mut action = serde_json::Map::new();
                    action.insert("type".into(), "send_maven_artifact".into());
                    action.insert("status".into(), 200.into());
                    action.insert("content_type".into(), content_type.into());
                    action.insert(key.into(), body.into());
                    serde_json::Value::Array(vec![serde_json::Value::Object(action)])
                })
                .expect_at_least(2)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    let work = tempfile::tempdir()?;
    let head_repo = work.path().join("repo");
    let settings = work.path().join("settings.xml");
    fs::write(
        &settings,
        format!(
            "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">\n\
             \x20 <mirrors>\n\
             \x20   <mirror>\n\
             \x20     <id>netget-under-test</id>\n\
             \x20     <url>http://127.0.0.1:{}/</url>\n\
             \x20     <mirrorOf>*</mirrorOf>\n\
             \x20   </mirror>\n\
             \x20 </mirrors>\n\
             </settings>\n",
            server.port
        ),
    )?;

    // `tokio::process`, not `std::process`: the in-process mock Ollama server shares this
    // test's runtime, and a blocking `mvn` would hold a worker while netget waits on the
    // model that cannot run.
    let output = tokio::process::Command::new("mvn")
        .arg("-B")
        .arg("-s")
        .arg(&settings)
        .arg(format!("-Dmaven.repo.local={}", head_repo.display()))
        .arg(format!("-Dmaven.repo.local.tail={}", tail_repo.display()))
        .arg(format!("{plugin}:get"))
        .arg("-Dartifact=com.netget.test:maven-test:1.0.0")
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Nothing outside this machine may be contacted.
    for line in stdout.lines().filter(|l| l.contains("Downloading from")) {
        assert!(
            line.contains("127.0.0.1"),
            "Maven reached outside localhost: {line}"
        );
    }

    assert!(
        output.status.success(),
        "mvn dependency:get failed against NetGet.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The assertion that means something: Maven wrote the artifact into its local
    // repository, which it does only after the download AND the checksum verification.
    let jar = head_repo.join("com/netget/test/maven-test/1.0.0/maven-test-1.0.0.jar");
    let pom = head_repo.join("com/netget/test/maven-test/1.0.0/maven-test-1.0.0.pom");
    assert!(
        jar.is_file(),
        "Maven reported success but wrote no JAR at {}\nstdout:\n{stdout}",
        jar.display()
    );
    assert_eq!(
        fs::read(&jar)?,
        jar_bytes,
        "the JAR Maven stored is not the one NetGet served"
    );
    assert_eq!(
        fs::read_to_string(&pom)?,
        POM_BODY,
        "the POM Maven stored is not the one NetGet served"
    );
    println!("mvn resolved, checksum-verified and stored the artifact NetGet served");

    // And Maven can *use* it. `dependency:unpack` opens the stored archive with Maven's
    // own unarchiver and writes its entries out, so a JAR that is not a real zip fails
    // here even though it downloaded and checksum-verified perfectly.
    //
    // This is the step that separates "a real client fetched bytes from this repository"
    // from "a real client used an artifact from this repository", and it is why the
    // fixture above is a genuine zip rather than the text placeholder it used to be.
    let unpacked = work.path().join("unpacked");
    let output = tokio::process::Command::new("mvn")
        .arg("-B")
        .arg("-s")
        .arg(&settings)
        .arg(format!("-Dmaven.repo.local={}", head_repo.display()))
        .arg(format!("-Dmaven.repo.local.tail={}", tail_repo.display()))
        .arg(format!("{plugin}:unpack"))
        .arg("-Dartifact=com.netget.test:maven-test:1.0.0")
        .arg(format!("-DoutputDirectory={}", unpacked.display()))
        // Outside a project, `dependency:unpack` writes its marker directory relative to
        // the working directory under a literal, unexpanded `${project.basedir}` name.
        // Both of these keep that inside the tempdir instead of the repository root.
        .arg(format!(
            "-Dmdep.markersDirectory={}",
            work.path().join("markers").display()
        ))
        .current_dir(work.path())
        .output()
        .await?;
    let unpack_stdout = String::from_utf8_lossy(&output.stdout);
    let unpack_stderr = String::from_utf8_lossy(&output.stderr);
    for line in unpack_stdout
        .lines()
        .filter(|l| l.contains("Downloading from"))
    {
        assert!(
            line.contains("127.0.0.1"),
            "Maven reached outside localhost: {line}"
        );
    }
    assert!(
        output.status.success(),
        "mvn dependency:unpack failed on the artifact NetGet served — the JAR is not a \
         usable archive.\nstdout:\n{unpack_stdout}\nstderr:\n{unpack_stderr}"
    );
    assert_eq!(
        fs::read_to_string(unpacked.join("com/netget/test/greeting.txt"))?,
        GREETING,
        "Maven unpacked the archive but the resource inside it is not what NetGet served"
    );
    println!("mvn unpacked the archive: a real client used an artifact from this repository");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// The resource inside the fixture JAR, asserted after Maven unpacks it.
const GREETING: &str = "hello from a real jar\n";

/// Build a genuine JAR — a zip with a manifest and one resource — using Python's
/// `zipfile`, an archiver NetGet does not own.
///
/// The point is not the manifest; it is that the bytes are a *real* archive, so
/// `mvn dependency:unpack` exercises Maven's unarchiver against what NetGet served.
/// With a text placeholder the download and the checksum both pass and nothing is ever
/// opened, which is precisely the gap that kept this protocol at `Experimental`.
fn build_real_jar(dir: &std::path::Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("maven-test-1.0.0.jar");
    let script = format!(
        "import sys, zipfile\n\
         z = zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED)\n\
         z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\\nCreated-By: netget-test\\n')\n\
         z.writestr('com/netget/test/greeting.txt', {greeting})\n\
         z.close()\n",
        greeting = serde_json::to_string(GREETING).unwrap(),
    );
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .arg(&path)
        .output()
        .map_err(|e| {
            format!(
                "python3 is not available ({e}): it builds the real JAR this test serves, and \
                 without a real archive `mvn dependency:unpack` would prove nothing. Install \
                 it with `brew install python3` or `apt-get install -y python3`."
            )
        })?;
    if !out.status.success() {
        return Err(format!(
            "python3 could not build the fixture JAR: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(path)
}

/// Base64 of a file, via Python rather than a crate, so the encoder is not this
/// codebase either.
fn base64_of(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg("import sys,base64;sys.stdout.write(base64.b64encode(open(sys.argv[1],'rb').read()).decode())")
        .arg(path)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "python3 could not base64 the fixture JAR: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// SHA-1 via `shasum -a 1`, an implementation NetGet does not own, so the checksum
/// Maven verifies is not this codebase checking itself.
///
/// Called before the server starts, so the blocking `Command` here cannot starve the
/// mock model.
fn external_sha1(bytes: &[u8]) -> Option<String> {
    use std::io::Write;
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("payload.bin");
    std::fs::File::create(&path).ok()?.write_all(bytes).ok()?;
    let out = std::process::Command::new("shasum")
        .arg("-a")
        .arg("1")
        .arg(&path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(stdout.split_whitespace().next()?.to_string())
}

/// The user's home directory, without pulling in a crate for it.
fn dirs_home() -> Result<std::path::PathBuf, String> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            "HOME is not set, so the Maven local repository cannot be located".to_string()
        })
}
