//! End-to-end tests for NPM Registry client
//!
//! These tests verify that the NPM client can:
//! 1. Search for packages
//! 2. Get package information
//! 3. Download package tarballs
//!
//! Target: < 10 LLM calls per test suite
//! Runtime: ~60 seconds

use netget::client::npm::NpmClient;
use netget::llm::OllamaClient;
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientInstance, ClientStatus};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Helper to create test environment
async fn setup_test() -> (Arc<AppState>, OllamaClient, mpsc::UnboundedSender<String>) {
    let state = Arc::new(AppState::new());
    let llm_client = OllamaClient::new("http://localhost:11434".to_string());
    let (status_tx, _status_rx) = mpsc::unbounded_channel();

    (state, llm_client, status_tx)
}

#[tokio::test]
#[ignore = "Requires Ollama and network access"]
async fn test_npm_client_get_package_info() {
    let (app_state, llm_client, status_tx) = setup_test().await;

    // Register client
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "https://registry.npmjs.org".to_string(),
        "NPM".to_string(),
        "Get information about the lodash package".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect to NPM registry
    let result = NpmClient::connect_with_llm_actions(
        "https://registry.npmjs.org".to_string(),
        llm_client.clone(),
        app_state.clone(),
        status_tx.clone(),
        client_id,
    )
    .await;

    assert!(result.is_ok(), "Failed to connect NPM client: {:?}", result);

    // Verify client is connected
    let client = app_state.get_client(client_id).await;
    assert!(client.is_some(), "Client not found in state");
    assert_eq!(client.unwrap().status, ClientStatus::Connected);

    // Get package info
    let get_result = NpmClient::get_package_info(
        client_id,
        "lodash".to_string(),
        "latest".to_string(),
        app_state.clone(),
        llm_client.clone(),
        status_tx.clone(),
    )
    .await;

    assert!(
        get_result.is_ok(),
        "Failed to get package info: {:?}",
        get_result
    );
}

#[tokio::test]
#[ignore = "Requires Ollama and network access"]
async fn test_npm_client_search_packages() {
    let (app_state, llm_client, status_tx) = setup_test().await;

    // Register client
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "https://registry.npmjs.org".to_string(),
        "NPM".to_string(),
        "Search for http server packages".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect to NPM registry
    let result = NpmClient::connect_with_llm_actions(
        "https://registry.npmjs.org".to_string(),
        llm_client.clone(),
        app_state.clone(),
        status_tx.clone(),
        client_id,
    )
    .await;

    assert!(result.is_ok(), "Failed to connect NPM client: {:?}", result);

    // Search for packages
    let search_result = NpmClient::search_packages(
        client_id,
        "http server".to_string(),
        10,
        app_state.clone(),
        llm_client.clone(),
        status_tx.clone(),
    )
    .await;

    assert!(
        search_result.is_ok(),
        "Failed to search packages: {:?}",
        search_result
    );
}

/// `download_tarball` fetches, reports, and writes nothing to disk.
///
/// This test used to be `#[ignore]`d, point at the public `registry.npmjs.org`, and
/// assert on the **real filesystem** — `output_path.exists()` after
/// `NpmClient::download_tarball(..., "/tmp/lodash-test.tgz", ...)`. That was the
/// coverage for an arbitrary-file-write driven by LLM output; the write is gone, and
/// so is the test that certified it. What replaces it runs by default against a
/// loopback stub, which is what the rest of this protocol's live tests already do.
#[tokio::test]
async fn download_tarball_reports_the_bytes_and_writes_no_file() {
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TARBALL: &[u8] = b"not-a-real-tgz-but-exactly-31-bytes";

    // A stand-in registry: the packument on any /-prefixed path, the tarball bytes on
    // /pkg.tgz. Nothing leaves this machine.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                seen.lock().unwrap().push(line.clone());
                let resp: Vec<u8> = if line.contains("/pkg.tgz") {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        TARBALL.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(TARBALL);
                    r
                } else {
                    let body = format!(
                        r#"{{"name":"demo","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"dist":{{"tarball":"http://127.0.0.1:{port}/pkg.tgz","integrity":"sha512-deadbeef"}}}}}}}}"#
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .into_bytes()
                };
                let _ = sock.write_all(&resp).await;
                let _ = sock.flush().await;
            });
        }
    });

    let (app_state, llm_client, status_tx) = setup_test().await;
    let registry = format!("http://127.0.0.1:{port}");
    let client = ClientInstance::new(
        ClientId::new(0),
        registry.clone(),
        "NPM".to_string(),
        String::new(),
    );
    let client_id = app_state.add_client(client).await;
    app_state
        .update_client_status(client_id, ClientStatus::Connected)
        .await;
    app_state
        .with_client_mut(client_id, |c| {
            c.set_protocol_field("registry_url".to_string(), serde_json::json!(registry));
        })
        .await;

    let summary = NpmClient::download_tarball(
        client_id,
        "demo".to_string(),
        "latest".to_string(),
        app_state.clone(),
        status_tx.clone(),
    )
    .await
    .expect("download_tarball should succeed against the stub registry");

    assert!(
        summary.contains(&TARBALL.len().to_string()),
        "the summary does not report how many bytes arrived: {summary}"
    );
    assert!(
        summary.contains("sha512-deadbeef"),
        "the summary does not carry the integrity the registry advertised: {summary}"
    );
    assert!(
        summary.contains("not saved"),
        "the summary should say plainly that nothing was stored: {summary}"
    );

    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.contains("/pkg.tgz")),
        "the tarball itself was never fetched: {requests:?}"
    );
}

#[tokio::test]
#[ignore = "Requires Ollama and network access"]
async fn test_npm_client_scoped_package() {
    let (app_state, llm_client, status_tx) = setup_test().await;

    // Register client
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "https://registry.npmjs.org".to_string(),
        "NPM".to_string(),
        "Get information about @types/node package".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect to NPM registry
    let result = NpmClient::connect_with_llm_actions(
        "https://registry.npmjs.org".to_string(),
        llm_client.clone(),
        app_state.clone(),
        status_tx.clone(),
        client_id,
    )
    .await;

    assert!(result.is_ok(), "Failed to connect NPM client: {:?}", result);

    // Get info for scoped package
    let get_result = NpmClient::get_package_info(
        client_id,
        "@types/node".to_string(),
        "latest".to_string(),
        app_state.clone(),
        llm_client.clone(),
        status_tx.clone(),
    )
    .await;

    assert!(
        get_result.is_ok(),
        "Failed to get scoped package info: {:?}",
        get_result
    );
}
