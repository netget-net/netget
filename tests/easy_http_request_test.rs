//! A real HTTP request through easy mode reaches the model with its path and query string.
//!
//! The HTTP server's `http_request` event carries `path` and `query_string`. Easy mode used to
//! read a `uri` field the event never has, so every request reached the model as `/` with no
//! query, whatever the browser asked for. The prompt snapshot helper takes a URI directly,
//! which is why the snapshots never showed it: this test goes through the socket, the HTTP
//! server's event and `HttpEasyProtocol::handle_event` instead.
//!
//! The mock model answers only a prompt naming the requested path and query, and its Markdown
//! must come back as HTML, so a prompt missing either fails twice: the mock reports zero
//! matched calls, and the peer gets no page.
//!
//! Local sockets only.

mod helpers;

use std::sync::Arc;
use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_easy_http_request_shows_the_model_its_path_and_query() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_prompt_containing("**Path**: /recipes/soup")
            .and_prompt_containing("**Query String**: servings=4&diet=vegan")
            .respond_with_raw("# Vegan soup\n\nServes 4.")
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = Arc::new(AppState::new_with_options(false, mock.base_url()));
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    netget::cli::easy_startup::start_easy_protocol(
        "http",
        Some("Serve recipes.".to_string()),
        Some(0),
        state.clone(),
        Arc::new(llm),
    )
    .await
    .expect("start easy http");

    let mut addr = None;
    for _ in 0..200 {
        if let Some(server) = state.get_all_servers().await.into_iter().next() {
            if let Some(a) = server.local_addr {
                addr = Some(a);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let addr = addr.expect("easy http server never bound a port");

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /recipes/soup?servings=4&diet=vegan HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut response))
        .await
        .expect("no response within 30s")
        .unwrap();
    let response = String::from_utf8_lossy(&response);

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "easy mode answers 200: {response}"
    );
    assert!(
        response.contains("<h1>Vegan soup</h1>"),
        "the model's Markdown, answered only for a prompt naming the path and query, must \
         come back as HTML: {response}"
    );

    mock.verify_calls().await.expect("mock expectations");
    for server in state.get_all_servers().await {
        state.remove_server(server.id).await;
    }
}

/// The prompt used to describe a code block as `` ```code``` `` on one line, and the renderer
/// read that line as an opening fence and swallowed everything after it into one block.
#[test]
fn a_one_line_code_fence_is_one_block_not_the_rest_of_the_page() {
    let html = netget::easy::http::actions::markdown_to_html("```let x = 1;```\n\n# After");
    assert!(
        html.contains("<pre><code>let x = 1;</code></pre>"),
        "{html}"
    );
    assert!(html.contains("<h1>After</h1>"), "{html}");

    // The fenced form still works, language name and all.
    let html = netget::easy::http::actions::markdown_to_html("```rust\nfn f() {}\n```\nAfter");
    assert!(
        html.contains("<pre><code>fn f() {}\n</code></pre>"),
        "{html}"
    );
    assert!(html.contains("<p>After</p>"), "{html}");
}
