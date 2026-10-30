//! MCP server mode (STDIO and HTTP transports)
//!
//! Runs NetGet as an MCP server, exposing network protocol management as MCP
//! tools. Protocol servers are driven by NetGet's own configured LLM backend
//! (Ollama or an OpenAI-compatible endpoint).

#[cfg(feature = "mcp-http")]
pub mod agent_client;
pub mod control;
pub mod docs;
#[cfg(feature = "mcp-stdio")]
pub mod drain;
pub mod events;
pub mod http_guard;
#[cfg(feature = "mcp-stdio")]
pub mod stdio;
pub mod tools;

use anyhow::Result;
use tracing::info;

use crate::cli::Args;
use crate::settings::Settings;

/// Main entry point for MCP STDIO server mode
#[cfg(feature = "mcp-stdio")]
pub async fn run_mcp_stdio(args: &Args, settings: Settings) -> Result<()> {
    // Logging goes to stderr only (stdout = JSON-RPC)
    // The CLI setup already handles this for non-interactive mode

    info!("Starting NetGet MCP STDIO server");

    // Create the MCP server service
    let service = tools::NetGetMcpService::new(args, settings).await?;

    // Serve over stdin/stdout. rmcp's own stdio transport, wrapped so that a request still
    // being handled when stdin closes is answered before the server stops (see `drain`).
    let (stdin, stdout) = rmcp::transport::stdio();
    stdio::serve(service, stdin, stdout).await?;

    info!("MCP STDIO server shut down");
    Ok(())
}

/// Entry point for MCP HTTP/SSE server mode
///
/// Serves the same tools as STDIO mode over the MCP Streamable HTTP transport,
/// allowing remote or web-based MCP clients to connect. All HTTP sessions share
/// a single `SharedState` (servers/clients started in one session are visible to all).
///
/// Every request passes `http_guard::HttpGuard` first (see that module): on a
/// loopback bind without a token, `Host` and `Origin` must name a loopback host so a
/// DNS-rebound web page cannot drive the endpoint; with `--mcp-token` /
/// `NETGET_MCP_TOKEN` every request needs that bearer token, and that is the only way
/// to bind a non-loopback address.
#[cfg(feature = "mcp-http")]
pub async fn run_mcp_http(args: &Args, settings: Settings, port: u16) -> Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;

    let listen_addr = args.listen_addr.as_deref().unwrap_or("127.0.0.1");
    let bind_ip: std::net::IpAddr = listen_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("--listen-addr {listen_addr:?} is not an IP address: {e}"))?;
    let guard = Arc::new(http_guard::HttpGuard::new(
        bind_ip,
        args.resolve_mcp_token(),
    )?);

    // Shared state created once, reused by every HTTP session
    let shared_state = tools::NetGetMcpService::create_shared_state(args, settings).await?;

    let service = StreamableHttpService::new(
        move || {
            Ok(tools::NetGetMcpService::new_with_shared_state(
                shared_state.clone(),
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(guard.clone(), admit));
    let listener = tokio::net::TcpListener::bind((listen_addr, port)).await?;
    let bind = listener.local_addr()?;

    info!(
        "NetGet MCP HTTP server listening on http://{}/mcp ({})",
        bind,
        if guard.requires_token() {
            "bearer token required"
        } else {
            "loopback only: Host and Origin must be local"
        }
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// The axum middleware around `/mcp`: apply the guard, then cap the body.
#[cfg(feature = "mcp-http")]
async fn admit(
    axum::extract::State(guard): axum::extract::State<std::sync::Arc<http_guard::HttpGuard>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if let Err(refusal) = guard.check(request.headers(), request.uri()) {
        tracing::warn!(
            status = %refusal.status,
            host = ?request.headers().get(http::header::HOST),
            origin = ?request.headers().get(http::header::ORIGIN),
            "refused MCP HTTP request: {}",
            refusal.reason
        );
        return (refusal.status, refusal.reason).into_response();
    }
    // rmcp collects the whole body before parsing it; `Limited` makes that collect fail
    // past the cap instead of buffering a multi-gigabyte POST.
    let request = request.map(|body| {
        axum::body::Body::new(http_body_util::Limited::new(
            body,
            http_guard::MAX_REQUEST_BODY_BYTES,
        ))
    });
    next.run(request).await
}
