//! The fail-open this closes: an HTTP proxy that forwards everything when the LLM is down.
//!
//! `consult_llm_http_request` returning `Err` defaulted to `RequestAction::Pass`, which sends
//! the request on to its destination unfiltered. So a proxy whose entire purpose is to let a
//! model decide what may leave the network became an open relay for exactly as long as the
//! backend was unreachable - and the access log recorded each request as having been passed on
//! purpose, so nothing about the outage was visible after the fact either.
//!
//! Its HTTPS twin, `consult_llm_https_connection`, always defaulted to Block. Only the HTTP
//! path fell open, which is the kind of asymmetry that survives review because each half looks
//! reasonable on its own.
//!
//! The assertion that matters is not the status code the client sees. It is that the target
//! server was never contacted at all.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A target that counts every connection it receives and answers a trivial 200.
///
/// It has to be a raw listener rather than a library server: the point is to detect a
/// *connection*, not a well-formed request, so that a proxy which forwards anything at all is
/// caught.
async fn start_counting_target() -> E2EResult<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            hits_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nleaked")
                    .await;
                let _ = socket.flush().await;
            });
        }
    });

    Ok((port, hits))
}

#[tokio::test]
async fn test_proxy_blocks_rather_than_forwards_when_llm_fails() -> E2EResult<()> {
    let (target_port, target_hits) = start_counting_target().await?;

    let prompt = "listen on port {AVAILABLE_PORT} using proxy stack. Decide each request";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("proxy stack")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Proxy",
                    "instruction": "Decide each request"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `proxy_http_request`, so the filtering decision cannot be made.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", server.port))?;
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .proxy(proxy)
        .timeout(Duration::from_secs(25))
        .build()?;

    let response = client
        .get(format!("http://127.0.0.1:{target_port}/secret"))
        .send()
        .await;

    match &response {
        Ok(r) => println!("proxy -> {}", r.status()),
        Err(e) => println!("proxy -> transport error: {e}"),
    }

    // Give any (wrongly) forwarded connection time to land before counting.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let hits = target_hits.load(Ordering::SeqCst);

    // Read the body before the asserts so a failure message can show what leaked.
    let body = match response {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            Some((status, text))
        }
        Err(_) => None,
    };

    assert_eq!(
        hits, 0,
        "the proxy forwarded the request to the target despite having no filtering decision - \
         this is the open-relay fail-open the change exists to close (response was {body:?})"
    );

    if let Some((status, text)) = body {
        assert!(
            (500..600).contains(&status),
            "expected a 5xx refusal from the proxy itself, got {status}: {text}"
        );
        assert!(
            !text.contains("leaked"),
            "the client received the target's body, so the request was relayed: {text}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
