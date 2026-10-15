//! An oversized request body must be refused before it is buffered, and before a model call.
//!
//! `hyper::body::Incoming` has no default limit. `req.into_body().collect()` therefore buffered
//! whatever the peer chose to send, from an unauthenticated `POST` to a port that IPP clients
//! try by default. This server keeps no job store and never looks past the 8-byte header, so
//! there is nothing a large body could be needed for.
//!
//! The second half is the part worth a test of its own: the old code turned a body read failure
//! into `Bytes::new()`, which `parse_ipp_header` reports as the operation `Empty`. The model
//! would then have been asked to answer a request nobody sent — the truncated-body-looks-like-a
//! -complete-one shape `http_common::BodyTooLarge` exists to avoid. So this asserts **zero**
//! `ipp_request_received` calls, not merely that the status is 413.
//!
//! The refusal is expressed twice, deliberately. HTTP 413 is what a generic client sees; the
//! body carries `client-error-request-entity-too-large` (0x0408) so an IPP client that only
//! reads the IPP layer learns the same thing rather than reporting a truncated response.
//!
//! **Expressing it twice is worth nothing if the peer never reads it**, which is what the third
//! test here is about. A server that answers 413 and closes while the peer is still writing
//! sends `RST` — closing a socket with unread data in the receive queue discards the response
//! bytes already written along with it — so the peer's `write` fails with `ECONNRESET` and it
//! sees a connection error where a refusal was sent. That was this suite's own intermittent
//! failure: the first test raced, passing whenever the 9 MiB write happened to fit in the
//! socket buffers and failing when it did not. The server now drains, boundedly, before
//! answering (`LINGER_DRAIN_BYTES`).


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Larger than `MAX_IPP_BODY_BYTES` (8 MiB) in `src/server/ipp/mod.rs`.
const OVERSIZED: usize = 9 * 1024 * 1024;

/// Past the cap by more than any socket buffer will absorb, and still inside the 8 MiB the
/// server will drain. Sized so the peer is **guaranteed** to be mid-write when the server
/// decides: without the drain this fails every run rather than intermittently.
const OVERSIZED_MID_WRITE: usize = 15 * 1024 * 1024;

/// A Content-Length far past what the server will ever read, declared by a peer that then
/// stops writing. Nothing is actually sent past `OVERSIZED`: the point is the promise.
const DECLARED_BUT_NEVER_SENT: usize = 64 * 1024 * 1024;

/// Only one oversized-body test runs at a time.
///
/// Not decoration, and not a way to make a flaky test pass — it is the smallest honest fix for
/// something measured. Every test in this file that exceeds the cap makes the server buffer a
/// full `MAX_IPP_BODY_BYTES` and keeps a `netget` process alive for seconds while it does.
/// With three of them running concurrently at `--test-threads=100`, **five `tuntap` tests
/// failed in half of all runs** — each timing out after 30 seconds waiting for an in-process
/// model that was never reached — and the whole `--features amqp,ipp,eapol,tuntap` binary went
/// from 14s to 45s. Removing any one of the three made it green again, which is what says the
/// problem is their overlap rather than any one of them.
///
/// The underlying fragility is not in this file and is not fixed here: `OllamaClient` builds a
/// `reqwest::Client` per instance, which on macOS reads the keychain through
/// Security.framework, synchronously and **serialised across processes** — the mechanism the
/// root `CLAUDE.md` records against the `doh` client failures. More concurrent, longer-lived
/// `netget` processes make that queue longer. What this file can do is not lengthen it.
static ONE_OVERSIZED_BODY_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `client-error-request-entity-too-large`, RFC 8011 appendix B.
const STATUS_ENTITY_TOO_LARGE: u16 = 0x0408;

#[tokio::test]
async fn an_oversized_body_is_refused_without_reaching_the_model() -> E2EResult<()> {
    let _serialised = ONE_OVERSIZED_BODY_AT_A_TIME.lock().await;
    let config =
        NetGetConfig::new("Open IPP on port {AVAILABLE_PORT} as a printer.").with_mock(|mock| {
            mock.on_instruction_containing("Open IPP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IPP",
                    "instruction": "IPP printer"
                }]))
                .expect_calls(1)
                .and()
                // The load-bearing expectation. If the cap ever stops firing, the oversized
                // request reaches the model and this count goes to 1.
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ipp_response",
                    "ipp_status": "successful-ok"
                }]))
                .expect_calls(0)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    wait_until_listening(server.port).await?;

    // A well-formed 8-byte header so nothing else can be blamed for the refusal, then bulk.
    let mut body = vec![0x01, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD];
    body.resize(OVERSIZED, 0x00);

    let response = tokio::time::timeout(
        Duration::from_secs(60),
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/printers/netget", server.port))
            .header("Content-Type", "application/ipp")
            .body(body)
            .send(),
    )
    .await
    .map_err(|_| "IPP server never answered the oversized request")??;

    assert_eq!(
        response.status(),
        413,
        "an oversized body must be refused with 413, not buffered and answered"
    );

    // The IPP layer must carry the same refusal: a client that reads only the IPP status must
    // not see a truncated or absent message.
    let reply = response.bytes().await?;
    assert!(
        reply.len() >= 9,
        "the refusal must still be a well-formed IPP message, got {} bytes",
        reply.len()
    );
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]),
        STATUS_ENTITY_TOO_LARGE,
        "expected client-error-request-entity-too-large, got 0x{:04x}",
        u16::from_be_bytes([reply[2], reply[3]])
    );
    assert_eq!(
        reply[reply.len() - 1],
        0x03,
        "the message must end with the end-of-attributes tag"
    );

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}

/// A body under the cap must still be served, so the refusal is not a refusal of everything.
#[tokio::test]
async fn a_body_under_the_cap_is_still_answered() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Open IPP on port {AVAILABLE_PORT} as a printer.").with_mock(|mock| {
            mock.on_instruction_containing("Open IPP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IPP",
                    "instruction": "IPP printer"
                }]))
                .expect_calls(1)
                .and()
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ipp_job_attributes",
                    "attributes": {"job-id": 7, "job-state": "completed"}
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    wait_until_listening(server.port).await?;

    // 1 MiB: a plausible Print-Job document, comfortably inside the cap.
    let mut body = vec![0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x02, 0xA7];
    body.push(0x03); // end-of-attributes, then document data
    body.resize(1024 * 1024, b'A');

    let response = tokio::time::timeout(
        Duration::from_secs(60),
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/printers/netget", server.port))
            .header("Content-Type", "application/ipp")
            .body(body)
            .send(),
    )
    .await
    .map_err(|_| "IPP server never answered a request inside the cap")??;

    assert_eq!(response.status(), 200, "a 1 MiB Print-Job must be served");
    let reply = response.bytes().await?;
    assert_eq!(
        u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]),
        0x0000_02A7,
        "the request-id must still be echoed"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// The refusal must reach a peer that is still writing when the server decides.
///
/// This is the one the fix is for. The server stops reading at 8 MiB, so with a 15 MiB body the
/// peer still has ~7 MiB to send — far more than any socket buffer holds — and is therefore
/// blocked in `write` when the 413 is produced. Answer-and-close there sends `RST`, the peer's
/// `write` fails with `ECONNRESET`, and both the HTTP status and the IPP status are lost. The
/// server drains the remainder (counting and discarding, never buffering) so the peer can
/// finish, then answers.
///
/// Both halves matter: the status assertions would pass on a server that had no limit at all if
/// `expect_calls(0)` were dropped, and `expect_calls(0)` would pass on a server that reset the
/// connection if the status assertions were dropped.
///
/// Written against a raw socket rather than `reqwest`, and that is the difference between a
/// test that reproduces the defect every run and one that reproduces it about half the time.
/// A hyper client polls the read side while it is still writing, so it can parse the 413 out of
/// its receive buffer *before* the `RST` arrives and lose the race in the test's favour —
/// measured at 5 failures in 8 runs with the drain disabled, which is exactly the intermittency
/// this suite was reported with. Writing the whole body first and only then reading is what an
/// IPP client with a document to send does anyway, and it makes the reset unmissable.
#[tokio::test]
async fn the_refusal_reaches_a_peer_that_is_still_writing() -> E2EResult<()> {
    let _serialised = ONE_OVERSIZED_BODY_AT_A_TIME.lock().await;
    let config =
        NetGetConfig::new("Open IPP on port {AVAILABLE_PORT} as a printer.").with_mock(|mock| {
            mock.on_instruction_containing("Open IPP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IPP",
                    "instruction": "IPP printer"
                }]))
                .expect_calls(1)
                .and()
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ipp_response",
                    "ipp_status": "successful-ok"
                }]))
                .expect_calls(0)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    wait_until_listening(server.port).await?;

    let mut body = vec![0x01, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD];
    body.resize(OVERSIZED_MID_WRITE, 0x00);

    let (status, reply) =
        tokio::time::timeout(Duration::from_secs(60), post_then_read(server.port, &body))
            .await
            .map_err(|_| "IPP server never answered the oversized request")?
            .map_err(|e| {
                format!(
            "the peer was reset instead of being answered ({e}); the server decided at the cap \
             and closed while {} MiB was still in flight",
            (OVERSIZED_MID_WRITE - 8 * 1024 * 1024) / (1024 * 1024)
        )
            })?;

    assert_eq!(status, 413, "the peer must receive the refusal");
    assert!(
        reply.len() >= 9,
        "the refusal must still be a well-formed IPP message, got {} bytes",
        reply.len()
    );
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]),
        STATUS_ENTITY_TOO_LARGE,
        "the IPP layer must carry the refusal too"
    );

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}

/// Write a whole IPP POST, *then* read the reply, on a raw socket.
///
/// Deliberately sequential: a client that reads while it writes can win the race against an
/// `RST` and see a refusal that a client which finishes writing first never gets. Returns the
/// HTTP status and the response body, or the write error that means the server hung up.
async fn post_then_read(port: u16, body: &[u8]) -> Result<(u16, Vec<u8>), std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let head = format!(
        "POST /printers/netget HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no header terminator in the reply"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other(format!("no status in {head:?}")))?;
    Ok((status, raw[split + 4..].to_vec()))
}

/// The drain is politeness, not an obligation, so it is bounded in **time** as well as in
/// bytes — and the deadline is the bound that matters, because it is the one a hostile peer
/// cannot sidestep.
///
/// `LINGER_DRAIN_BYTES` only binds a peer that writes *fast*; such a peer has already spent
/// the bandwidth, and it reaches the byte bound in a moment. A peer that declares 64 MiB,
/// sends just past the cap and then says nothing costs it nothing at all, and without
/// `LINGER_DRAIN_TIMEOUT` the drain waits for the rest of that 64 MiB forever — holding a
/// connection, a task and an `AppState` row, which is the free denial of service every other
/// bound in this tree exists to close.
///
/// Without the deadline this test does not fail, it **hangs**: the 20-second timeout below is
/// the assertion. The model must still never be asked, whichever way the exchange ends.
///
/// Deliberately cheap. An earlier version proved the byte bound by actually sending
/// cap + drain + slack — 24 MiB through a debug build — and that much loopback traffic starved
/// the rest of the suite: five `tuntap` tests waiting on an in-process model timed out at 30s
/// in half of all runs, and the whole binary went from 14s to 45s. A test that has to
/// monopolise the machine to prove a bound is not worth the bound.
#[tokio::test]
async fn a_peer_that_stops_writing_cannot_hold_the_drain_open() -> E2EResult<()> {
    let _serialised = ONE_OVERSIZED_BODY_AT_A_TIME.lock().await;
    let config =
        NetGetConfig::new("Open IPP on port {AVAILABLE_PORT} as a printer.").with_mock(|mock| {
            mock.on_instruction_containing("Open IPP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IPP",
                    "instruction": "IPP printer"
                }]))
                .expect_calls(1)
                .and()
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ipp_response",
                    "ipp_status": "successful-ok"
                }]))
                .expect_calls(0)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    wait_until_listening(server.port).await?;

    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await?;
        let port = server.port;
        let head = format!(
            "POST /printers/netget HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Type: application/ipp\r\nContent-Length: {DECLARED_BUT_NEVER_SENT}\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await?;

        // Just past the cap, so the server is committed to draining, and then silence. The
        // other 55 MiB it was promised never arrive.
        let mut sent = vec![0x01, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD];
        sent.resize(OVERSIZED, 0x00);
        stream.write_all(&sent).await?;
        stream.flush().await?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        Ok::<Vec<u8>, std::io::Error>(raw)
    })
    .await
    .map_err(|_| {
        "the server was still waiting for a body the peer had stopped sending; the drain \
         deadline did not fire"
    })?;

    // Either way is acceptable — the deadline may end in a 413 the peer can still read, or in
    // a close. What is not acceptable is the exchange never ending. When there is a status
    // line, it must be the refusal and not an answer.
    if let Ok(raw) = ended {
        if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..split]).to_string();
            assert!(
                head.contains(" 413 "),
                "if the peer was answered at all, it must have been refused, got {head:?}"
            );
        }
    }

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    Ok(())
}

/// Poll until the IPP server's TCP port accepts a connection.
///
/// `start_netget_server` returns when startup has been *parsed*, not when the socket is bound.
/// Every other test here posts a few dozen bytes and wins the race by accident; these post a
/// megabyte and nine, which takes long enough under `--test-threads=100` that losing it shows
/// up as the server "answering wrongly" rather than as a connection refused. Wait for the
/// condition instead of hoping.
async fn wait_until_listening(port: u16) -> E2EResult<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(_) => return Ok(()),
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(format!("IPP server never bound port {port}: {e}").into())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}
