//! E2E tests for the ZooKeeper server.
//!
//! Two layers, deliberately:
//!
//! 1. `test_zookeeper_connect_handshake` drives a raw socket and asserts the
//!    `ConnectResponse` **bytes**, because that frame is what every real client blocks on and
//!    a byte-level assertion is the only thing that pins its layout. It also asserts the two
//!    negotiation behaviours (timeout clamping, and refusing a first frame that is not a
//!    `ConnectRequest`).
//! 2. The remaining tests use the real `zookeeper-async` client, so a passing test means an
//!    actual ZooKeeper client completed a session and parsed our replies with its own decoder
//!    — not that our encoder agrees with our decoder.
//!
//! The previous version of this file hand-built request bytes and never sent a
//! `ConnectRequest` at all, which is exactly why the missing handshake went unnoticed.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zookeeper_async::{WatchedEvent, ZkError, ZooKeeper};

/// Session timeout the tests ask for. Inside the server's clamp range, and long enough that
/// the client's ping timer (negotiated / 3 * 2) never fires during a test.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a ZooKeeper `ConnectRequest`.
///
/// `[4 len][4 protocolVersion][8 lastZxidSeen][4 timeOut][8 sessionId][4 16][16 passwd][1 readOnly]`
fn build_connect_request(timeout_ms: i32, session_id: i64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0i32.to_be_bytes()); // protocolVersion
    payload.extend_from_slice(&0i64.to_be_bytes()); // lastZxidSeen
    payload.extend_from_slice(&timeout_ms.to_be_bytes()); // timeOut
    payload.extend_from_slice(&session_id.to_be_bytes()); // sessionId (0 = new session)
    payload.extend_from_slice(&16i32.to_be_bytes()); // passwd length
    payload.extend_from_slice(&[0u8; 16]); // passwd
    payload.push(0); // readOnly

    let mut frame = (payload.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

/// A pre-handshake `getData` request — the shape the old tests used. The server must refuse it.
fn build_bare_get_data_request(xid: i32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&xid.to_be_bytes());
    payload.extend_from_slice(&4i32.to_be_bytes()); // opcode 4 = getData
    payload.extend_from_slice(&(path.len() as i32).to_be_bytes());
    payload.extend_from_slice(path.as_bytes());
    payload.push(0); // watch = false

    let mut frame = (payload.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

/// The decoded `ConnectResponse`.
#[derive(Debug)]
struct ConnectResponse {
    protocol_version: i32,
    timeout_ms: i32,
    session_id: i64,
    passwd: Vec<u8>,
    read_only: u8,
}

/// Perform the handshake on `stream` and decode the reply.
async fn handshake(
    stream: &mut TcpStream,
    timeout_ms: i32,
    session_id: i64,
) -> E2EResult<ConnectResponse> {
    stream
        .write_all(&build_connect_request(timeout_ms, session_id))
        .await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "timed out waiting for the ConnectResponse length prefix")??;

    // protocolVersion(4) + timeOut(4) + sessionId(8) + passwd(4+16) + readOnly(1)
    let declared_len = i32::from_be_bytes(len_buf);
    assert_eq!(
        declared_len, 37,
        "ConnectResponse body must be 37 bytes when the request carried a readOnly flag"
    );

    let mut body = vec![0u8; declared_len as usize];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body))
        .await
        .map_err(|_| "timed out waiting for the ConnectResponse body")??;

    Ok(ConnectResponse {
        protocol_version: i32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        timeout_ms: i32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        session_id: i64::from_be_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]),
        passwd: {
            let passwd_len = i32::from_be_bytes([body[16], body[17], body[18], body[19]]);
            assert_eq!(passwd_len, 16, "session password must be 16 bytes");
            body[20..36].to_vec()
        },
        read_only: body[36],
    })
}

/// A ZooKeeper server whose handler never has to run: every assertion is about the handshake.
///
/// LLM calls: 1 (server startup)
#[tokio::test]
async fn test_zookeeper_connect_handshake() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a ZooKeeper server on port 0.").with_mock(|mock| {
        mock.on_instruction_containing("ZooKeeper")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ZooKeeper",
                    "instruction": "Answer coordination requests"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let addr = format!("127.0.0.1:{}", server.port);

    // 1. A normal handshake.
    let mut stream = TcpStream::connect(&addr).await?;
    let resp = handshake(&mut stream, 30_000, 0).await?;
    assert_eq!(resp.protocol_version, 0, "protocolVersion must be 0");
    assert_eq!(
        resp.timeout_ms, 30_000,
        "a timeout inside the server's range must be granted unchanged"
    );
    assert_ne!(
        resp.session_id, 0,
        "session id 0 means 'no session' and would leave the client unusable"
    );
    assert_eq!(resp.passwd.len(), 16);
    assert_ne!(
        resp.passwd,
        vec![0u8; 16],
        "the session password must be derived, not echoed back as the client's zeros"
    );
    assert_eq!(resp.read_only, 0, "this server is never read-only");

    // 2. A timeout below the server's minimum is clamped up, not rejected.
    let mut stream2 = TcpStream::connect(&addr).await?;
    let clamped = handshake(&mut stream2, 500, 0).await?;
    assert_eq!(
        clamped.timeout_ms, 4_000,
        "a sub-minimum timeout must be clamped to minSessionTimeout"
    );
    assert_ne!(
        clamped.session_id, resp.session_id,
        "each new session must get its own id"
    );

    // 3. A client resuming a session gets its own id back.
    let mut stream3 = TcpStream::connect(&addr).await?;
    let resumed = handshake(&mut stream3, 30_000, resp.session_id).await?;
    assert_eq!(
        resumed.session_id, resp.session_id,
        "a presented session id must be honoured, not silently replaced"
    );

    // 4. The regression guard: a first frame that is not a ConnectRequest must be refused
    //    outright rather than parsed as a request header. This is the shape the pre-fix tests
    //    used, and the reason the missing handshake went unnoticed.
    let mut stream4 = TcpStream::connect(&addr).await?;
    stream4
        .write_all(&build_bare_get_data_request(1, "/config/database"))
        .await?;
    stream4.flush().await?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream4.read(&mut buf))
        .await
        .map_err(|_| "server neither answered nor closed a request sent before the handshake")??;
    assert_eq!(
        n, 0,
        "a request sent before the handshake must close the connection, not get a reply"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A real `zookeeper-async` client reads a znode.
///
/// LLM calls: 2 (server startup + getData)
#[tokio::test]
async fn test_zookeeper_get_data() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start ZooKeeper server on port 0. When clients read /config/database, return \
         'postgres://localhost:5432'.",
    )
    .with_mock(|mock| {
        mock.on_event("zookeeper_request")
            .and_event_data_contains("operation", "getData")
            .and_event_data_contains("path", "/config/database")
            .respond_with_actions_from_event(|e| {
                serde_json::json!([
                    {
                        "type": "zookeeper_data",
                        // The client correlates by xid; a literal would break the session.
                        "xid": e["xid"].as_i64().unwrap_or(0),
                        "zxid": 100,
                        "data": "postgres://localhost:5432",
                        "version": 7
                    }
                ])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("ZooKeeper")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ZooKeeper",
                    "instruction": "Return database config"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let zk = ZooKeeper::connect(
        &format!("127.0.0.1:{}", server.port),
        SESSION_TIMEOUT,
        |_ev: WatchedEvent| {},
    )
    .await?;

    let (data, stat) = tokio::time::timeout(
        Duration::from_secs(10),
        zk.get_data("/config/database", false),
    )
    .await
    .map_err(|_| "timed out waiting for getData - the client never completed its session")??;

    assert_eq!(
        String::from_utf8_lossy(&data),
        "postgres://localhost:5432",
        "the client must decode the data we encoded"
    );
    assert_eq!(stat.czxid, 100, "Stat.czxid must carry the handler's zxid");
    assert_eq!(
        stat.version, 7,
        "Stat.version must carry the handler's version"
    );
    assert_eq!(
        stat.data_length,
        data.len() as i32,
        "Stat.dataLength must match the data actually sent"
    );

    zk.close().await?;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A real client lists children.
///
/// LLM calls: 2 (server startup + getChildren)
#[tokio::test]
async fn test_zookeeper_get_children() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start ZooKeeper server on port 0. The children of /services are web, api and db.",
    )
    .with_mock(|mock| {
        mock.on_event("zookeeper_request")
            .and_event_data_contains("operation", "getChildren")
            .and_event_data_contains("path", "/services")
            .respond_with_actions_from_event(|e| {
                serde_json::json!([
                    {
                        "type": "zookeeper_children",
                        "xid": e["xid"].as_i64().unwrap_or(0),
                        "zxid": 200,
                        "children": ["web", "api", "db"]
                    }
                ])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("ZooKeeper")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ZooKeeper",
                    "instruction": "Return service list"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let zk = ZooKeeper::connect(
        &format!("127.0.0.1:{}", server.port),
        SESSION_TIMEOUT,
        |_ev: WatchedEvent| {},
    )
    .await?;

    let children =
        tokio::time::timeout(Duration::from_secs(10), zk.get_children("/services", false))
            .await
            .map_err(|_| "timed out waiting for getChildren")??;

    assert_eq!(
        children,
        vec!["web".to_string(), "api".to_string(), "db".to_string()],
        "the client must decode the child list we encoded, in order"
    );

    zk.close().await?;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A real client sees a NONODE error as `ZkError::NoNode`.
///
/// LLM calls: 2 (server startup + getData)
#[tokio::test]
async fn test_zookeeper_error_response() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start ZooKeeper server on port 0. /nonexistent does not exist; return NONODE.",
    )
    .with_mock(|mock| {
        mock.on_event("zookeeper_request")
            .and_event_data_contains("operation", "getData")
            .and_event_data_contains("path", "/nonexistent")
            .respond_with_actions_from_event(|e| {
                serde_json::json!([
                    {
                        "type": "zookeeper_response",
                        "xid": e["xid"].as_i64().unwrap_or(0),
                        "zxid": 300,
                        "error_code": -101
                    }
                ])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("ZooKeeper")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ZooKeeper",
                    "instruction": "Return error for missing nodes"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let zk = ZooKeeper::connect(
        &format!("127.0.0.1:{}", server.port),
        SESSION_TIMEOUT,
        |_ev: WatchedEvent| {},
    )
    .await?;

    let result = tokio::time::timeout(Duration::from_secs(10), zk.get_data("/nonexistent", false))
        .await
        .map_err(|_| "timed out waiting for the NONODE reply")?;

    match result {
        Err(ZkError::NoNode) => {}
        Err(other) => panic!("expected ZkError::NoNode, got {:?}", other),
        Ok((data, _)) => panic!("expected ZkError::NoNode, got {} bytes of data", data.len()),
    }

    zk.close().await?;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
