use netget::cli::management::ServerForm;
use netget::state::{app_state::AppState, AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
pub(super) async fn start(
    handlers: Option<Vec<Value>>,
    params: Option<Value>,
) -> (AppState, ServerId, SocketAddr) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "influxdb".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some("Default collection must not call the model".into()),
        event_handlers: handlers,
        startup_params: params,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, addr)
}
pub(super) async fn request(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &str,
    body: &[u8],
) -> (u16, Value, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{headers}\r\n",body.len()).as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let wire = String::from_utf8(bytes).unwrap();
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap()
    };
    (status, value, head.into())
}
pub(super) async fn logs(
    state: &AppState,
    id: ServerId,
    count: usize,
) -> Vec<netget::state::app_state::AccessLogEntry> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let entries = state
                .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
                .await;
            if entries.len() >= count {
                break entries;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
pub(super) const TARGET: &str = "/api/v2/write?org=example&bucket=metrics&precision=ns";

#[tokio::test]
async fn explicitly_opted_in_write_reaches_standard_model_dispatcher(
) -> crate::server::helpers::E2EResult<()> {
    use crate::server::helpers::{start_netget_server, NetGetConfig};
    let config=NetGetConfig::new("listen on port {AVAILABLE_PORT} via influxdb. Review writes.").with_mock(|mock| {
        mock.on_instruction_containing("via influxdb").respond_with_actions(json!([{"type":"open_server","base_stack":"influxdb","port":0,"instruction":"Review writes","startup_params":{"llm_fallback":true}}])).expect_calls(1).and()
        .on_event("influx_write").respond_with_actions_from_event(|event|{assert_eq!(event["points"][0]["measurement"],"model");assert_eq!(event["points"][0]["fields"]["f"]["type"],"integer");json!([{"type":"accept_influx_points"}])}).expect_calls(1).and()
    });
    let server = start_netget_server(config).await?;
    assert_eq!(
        request(
            (
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
                server.port
            )
                .into(),
            "POST",
            TARGET,
            "",
            b"model f=42i"
        )
        .await
        .0,
        204
    );
    server.wait_for_mocks(20).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn native_pair_followups_refresh_common_memory_and_stop_at_depth_bound() {
    let (state, server, addr) = start(None, None).await;
    let (tx, _) = mpsc::unbounded_channel();
    let batch = serde_json::to_value(super::codec_test::batch("ns", false)).unwrap();
    let code=format!("import json,sys\nx=json.load(sys.stdin)\nn=int(x['client']['memory'] or '0')+1\nassert x['event']['status']==204\nprint(json.dumps({{'actions':[{{'type':'set_memory','value':str(n)}},{{'type':'write_influx_points','batch':json.loads({})}}]}}))",serde_json::to_string(&batch.to_string()).unwrap());
    let client=netget::cli::management::ClientForm {protocol:"influxdb".into(),remote_addr:Some(addr.to_string()),instruction:Some(String::new()),event_handlers:Some(vec![json!({"event_pattern":"influx_connected","handler":{"type":"static","actions":[{"type":"write_influx_points","batch":batch}]}}),json!({"event_pattern":"influx_write_response","handler":{"type":"script","language":"python","code":code}})]),..Default::default()}.create(&state,netget::llm::OllamaClient::new("http://127.0.0.1:1"),tx).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while state.get_client(client).await.unwrap().memory != "8" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(logs(&state, server, 8).await.len(), 8);
    assert_eq!(state.get_client_llm_calls(client).await, 0);
    state.remove_client(client).await;
    state.remove_server(server).await;
    assert!(state.list_intercepts().await.is_empty());
}

#[tokio::test]
async fn connection_cap_refuses_and_malformed_peer_releases_slot() {
    let (state, id, addr) = start(None, None).await;
    let mut peers = Vec::new();
    for _ in 0..netget::server::accept_bounded::DEFAULT_MAX_CONNECTIONS {
        let mut p = TcpStream::connect(addr).await.unwrap();
        p.write_all(b"POST ").await.unwrap();
        peers.push(p);
    }
    let mut refused = TcpStream::connect(addr).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), refused.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 503"));
    let mut malformed = peers.pop().unwrap();
    let _ = malformed
        .write_all(b"/ HTTP/1.1\r\nMalformed\r\n\r\n")
        .await;
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), malformed.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert_eq!(request(addr, "POST", TARGET, "", b"m f=1i").await.0, 204);
    state.remove_server(id).await;
    for mut p in peers {
        let closed = tokio::time::timeout(Duration::from_secs(5), p.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0)) || closed.is_err());
    }
}
#[tokio::test]
async fn typed_collection_partial_syntax_gzip_and_default_model_suppression() {
    let (state, id, addr) = start(None, None).await;
    let b = super::codec_test::batch("ms", true);
    let body = netget::server::influxdb::codec::encode_batch(&b).unwrap();
    assert_eq!(
        request(
            addr,
            "POST",
            "/api/v2/write?org=org%20%E5%90%8D%20%26&bucket=bucket%20%2F%20%26&precision=ms",
            "Content-Type: text/plain; charset=utf-8\r\nContent-Encoding: gzip\r\n",
            &body
        )
        .await
        .0,
        204
    );
    let entries = logs(&state, id, 1).await;
    assert_eq!(entries[0].request["org"], b.org);
    assert_eq!(entries[0].request["points"][0]["timestamp_ns"], 123_000_000);
    assert_eq!(
        entries[0].request["points"][0]["fields"]["uint"]["value"],
        u64::MAX
    );
    assert_eq!(
        entries[0].request["points"][0]["fields"]["str =,"]["value"],
        serde_json::to_value(&b.points[0].fields["str =,"]).unwrap()["value"]
    );
    let (status, value, _) = request(addr, "POST", TARGET, "", b"m f=1i\nbad\nm f=2i\n").await;
    assert_eq!(status, 400);
    assert_eq!(value["accepted_points"], 2);
    assert_eq!(value["rejected_points"], 1);
    assert_eq!(value["line"], 2);
    state.remove_server(id).await;
}
#[tokio::test]
async fn token_check_route_query_and_header_errors_never_reach_handlers_or_leak_credentials() {
    let (state, id, addr) = start(None, Some(json!({"auth_token":"top-secret"}))).await;
    for h in [
        "",
        "Authorization: Token wrong\r\n",
        "Authorization: Token top-secret\r\nAuthorization: Token top-secret\r\n",
    ] {
        assert_eq!(request(addr, "POST", TARGET, h, b"m f=1i").await.0, 401);
    }
    for scheme in ["Token", "Bearer"] {
        assert_eq!(
            request(
                addr,
                "POST",
                TARGET,
                &format!("Authorization: {scheme} top-secret\r\n"),
                b"m f=1i"
            )
            .await
            .0,
            204
        );
    }
    for (method, target, extra, want) in [
        ("GET", TARGET, "", 405),
        ("POST", "/write", "", 404),
        ("POST", "/api/v2/write?org=x&org=y&bucket=z", "", 400),
        ("POST", "/api/v2/write?orgID=x&bucket=z", "", 400),
        ("POST", "/api/v2/write?org=x&bucket=z&precision=m", "", 400),
        ("POST", "/api/v2/write?org=%GG&bucket=z", "", 400),
        ("POST", TARGET, "Content-Type: application/json\r\n", 415),
        ("POST", TARGET, "Content-Encoding: br\r\n", 415),
        (
            "POST",
            TARGET,
            "Content-Encoding: gzip\r\nContent-Encoding: identity\r\n",
            400,
        ),
    ] {
        assert_eq!(
            request(
                addr,
                method,
                target,
                &format!("Authorization: Token top-secret\r\n{extra}"),
                b"m f=1i"
            )
            .await
            .0,
            want
        );
    }
    let entries = logs(&state, id, 2).await;
    assert_eq!(entries.len(), 2);
    for e in entries {
        assert!(!e.request.to_string().contains("top-secret"));
        assert!(e.request["authenticated"].as_bool().unwrap());
        assert!(e.request["auth_required"].as_bool().unwrap());
    }
    state.remove_server(id).await;
}
#[tokio::test]
async fn explicit_partial_reject_and_invalid_decisions_obey_http_contract() {
    for (action, want) in [
        (
            json!({"type":"accept_influx_subset","accepted_lines":[1],"message":"Type conflict"}),
            400,
        ),
        (
            json!({"type":"reject_influx_points","status":429,"message":"Rate limit","retry_after_seconds":3}),
            429,
        ),
        (
            json!({"type":"accept_influx_subset","accepted_lines":[3],"message":"Invalid"}),
            503,
        ),
    ] {
        let(state,id,addr)=start(Some(vec![json!({"event_pattern":"influx_write","handler":{"type":"static","actions":[action]}})]),None).await;
        let (status, value, head) = request(addr, "POST", TARGET, "", b"m f=1i\nm f=2i").await;
        assert_eq!(status, want);
        if want == 400 {
            assert_eq!(value["accepted_points"], 1);
            assert_eq!(value["rejected_points"], 1);
            assert_eq!(value["line"], 2);
        }
        if want == 429 {
            assert!(head.to_ascii_lowercase().contains("retry-after: 3"));
            assert_eq!(value["accepted_points"], 0);
        }
        state.remove_server(id).await;
    }
}
#[tokio::test]
async fn failed_action_alongside_accept_fails_closed_and_script_memory_refreshes() {
    let script="import json,sys\nx=json.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'accept_influx_points'},{'type':'unknown_influx_action'}]}))";
    let(state,id,addr)=start(Some(vec![json!({"event_pattern":"influx_write","handler":{"type":"script","language":"python","code":script}})]),None).await;
    assert_eq!(request(addr, "POST", TARGET, "", b"m f=1i").await.0, 503);
    assert!(logs(&state, id, 1)
        .await
        .iter()
        .any(|e| e.event_type == "influx_handler_failed"));
    state.remove_server(id).await;
    let script="import json,sys\nx=json.load(sys.stdin)\nm=x['event']['points'][0]['measurement']\nassert x['server']['memory']==('' if m=='first' else 'first')\nprint(json.dumps({'actions':[{'type':'set_memory','value':m},{'type':'accept_influx_points'}]}))";
    let(state,id,addr)=start(Some(vec![json!({"event_pattern":"influx_write","handler":{"type":"script","language":"python","code":script}})]),None).await;
    for m in ["first", "second"] {
        assert_eq!(
            request(addr, "POST", TARGET, "", format!("{m} f=1i").as_bytes())
                .await
                .0,
            204
        );
    }
    assert_eq!(state.get_memory(id).await.unwrap(), "second");
    state.remove_server(id).await;
}
#[tokio::test]
async fn server_stop_cancels_parked_handler_socket_intercept_and_listener() {
    let (state, id, addr) = start(
        Some(vec![
            json!({"event_pattern":"influx_write","handler":{"type":"manual","timeout_secs":300}}),
        ]),
        None,
    )
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("POST {TARGET} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nm f=1i")
                .as_bytes(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.list_intercepts().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), stream.read(&mut [0; 1]))
            .await
            .is_err()
    );
    assert!(!state.list_intercepts().await.is_empty());
    state.remove_server(id).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    assert!(state.list_intercepts().await.is_empty());
    assert!(TcpStream::connect(addr).await.is_err());
}
#[tokio::test]
async fn body_and_gzip_limits_reject_without_dispatch() {
    let (state, id, addr) = start(None, None).await;
    assert_eq!(
        request(
            addr,
            "POST",
            TARGET,
            "",
            &vec![b'x'; netget::server::influxdb::codec::MAX_BODY_BYTES + 1]
        )
        .await
        .0,
        413
    );
    use std::io::Write;
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&vec![
        b'x';
        netget::server::influxdb::codec::MAX_BODY_BYTES + 1
    ])
    .unwrap();
    assert_eq!(
        request(
            addr,
            "POST",
            TARGET,
            "Content-Encoding: gzip\r\n",
            &z.finish().unwrap()
        )
        .await
        .0,
        413
    );
    assert_eq!(
        request(
            addr,
            "POST",
            TARGET,
            "Content-Encoding: gzip\r\n",
            b"not gzip"
        )
        .await
        .0,
        400
    );
    assert!(state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .is_empty());
    state.remove_server(id).await;
}
#[tokio::test]
async fn absolute_header_deadline_closes_slow_connection() {
    deadline_case(true).await;
}
#[tokio::test]
async fn absolute_body_deadline_returns_408_before_closing() {
    deadline_case(false).await;
}
async fn deadline_case(header: bool) {
    // Separate runtimes avoid reusing Tokio's advanced test clock with Hyper's
    // std::Instant-based header timer on the next connection.
    let (state, id, addr) = start(None, None).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let prefix = if header {
        "POST /api/v2/write HTTP/1.1\r\nHost: "
    } else {
        "POST /api/v2/write?org=x&bucket=z HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx"
    };
    stream.write_all(prefix.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    if !header {
        assert!(
            String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 408"),
            "body deadline wire: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
    assert!(state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .is_empty());
    state.remove_server(id).await;
}
