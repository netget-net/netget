mod helpers;
use bytes::{Buf, BufMut, Bytes};
use helpers::gnmi_peer as peer;
use netget::server::gnmi::{codec::MAX_MESSAGE_BYTES, proto::gnmi as pb};
use prost::Message;
use serde_json::json;
use std::time::Duration;
use tonic::{
    codec::{Codec, CompressionEncoding, DecodeBuf, Decoder, EncodeBuf, Encoder},
    Status,
};
#[derive(Default)]
struct Raw;
struct Encode;
struct Decode;
impl Codec for Raw {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = Encode;
    type Decoder = Decode;
    fn encoder(&mut self) -> Encode {
        Encode
    }
    fn decoder(&mut self) -> Decode {
        Decode
    }
}
impl Encoder for Encode {
    type Item = Bytes;
    type Error = Status;
    fn encode(&mut self, item: Bytes, buf: &mut EncodeBuf<'_>) -> Result<(), Status> {
        buf.put_slice(&item);
        Ok(())
    }
}
impl Decoder for Decode {
    type Item = Bytes;
    type Error = Status;
    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        Ok(Some(buf.copy_to_bytes(buf.remaining())))
    }
}
async fn channel(port: u16) -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}
async fn call(
    port: u16,
    path: &'static str,
    bytes: Vec<u8>,
    gzip: bool,
    timeout: Option<Duration>,
) -> Result<Bytes, Status> {
    let mut client = tonic::client::Grpc::new(channel(port).await)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_encoding_message_size(MAX_MESSAGE_BYTES + 1024);
    if gzip {
        client = client.send_compressed(CompressionEncoding::Gzip);
    }
    client
        .ready()
        .await
        .map_err(|_| Status::unavailable("ready"))?;
    let mut request = tonic::Request::new(Bytes::from(bytes));
    if let Some(timeout) = timeout {
        request.set_timeout(timeout);
    }
    client
        .unary(request, http::uri::PathAndQuery::from_static(path), Raw)
        .await
        .map(|r| r.into_inner())
}
fn varint(mut value: usize) -> Vec<u8> {
    let mut output = vec![];
    while value > 127 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
    output
}
fn sized(size: usize) -> Vec<u8> {
    for n in size - 8..size {
        let mut bytes = varint(999 << 3 | 2);
        bytes.extend(varint(n));
        bytes.resize(bytes.len() + n, b'x');
        if bytes.len() == size {
            return bytes;
        }
    }
    panic!("size")
}
async fn intercepts(state: &netget::state::AppState, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.list_intercepts().await.len() == count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn exact_encoded_and_gzip_expanded_request_bound_plus_one() {
    let state = peer::state().await;
    let (id, port) = peer::server(&state, peer::handlers(), json!({}))
        .await
        .unwrap();
    for gzip in [false, true] {
        let reply = call(
            port,
            "/gnmi.gNMI/Capabilities",
            sized(MAX_MESSAGE_BYTES),
            gzip,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            pb::CapabilityResponse::decode(reply).unwrap().g_nmi_version,
            "0.10.0"
        );
        assert_eq!(
            call(
                port,
                "/gnmi.gNMI/Capabilities",
                sized(MAX_MESSAGE_BYTES + 1),
                gzip,
                None
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::ResourceExhausted
        );
    }
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn malformed_structural_and_opaque_inputs_are_refused_before_handler() {
    let state = peer::state().await;
    let (id, port) = peer::server(&state, peer::handlers(), json!({}))
        .await
        .unwrap();
    for (request, code) in [
        (vec![0], tonic::Code::InvalidArgument),
        (vec![10, 0], tonic::Code::Unimplemented),
    ] {
        assert_eq!(
            call(port, "/gnmi.gNMI/Capabilities", request, false, None)
                .await
                .unwrap_err()
                .code(),
            code
        );
    }
    let opaque = pb::SetRequest {
        update: vec![pb::Update {
            val: Some(pb::TypedValue {
                value: Some(pb::typed_value::Value::BytesVal(vec![1])),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        call(port, "/gnmi.gNMI/Set", opaque.encode_to_vec(), false, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
    let request = pb::GetRequest {
        path: vec![pb::Path::default(); 129],
        encoding: 2,
        ..Default::default()
    };
    assert_eq!(
        call(port, "/gnmi.gNMI/Get", request.encode_to_vec(), false, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert!(state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None
        )
        .await
        .is_empty());
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn trailers_only_errors_release_admission_on_one_live_connection() {
    let state = peer::state().await;
    let (id, port) = peer::server(
        &state,
        vec![peer::static_handler(
            "*",
            json!([{"type":"gnmi_error","code":7,"message":"denied: fixture"}]),
        )],
        json!({}),
    )
    .await
    .unwrap();
    let mut client = tonic::client::Grpc::new(channel(port).await);
    for _ in 0..70 {
        client.ready().await.unwrap();
        let error = client
            .unary(
                tonic::Request::new(Bytes::new()),
                http::uri::PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
                Raw,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(error.message(), "denied: fixture");
    }
    assert_eq!(state.get_server(id).await.unwrap().connections.len(), 1);
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn unary_extra_frames_and_duplicate_timeout_do_not_reach_model() {
    let state = peer::state().await;
    let (id, port) = peer::server(&state, peer::handlers(), json!({}))
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel(port).await);
    client.ready().await.unwrap();
    let error = client
        .client_streaming(
            tonic::Request::new(tokio_stream::iter([Bytes::new(), Bytes::new()])),
            http::uri::PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
            Raw,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    client.ready().await.unwrap();
    let mut request = tonic::Request::new(Bytes::new());
    request
        .metadata_mut()
        .append("grpc-timeout", "1S".parse().unwrap());
    request
        .metadata_mut()
        .append("grpc-timeout", "2S".parse().unwrap());
    assert_eq!(
        client
            .unary(
                request,
                http::uri::PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
                Raw
            )
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert!(state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None
        )
        .await
        .is_empty());
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn global_rpc_admission_cancellation_and_slot_recovery() {
    let state = peer::state().await;
    let (id, port) = peer::server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({}),
    )
    .await
    .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    let mut channels = vec![];
    for _ in 0..4 {
        let channel = channel(port).await;
        channels.push(channel.clone());
        for _ in 0..16 {
            let channel = channel.clone();
            tasks.spawn(async move {
                let mut client = tonic::client::Grpc::new(channel);
                client.ready().await.unwrap();
                client
                    .unary(
                        tonic::Request::new(Bytes::new()),
                        http::uri::PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
                        Raw,
                    )
                    .await
                    .map(|response| response.into_inner())
            });
        }
    }
    intercepts(&state, 64).await;
    assert_eq!(
        call(port, "/gnmi.gNMI/Capabilities", vec![], false, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    intercepts(&state, 0).await;
    tasks.spawn(async move { call(port, "/gnmi.gNMI/Capabilities", vec![], false, None).await });
    intercepts(&state, 1).await;
    state.remove_server(id).await.unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(3), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        stopped.is_err(),
        "server removal must terminate the admitted RPC"
    );
    intercepts(&state, 0).await;
    drop(channels);
}
#[tokio::test]
async fn whole_rpc_deadline_bounds_parked_handler_and_partial_message() {
    let state = peer::state().await;
    let (id, port) = peer::server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({"rpc_timeout_secs":1}),
    )
    .await
    .unwrap();
    let started = std::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        call(
            port,
            "/gnmi.gNMI/Capabilities",
            vec![],
            false,
            Some(Duration::from_millis(100)),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        error.code(),
        tonic::Code::DeadlineExceeded | tonic::Code::Cancelled | tonic::Code::Unknown
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    intercepts(&state, 0).await;
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, driver) = h2::client::handshake(socket).await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(driver);
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/gnmi.gNMI/Capabilities"))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let (response, mut input) = sender.send_request(request, false).unwrap();
    input
        .send_data(Bytes::from_static(&[0, 0, 0, 0, 5]), false)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        match response.await {
            Err(_) => {}
            Ok(response) => {
                let mut body = response.into_body();
                while let Some(data) = body.data().await {
                    if data.is_err() {
                        break;
                    }
                }
            }
        }
    })
    .await
    .unwrap();
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn zero_http2_receive_window_cannot_outlive_whole_response_deadline() {
    let state = peer::state().await;
    let mut notification = peer::notification(42);
    notification["update"][0]["value"] = json!({"kind":"string","value":"x".repeat(65536)});
    let (id, port) = peer::server(
        &state,
        vec![peer::static_handler(
            "gnmi_get_request",
            json!([{"type":"gnmi_get_response","notification":[notification]}]),
        )],
        json!({"rpc_timeout_secs":1}),
    )
    .await
    .unwrap();
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, driver) = h2::client::Builder::new()
        .initial_window_size(0)
        .handshake(socket)
        .await
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(driver);
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/gnmi.gNMI/Get"))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let (response, mut input) = sender.send_request(request, false).unwrap();
    let encoded = pb::GetRequest {
        encoding: 2,
        ..Default::default()
    }
    .encode_to_vec();
    let mut frame = vec![0];
    frame.extend((encoded.len() as u32).to_be_bytes());
    frame.extend(encoded);
    input.send_data(Bytes::from(frame), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert!(tokio::time::timeout(Duration::from_secs(3), body.data())
        .await
        .unwrap()
        .unwrap()
        .is_err());
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn actual_first_byte_and_idle_connection_bounds() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = peer::state().await;
    let (id, port) = peer::server(&state, peer::handlers(), json!({}))
        .await
        .unwrap();
    let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut idle = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    idle.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let first = async {
        let start = std::time::Instant::now();
        let mut bytes = vec![];
        tokio::time::timeout(Duration::from_secs(35), silent.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(29) && elapsed < Duration::from_secs(35));
        assert!(bytes.is_empty());
        println!("gNMI actual first-byte close: {elapsed:?}");
    };
    let between = async {
        let start = std::time::Instant::now();
        let mut bytes = vec![];
        tokio::time::timeout(
            Duration::from_secs(130),
            idle.take(65537).read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        let elapsed = start.elapsed();
        assert!(bytes.len() < 65537);
        assert!(elapsed >= Duration::from_secs(119) && elapsed < Duration::from_secs(130));
        println!("gNMI actual idle close: {elapsed:?}; watchdog resolution 6s");
    };
    tokio::join!(first, between);
    state.remove_server(id).await.unwrap();
}
#[tokio::test]
async fn tcp_connection_cap_refuses_257th_and_releases_closed_peers() {
    use tokio::io::AsyncReadExt;
    let state = peer::state().await;
    let (id, port) = peer::server(&state, peer::handlers(), json!({}))
        .await
        .unwrap();
    let mut sockets = vec![];
    for _ in 0..256 {
        sockets.push(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap(),
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.get_server(id).await.unwrap().connections.len() == 256 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let refused = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut bytes = vec![];
    tokio::time::timeout(
        Duration::from_secs(3),
        refused.take(4097).read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(bytes.len() < 4097);
    drop(sockets);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.get_server(id).await.unwrap().connections.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let recovered = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    drop(recovered);
    state.remove_server(id).await.unwrap();
}
