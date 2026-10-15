use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use netget::server::connect_rpc::wire::{self, Shape};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tonic::{body::BoxBody, Code, Status};
fn chunks(chunks: Vec<Bytes>) -> BoxBody {
    StreamBody::new(futures::stream::iter(
        chunks
            .into_iter()
            .map(|bytes| Ok::<_, Status>(Frame::data(bytes))),
    ))
    .boxed_unsync()
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
async fn decode(data: Bytes, gzip: bool) -> Result<(usize, HeaderMap, bool), Status> {
    let complete = Arc::new(AtomicBool::new(false));
    let mut body = wire::client_stream_body(
        chunks(
            data.iter()
                .map(|byte| Bytes::copy_from_slice(&[*byte]))
                .collect(),
        ),
        gzip,
        complete.clone(),
    );
    let mut messages = 0;
    let mut trailers = HeaderMap::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if frame.is_data() {
            messages += 1;
        } else {
            trailers = frame.into_trailers().unwrap();
        }
    }
    Ok((messages, trailers, complete.load(Ordering::Relaxed)))
}
#[tokio::test]
async fn arbitrary_splits_final_endstream_and_ascii_metadata() {
    let data = [
        wire::frame(0, b"protobuf"),
        wire::frame(2, br#"{"metadata":{"X-Note":["contains:colon","second"]}}"#),
    ]
    .concat();
    let (count, headers, complete) = decode(data.into(), false).await.unwrap();
    assert_eq!(count, 1);
    assert_eq!(headers.get_all("x-note").iter().count(), 2);
    assert_eq!(headers["grpc-status"], "0");
    assert!(complete);
    let (_, headers, _) = decode(
        wire::frame(
            2,
            br#"{"error":{"code":"permission_denied","message":"denied: reason"}}"#,
        ),
        false,
    )
    .await
    .unwrap();
    assert_eq!(headers["grpc-status"], "7");
    assert_eq!(
        Status::from_header_map(&headers).unwrap().message(),
        "denied: reason"
    );
}
#[tokio::test]
async fn final_envelope_is_mandatory_valid_unique_and_last() {
    let good = wire::frame(2, b"{}");
    for data in [
        Bytes::new(),
        wire::frame(0, b"x"),
        Bytes::from_static(&[2, 0, 0, 0, 3, b'{']),
        wire::frame(128, b"{}"),
        wire::frame(2, br#"{"error":null}"#),
        wire::frame(2, br#"{"error":{}}"#),
        wire::frame(2, br#"{"error":{"code":"ok"}}"#),
        wire::frame(2, br#"{"error":{"code":"unknown","code":"internal"}}"#),
        wire::frame(2, br#"{"metadata":{"x":["a"],"X":["b"]}}"#),
        wire::frame(2, br#"{"metadata":{"x-bin":["Ym9keQ"]}}"#),
        [good.clone(), Bytes::from_static(b"x")].concat().into(),
        [good.clone(), good.clone()].concat().into(),
    ] {
        assert!(decode(data, false).await.is_err());
    }
    let body = StreamBody::new(futures::stream::iter([Ok::<_, Status>(
        Frame::<Bytes>::trailers(HeaderMap::new()),
    )]))
    .boxed_unsync();
    assert!(
        wire::client_stream_body(body, false, Arc::new(AtomicBool::new(false)))
            .frame()
            .await
            .unwrap()
            .is_err()
    );
}
#[tokio::test]
async fn prefixes_bound_before_payload_and_message_count_exact_plus_one() {
    for (flag, length) in [
        (0, wire::MAX_MESSAGE_BYTES + 1),
        (1, wire::MAX_MESSAGE_BYTES + 1),
        (2, wire::MAX_END_BYTES + 1),
        (3, wire::MAX_END_BYTES + 1),
    ] {
        let mut prefix = vec![flag];
        prefix.extend((length as u32).to_be_bytes());
        assert_eq!(
            decode(prefix.into(), true).await.unwrap_err().code(),
            Code::ResourceExhausted
        );
    }
    for (count, success) in [(256, true), (257, false)] {
        let mut data = Vec::new();
        for _ in 0..count {
            data.extend(wire::frame(0, b""));
        }
        data.extend(wire::frame(2, b"{}"));
        let result = decode(data.into(), false).await;
        if success {
            assert_eq!(result.unwrap().0, 256);
        } else {
            assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
        }
    }
}
#[test]
fn requests_plain_and_gzip_exact_plus_one_and_shape_flags() {
    let exact = vec![0; wire::MAX_MESSAGE_BYTES];
    assert_eq!(
        wire::unary_request(&exact, false).unwrap().len(),
        wire::MAX_MESSAGE_BYTES + 5
    );
    assert_eq!(
        wire::unary_request(&vec![0; wire::MAX_MESSAGE_BYTES + 1], false)
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        wire::unary_request(&gzip(&exact), true).unwrap().len(),
        wire::MAX_MESSAGE_BYTES + 5
    );
    assert_eq!(
        wire::unary_request(&gzip(&vec![0; wire::MAX_MESSAGE_BYTES + 1]), true)
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert!(wire::streaming_request(&wire::frame(1, &gzip(b"protobuf")), true).is_ok());
    for bytes in [
        wire::frame(1, &gzip(b"x")),
        wire::frame(2, b"{}"),
        [wire::frame(0, b"x"), wire::frame(0, b"y")].concat().into(),
        Bytes::from_static(&[0, 0, 0, 0, 1]),
    ] {
        assert!(wire::streaming_request(&bytes, false).is_err());
    }
    let mut corrupt = gzip(b"x");
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(wire::inflate(&corrupt, 1024).is_err());
}
#[tokio::test]
async fn gzip_endstream_integrity_negotiation_and_expansion_bound() {
    let compressed = wire::frame(3, &gzip(b"{}"));
    assert!(decode(compressed.clone(), false).await.is_err());
    assert!(decode(compressed, true).await.is_ok());
    let mut padded = b"{}".to_vec();
    padded.resize(wire::MAX_END_BYTES, b' ');
    assert!(decode(wire::frame(3, &gzip(&padded)), true).await.is_ok());
    padded.push(b' ');
    assert_eq!(
        decode(wire::frame(3, &gzip(&padded)), true)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    let mut bad = gzip(b"{}");
    *bad.last_mut().unwrap() ^= 1;
    assert!(decode(wire::frame(3, &bad), true).await.is_err());
}
#[test]
fn metadata_limits_and_response_header_sealing_are_real() {
    let exact = json!({"a":"x".repeat(1023),"b":"x".repeat(1023),"c":"x".repeat(1023),"d":"x".repeat(1023),"e":"x".repeat(1023),"f":"x".repeat(1023),"g":"x".repeat(1023),"h":"x".repeat(1023)});
    assert!(wire::Metadata::from_action(&exact).is_ok());
    let mut over = exact;
    over["a"] = json!("x".repeat(1024));
    assert!(wire::Metadata::from_action(&over).is_err());
    for value in [
        json!({"connect-timeout-ms":"1"}),
        json!({"x-bin":"YWJj"}),
        json!({"x":"line\nbreak"}),
        json!({"x":"x".repeat(1025)}),
        json!({"x".repeat(129):"value"}),
    ] {
        assert!(wire::Metadata::from_action(&value).is_err());
    }
    let metadata = wire::RpcMetadata::new(&HeaderMap::new()).unwrap();
    metadata
        .apply(&json!({"phase":"headers","metadata":{"x-note":"a"}}))
        .unwrap();
    metadata.response.lock().unwrap().sealed = true;
    assert!(metadata
        .apply(&json!({"phase":"headers","metadata":{"x-note":"b"}}))
        .is_err());
    metadata
        .apply(&json!({"phase":"trailers","metadata":{"x-note":"b"}}))
        .unwrap();
}
#[test]
fn protocol_timeout_uniqueness_bounds_and_all_error_statuses() {
    let mut headers = HeaderMap::new();
    for value in ["0", "-1", "1.0", "10000000000", ""] {
        headers.insert("connect-timeout-ms", HeaderValue::from_str(value).unwrap());
        assert!(wire::timeout_ms(&headers).is_err());
    }
    headers.insert("connect-timeout-ms", HeaderValue::from_static("9999999999"));
    assert_eq!(wire::timeout_ms(&headers).unwrap(), Some(9999999999));
    headers.append("connect-timeout-ms", HeaderValue::from_static("1"));
    assert!(wire::timeout_ms(&headers).is_err());
    for code in 1..=16 {
        let status = Status::new(Code::from_i32(code), "reason");
        let response = wire::failure(status, Shape::Unary, false);
        assert_eq!(response.status(), wire::http_status(Code::from_i32(code)));
        assert_eq!(response.headers()["content-type"], "application/json");
    }
    assert_eq!(
        wire::inferred_code(StatusCode::TOO_MANY_REQUESTS),
        Code::Unavailable
    );
}
#[tokio::test]
async fn unary_response_is_bare_status_is_http_and_prefixed_trailers_survive() {
    let mut trailers = HeaderMap::new();
    Status::ok("").add_header(&mut trailers).unwrap();
    let native = StreamBody::new(futures::stream::iter([
        Ok::<_, Status>(Frame::data(wire::frame(0, b"proto"))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed_unsync();
    let md = wire::RpcMetadata::new(&HeaderMap::new()).unwrap();
    md.apply(&json!({"phase":"headers","metadata":{"x-leading":"before"}}))
        .unwrap();
    md.apply(&json!({"phase":"trailers","metadata":{"x-note":"after"}}))
        .unwrap();
    let response = wire::server_response(Response::new(native), Shape::Unary, md)
        .await
        .unwrap();
    assert_eq!(response.headers()["x-leading"], "before");
    assert_eq!(response.headers()["trailer-x-note"], "after");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "proto"
    );
    let complete = Arc::new(AtomicBool::new(false));
    let mut response = Response::new(wire::body(Bytes::from_static(
        br#"{"code":"permission_denied","message":"denied: reason"}"#,
    )));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    let response = wire::client_response(response, Shape::Unary, complete.clone())
        .await
        .unwrap();
    assert_eq!(
        Status::from_header_map(response.headers()).unwrap().code(),
        Code::PermissionDenied
    );
    assert!(complete.load(Ordering::Relaxed));
}
