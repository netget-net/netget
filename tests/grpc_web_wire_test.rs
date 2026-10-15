#[test]
fn initial_http_header_count_and_aggregate_exact_plus_one() {
    let mut headers = http::HeaderMap::new();
    for index in 0..64 {
        headers.insert(
            http::HeaderName::from_bytes(format!("x{index}").as_bytes()).unwrap(),
            http::HeaderValue::from_static(""),
        );
    }
    assert!(netget::server::grpc_web::wire::bounded_headers(&headers));
    headers.insert("extra", http::HeaderValue::from_static(""));
    assert!(!netget::server::grpc_web::wire::bounded_headers(&headers));
    headers.clear();
    headers.insert(
        "a",
        http::HeaderValue::from_str(&"x".repeat(32768 - 5)).unwrap(),
    );
    assert!(netget::server::grpc_web::wire::bounded_headers(&headers));
    headers.insert(
        "a",
        http::HeaderValue::from_str(&"x".repeat(32768 - 4)).unwrap(),
    );
    assert!(!netget::server::grpc_web::wire::bounded_headers(&headers));
}

#[tokio::test]
async fn admission_survives_last_status_frame_until_eof_and_releases_on_drop() {
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let mut headers = http::HeaderMap::new();
    headers.insert("grpc-status", http::HeaderValue::from_static("7"));
    let status = StreamBody::new(futures::stream::iter([Ok::<_, tonic::Status>(Frame::<
        Bytes,
    >::trailers(
        headers
    ))]))
    .boxed_unsync();
    let mut held = wire::hold_body(status, permits.clone().try_acquire_owned().unwrap());
    assert_eq!(permits.available_permits(), 0);
    assert!(held.frame().await.unwrap().unwrap().is_trailers());
    assert!(!hyper::body::Body::is_end_stream(&held));
    assert_eq!(
        permits.available_permits(),
        0,
        "the last-frame hint must not release admission"
    );
    assert!(held.frame().await.is_none());
    assert_eq!(permits.available_permits(), 1);
    let held = wire::hold_body(
        body(vec![vec![0; 5]]),
        permits.clone().try_acquire_owned().unwrap(),
    );
    assert_eq!(permits.available_permits(), 0);
    drop(held);
    assert_eq!(permits.available_permits(), 1);
}
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use netget::server::grpc_web::wire;
fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![flag];
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(payload);
    result
}
fn body(chunks: Vec<Vec<u8>>) -> tonic::body::BoxBody {
    StreamBody::new(futures::stream::iter(
        chunks
            .into_iter()
            .map(|chunk| Ok::<_, tonic::Status>(Frame::data(Bytes::from(chunk)))),
    ))
    .boxed_unsync()
}
async fn decode(chunks: Vec<Vec<u8>>) -> Result<(usize, hyper::HeaderMap), tonic::Status> {
    let mut body = wire::response_body(body(chunks));
    let mut count = 0;
    let mut trailers = hyper::HeaderMap::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if frame.is_data() {
            count += 1;
        } else {
            trailers = frame.into_trailers().unwrap();
        }
    }
    Ok((count, trailers))
}
#[tokio::test]
async fn binary_frames_arbitrary_splits_preserve_colons_and_final_status() {
    let mut data = frame(0, b"protobuf");
    data.extend(frame(
        128,
        b"grpc-status:0\r\ngrpc-message:hello:world%20ok\r\nx-note:contains:colon\r\n",
    ));
    let (count, headers) = decode(data.into_iter().map(|byte| vec![byte]).collect())
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(headers["grpc-message"], "hello:world%20ok");
    assert_eq!(headers["x-note"], "contains:colon");
    assert_eq!(wire::status(&headers).unwrap(), 0);
    let (_, headers) = decode(vec![frame(
        128,
        b"grpc-status:7\r\ngrpc-message:denied:reason",
    )])
    .await
    .unwrap();
    assert_eq!(headers["grpc-status"], "7");
    assert_eq!(headers["grpc-message"], "denied:reason");
}
#[tokio::test]
async fn response_prefix_limits_exact_and_plus_one_before_payload() {
    let mut data = frame(0, &vec![0; wire::MAX_MESSAGE_BYTES]);
    data.extend(frame(128, b"grpc-status:0\r\n"));
    assert_eq!(decode(vec![data]).await.unwrap().0, 1);
    for (flag, length) in [
        (0, wire::MAX_MESSAGE_BYTES + 1),
        (1, wire::MAX_MESSAGE_BYTES + 1),
        (128, wire::MAX_TRAILER_BYTES + 1),
    ] {
        let mut prefix = vec![flag];
        prefix.extend((length as u32).to_be_bytes());
        assert_eq!(
            decode(vec![prefix]).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }
}
#[tokio::test]
async fn final_trailer_is_complete_unique_and_last() {
    let good = frame(128, b"grpc-status:0\r\n");
    for data in [
        vec![],
        frame(0, b"x"),
        vec![128, 0, 0, 0, 15, b'g'],
        frame(128, b"x-note:status absent\r\n"),
        frame(128, b"grpc-status:0\r\ngrpc-status:7\r\n"),
        frame(129, b"grpc-status:0\r\n"),
        [good.clone(), vec![0]].concat(),
        [good.clone(), good.clone()].concat(),
        frame(2, b"x"),
    ] {
        assert!(decode(vec![data]).await.is_err());
    }
    for trailer in [
        b"Grpc-Status:0\r\n".as_slice(),
        b"grpc-status:17\r\n",
        b"grpc-status:0\r\nconnection:close\r\n",
        b"grpc-status:0\r\ngrpc-message:bad\nline\r\n",
        b"grpc-status:0\r\n\r\n",
    ] {
        assert!(wire::trailers(trailer).is_err());
    }
    assert_eq!(decode(vec![good]).await.unwrap().0, 0);
}
#[test]
fn trailer_byte_and_field_limits_accept_boundary() {
    let mut payload = b"grpc-status:0\r\n".to_vec();
    for i in 0..3 {
        payload.extend(format!("x-{i}:{}\r\n", "x".repeat(4096)).as_bytes());
    }
    let remaining = wire::MAX_TRAILER_BYTES - payload.len() - 8;
    payload.extend(format!("x-end:{}\r\n", "x".repeat(remaining)).as_bytes());
    assert_eq!(payload.len(), wire::MAX_TRAILER_BYTES);
    wire::trailers(&payload).unwrap();
    payload.push(b'x');
    assert_eq!(
        wire::trailers(&payload).unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    let mut payload = b"grpc-status:0\r\n".to_vec();
    for i in 1..wire::MAX_TRAILER_FIELDS {
        payload.extend(format!("x-{i}:v\r\n").as_bytes());
    }
    assert_eq!(wire::trailers(&payload).unwrap().len(), 32);
    payload.extend(b"x-extra:v\r\n");
    assert_eq!(
        wire::trailers(&payload).unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
}
#[tokio::test]
async fn response_count_bound_and_http_trailers_rejected() {
    let mut data = Vec::new();
    for _ in 0..wire::MAX_MESSAGES {
        data.extend(frame(0, b""));
    }
    assert_eq!(
        decode(vec![
            [data.clone(), frame(128, b"grpc-status:0\r\n")].concat()
        ])
        .await
        .unwrap()
        .0,
        256
    );
    data.extend(frame(0, b""));
    assert_eq!(
        decode(vec![data]).await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    let mut headers = hyper::HeaderMap::new();
    headers.insert("grpc-status", "0".parse().unwrap());
    let body = StreamBody::new(futures::stream::iter([Ok::<_, tonic::Status>(Frame::<
        Bytes,
    >::trailers(
        headers
    ))]))
    .boxed_unsync();
    assert!(wire::response_body(body).frame().await.unwrap().is_err());
}
#[tokio::test]
async fn compressed_trailers_follow_negotiation_and_bound_expansion() {
    use std::io::Write;
    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }
    let payload = b"grpc-status:7\r\ngrpc-message:denied:reason\r\n";
    let encoded = frame(129, &gzip(payload));
    let result = wire::response_body_with_gzip(body(vec![encoded.clone()]), true)
        .collect()
        .await
        .unwrap();
    assert_eq!(result.trailers().unwrap()["grpc-status"], "7");
    assert_eq!(result.trailers().unwrap()["grpc-message"], "denied:reason");
    assert!(wire::response_body_with_gzip(body(vec![encoded]), false)
        .collect()
        .await
        .is_err());
    let oversized = frame(129, &gzip(&vec![b'x'; wire::MAX_TRAILER_BYTES + 1]));
    assert_eq!(
        wire::response_body_with_gzip(body(vec![oversized]), true)
            .collect()
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    let mut broken = gzip(payload);
    broken.pop();
    assert!(
        wire::response_body_with_gzip(body(vec![frame(129, &broken)]), true)
            .collect()
            .await
            .is_err()
    );
}
