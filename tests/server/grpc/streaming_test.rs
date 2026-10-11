use crate::helpers::grpc_peer as peer;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn independent_grpcio_all_stream_shapes_and_gzip() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(&state, vec![peer::semantic_handler()], json!({}))
        .await
        .unwrap();
    assert_eq!(
        peer::client(port, "streaming").await.unwrap(),
        json!({"watch":3,"collected":5,"chat":2})
    );
    let logs = state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None,
        )
        .await;
    assert!(logs.iter().any(|log| log.event_type == "grpc_stream_opened"
        && log.request["message"]["tags"] == json!(["blue", "green"])));
    let collect: Vec<_> = logs
        .iter()
        .filter(|log| log.event_type == "grpc_stream_message" && log.request["method"] == "Collect")
        .collect();
    assert_eq!(collect.len(), 2);
    assert!(collect
        .iter()
        .any(|log| log.request["message"]["value"] == 2));
    assert!(collect
        .iter()
        .any(|log| log.request["message"]["value"] == 3));
    state.remove_server(id).await.unwrap();
}

#[tokio::test]
async fn independent_reflection_grpcio_and_grpcurl_without_schema() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(&state, vec![peer::semantic_handler()], json!({}))
        .await
        .unwrap();
    assert_eq!(
        peer::client(port, "reflection").await.unwrap(),
        json!({"queries":4,"unknown_code":5})
    );
    for (suffix, needle) in [
        (vec!["list"], "streams.Session"),
        (vec!["describe", "streams.Session"], "rpc Watch"),
        (
            vec!["-d", r#"{"name":"watch"}"#, "streams.Session/Watch"],
            "watch-2",
        ),
    ] {
        let mut args = vec!["-plaintext".to_owned()];
        // grpcurl flags precede the endpoint; method/list/describe follow it.
        if suffix.first() == Some(&"-d") {
            args.extend(suffix[..2].iter().map(|value| value.to_string()));
        }
        args.push(format!("127.0.0.1:{port}"));
        args.extend(
            suffix[if suffix.first() == Some(&"-d") { 2 } else { 0 }..]
                .iter()
                .map(|value| value.to_string()),
        );
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("grpcurl")
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .expect("grpcurl is mandatory; install grpcurl 1.9.4");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(needle),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    state.remove_server(id).await.unwrap();
}

async fn channel(port: u16) -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}
async fn intercepts(state: &netget::state::AppState, count: usize) {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        while state.list_intercepts().await.len() != count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "expected {count} intercepts, got {}",
        state.list_intercepts().await.len()
    );
}

#[tokio::test]
async fn cancelled_stream_and_server_removal_release_parked_handlers() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({}),
    )
    .await
    .unwrap();
    let pool = peer::pool().unwrap();
    let descriptor = pool.get_message_by_name("streams.Message").unwrap();
    let codec = netget::server::grpc::stream_codec::DynamicCodec {
        encode: descriptor.clone(),
        decode: descriptor.clone(),
    };
    let channel = channel(port).await;
    // Tonic waits for the handler to open the response, so cancellation here must
    // remove the manual intercept and release admission before response headers.
    for stop_server in [false, true] {
        let channel = channel.clone();
        let codec = codec.clone();
        let message = prost_reflect::DynamicMessage::new(descriptor.clone());
        let mut task = tokio::task::JoinSet::new();
        task.spawn(async move {
            let mut client = tonic::client::Grpc::new(channel);
            client.ready().await.unwrap();
            client
                .server_streaming(
                    tonic::Request::new(message),
                    http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
                    codec,
                )
                .await
        });
        intercepts(&state, 1).await;
        if stop_server {
            state.remove_server(id).await.unwrap();
            let response = tokio::time::timeout(Duration::from_secs(3), task.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Ok(response) = response {
                assert!(response.into_inner().message().await.is_err());
            }
        } else {
            task.abort_all();
            while task.join_next().await.is_some() {}
        }
        intercepts(&state, 0).await;
    }
}

#[tokio::test]
async fn streaming_deadline_covers_parked_model_and_unclosed_input() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({"stream_timeout_secs":1}),
    )
    .await
    .unwrap();
    let descriptor = peer::pool()
        .unwrap()
        .get_message_by_name("streams.Message")
        .unwrap();
    for unclosed in [false, true] {
        let mut client = tonic::client::Grpc::new(channel(port).await);
        client.ready().await.unwrap();
        let codec = netget::server::grpc::stream_codec::DynamicCodec {
            encode: descriptor.clone(),
            decode: descriptor.clone(),
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(prost_reflect::DynamicMessage::new(descriptor.clone()))
            .await
            .unwrap();
        let retained = if unclosed {
            Some(sender)
        } else {
            drop(sender);
            None
        };
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            client.streaming(
                tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(receiver)),
                http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
                codec,
            ),
        )
        .await
        .unwrap();
        let error = match result {
            Err(status) => status,
            Ok(response) => response.into_inner().message().await.unwrap_err(),
        };
        assert!(
            matches!(
                error.code(),
                tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
            ),
            "{error:?}"
        );
        drop(retained);
        intercepts(&state, 0).await;
    }
    state.remove_server(id).await.unwrap();
}

#[tokio::test]
async fn reflection_v1_query_count_message_bounds_and_opt_out() {
    use prost::Message;
    use tonic_reflection::pb::v1::{
        server_reflection_client::ServerReflectionClient,
        server_reflection_request::MessageRequest, ServerReflectionRequest,
    };
    let state = peer::state().await;
    let (id, port) = peer::netget_server(&state, vec![], json!({}))
        .await
        .unwrap();
    let mut client = ServerReflectionClient::new(channel(port).await)
        .max_encoding_message_size(64 * 1024 + 1)
        .max_decoding_message_size(5 * 1024 * 1024);
    let query = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let mut replies = client
        .server_reflection_info(tokio_stream::iter(vec![query.clone(); 129]))
        .await
        .unwrap()
        .into_inner();
    for _ in 0..128 {
        assert!(replies.message().await.unwrap().is_some());
    }
    assert_eq!(
        replies.message().await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    // A request exactly at the decoder bound works. The next byte is rejected,
    // including after gzip expansion, and another RPC on the connection works.
    for gzip in [false, true] {
        let mut bounded = client.clone();
        if gzip {
            bounded = bounded.send_compressed(tonic::codec::CompressionEncoding::Gzip);
        }
        let mut exact = query.clone();
        exact.host = "h".repeat(64 * 1024 - 6);
        assert_eq!(exact.encoded_len(), 64 * 1024);
        let mut response = bounded
            .server_reflection_info(tokio_stream::iter(vec![exact.clone()]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response.message().await.unwrap().unwrap().valid_host.len(),
            64 * 1024 - 6
        );
        exact.host.push('h');
        assert_eq!(exact.encoded_len(), 64 * 1024 + 1);
        let result = bounded
            .server_reflection_info(tokio_stream::iter(vec![exact]))
            .await;
        let error = match result {
            Err(status) => status,
            Ok(response) => response.into_inner().message().await.unwrap_err(),
        };
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }
    let mut response = client
        .server_reflection_info(tokio_stream::iter(vec![query.clone()]))
        .await
        .unwrap()
        .into_inner();
    assert!(response.message().await.unwrap().is_some());
    state.remove_server(id).await.unwrap();
    let (disabled, port) = peer::netget_server(&state, vec![], json!({"enable_reflection":false}))
        .await
        .unwrap();
    let error = ServerReflectionClient::new(channel(port).await)
        .server_reflection_info(tokio_stream::iter(vec![query]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    state.remove_server(disabled).await.unwrap();
}

#[tokio::test]
async fn grpcio_request_exact_bound_plus_one_plain_and_gzip() {
    let state = peer::state().await;
    let script="import json,sys\nd=json.load(sys.stdin)\ne=d['event']\na=[{'type':'grpc_stream_wait','milliseconds':1000}]\nif d['event_type_id']=='grpc_stream_opened': a=[{'type':'grpc_stream_send','message':{'value':len(e['message'].get('name',''))}},{'type':'grpc_stream_finish'}]\nprint(json.dumps({'actions':a}))";
    let (id,port)=peer::netget_server(&state,vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":script}})],json!({})).await.unwrap();
    assert_eq!(
        peer::client(port, "request-bounds").await.unwrap(),
        json!({"exact":4194304,"overflow":4194305,"gzip":true,"recovered":true})
    );
    state.remove_server(id).await.unwrap();
}

#[tokio::test]
async fn server_global_stream_admission_and_slot_recovery() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({}),
    )
    .await
    .unwrap();
    let descriptor = peer::pool()
        .unwrap()
        .get_message_by_name("streams.Message")
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    let mut channels = Vec::new();
    for _ in 0..4 {
        let channel = channel(port).await;
        channels.push(channel.clone());
        for _ in 0..16 {
            let channel = channel.clone();
            let descriptor = descriptor.clone();
            tasks.spawn(async move {
                let mut client = tonic::client::Grpc::new(channel);
                client.ready().await.unwrap();
                client
                    .server_streaming(
                        tonic::Request::new(prost_reflect::DynamicMessage::new(descriptor.clone())),
                        http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
                        netget::server::grpc::stream_codec::DynamicCodec {
                            encode: descriptor.clone(),
                            decode: descriptor,
                        },
                    )
                    .await
            });
        }
    }
    intercepts(&state, 64).await;
    let mut client = tonic::client::Grpc::new(channel(port).await);
    client.ready().await.unwrap();
    let error = client
        .server_streaming(
            tonic::Request::new(prost_reflect::DynamicMessage::new(descriptor.clone())),
            http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
            netget::server::grpc::stream_codec::DynamicCodec {
                encode: descriptor.clone(),
                decode: descriptor.clone(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert_eq!(state.list_intercepts().await.len(), 64);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    intercepts(&state, 0).await;
    tasks.spawn(async move {
        client.ready().await.unwrap();
        client
            .server_streaming(
                tonic::Request::new(prost_reflect::DynamicMessage::new(descriptor.clone())),
                http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
                netget::server::grpc::stream_codec::DynamicCodec {
                    encode: descriptor.clone(),
                    decode: descriptor,
                },
            )
            .await
    });
    intercepts(&state, 1).await;
    state.remove_server(id).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    if let Ok(response) = response {
        assert!(response.into_inner().message().await.is_err());
    }
    intercepts(&state, 0).await;
}

#[tokio::test]
async fn server_deadline_cancels_response_stalled_by_zero_http2_window() {
    use bytes::Bytes;
    let state = peer::state().await;
    let (id,port)=peer::netget_server(&state,vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"grpc_stream_send","message":{"name":"r".repeat(1024*1024)}},{"type":"grpc_stream_wait","milliseconds":1000}]}})],json!({"stream_timeout_secs":1})).await.unwrap();
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(0)
        .handshake(socket)
        .await
        .unwrap();
    let mut owner = tokio::task::JoinSet::new();
    owner.spawn(async move { connection.await });
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/streams.Session/Watch"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, mut input) = sender.send_request(request, false).unwrap();
    input
        .send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let reset = tokio::time::timeout(Duration::from_secs(3), body.data())
        .await
        .unwrap()
        .expect("stalled stream must reset");
    assert!(
        reset.is_err(),
        "no DATA may cross a zero window before the owned deadline resets it"
    );
    assert!(state.list_intercepts().await.is_empty());
    state.remove_server(id).await.unwrap();
}

#[tokio::test]
async fn injected_send_finish_and_cancel_control_parked_server_streams() {
    use netget::state::client_handles::ClientSendOutcome;
    let state = peer::state().await;
    let (id, port) = peer::netget_server(
        &state,
        vec![json!({"event_pattern":"*","handler":{"type":"manual"}})],
        json!({}),
    )
    .await
    .unwrap();
    let descriptor = peer::pool()
        .unwrap()
        .get_message_by_name("streams.Message")
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel(port).await);
    for cancel in [false, true] {
        client.ready().await.unwrap();
        let response = client
            .server_streaming(
                tonic::Request::new(prost_reflect::DynamicMessage::new(descriptor.clone())),
                http::uri::PathAndQuery::from_static("/streams.Session/Watch"),
                netget::server::grpc::stream_codec::DynamicCodec {
                    encode: descriptor.clone(),
                    decode: descriptor.clone(),
                },
            )
            .await
            .unwrap();
        let mut response = response.into_inner();
        intercepts(&state, 1).await;
        let intercept = state.list_intercepts().await.remove(0);
        let connection = intercept.connection_id.unwrap();
        let stream = intercept.event_data.unwrap()["stream_id"].as_u64().unwrap();
        assert!(state
            .send_to_peer(
                id,
                connection,
                json!({"type":"grpc_stream_send","stream_id":stream,"message":{"value":"wrong"}}),
                Duration::from_secs(3)
            )
            .await
            .is_err());
        if !cancel {
            let queued=state.send_to_peer(id,connection,json!({"type":"grpc_stream_send","stream_id":stream,"message":{"name":"injected"}}),Duration::from_secs(3)).await.unwrap();
            assert!(matches!(queued, ClientSendOutcome::Executed { .. }));
            assert_eq!(
                netget::server::grpc::stream_codec::to_json(
                    &response.message().await.unwrap().unwrap()
                )
                .unwrap()["name"],
                "injected"
            );
        }
        state.send_to_peer(id,connection,json!({"type":if cancel {"grpc_stream_cancel"}else{"grpc_stream_finish"},"stream_id":stream}),Duration::from_secs(3)).await.unwrap();
        if cancel {
            assert_eq!(
                response.message().await.unwrap_err().code(),
                tonic::Code::Cancelled
            );
        } else {
            assert!(response.message().await.unwrap().is_none());
        }
        intercepts(&state, 0).await;
        assert!(state
            .send_to_peer(
                id,
                connection,
                json!({"type":"grpc_stream_send","stream_id":stream,"message":{}}),
                Duration::from_secs(3)
            )
            .await
            .is_err());
    }
    state.remove_server(id).await.unwrap();
}

/// grpcurl — grpc-go, a second implementation beside grpcio — drives the two client-sending
/// shapes through reflection alone: three messages into client-streaming `Collect` (one reply
/// after half-close, counting them) and two into bidirectional `Chat` (one reply per message,
/// each derived from it). Every message is decoded by NetGet and reaches the handler.
#[tokio::test]
async fn independent_grpcurl_client_streaming_and_bidi() {
    let state = peer::state().await;
    let (id, port) = peer::netget_server(&state, vec![peer::semantic_handler()], json!({}))
        .await
        .unwrap();
    let grpcurl = |method: &'static str, input: &'static str| {
        let address = format!("127.0.0.1:{port}");
        async move {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new("grpcurl")
                .args(["-plaintext", "-d", "@", &address, method])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .expect("grpcurl is mandatory; install grpcurl 1.9.4");
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(input.as_bytes()).await.unwrap();
            drop(stdin);
            let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "grpcurl {method}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            // grpcurl prints each reply as a pretty JSON object; read them back as a stream.
            serde_json::Deserializer::from_slice(&output.stdout)
                .into_iter::<serde_json::Value>()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        }
    };
    let collected = grpcurl(
        "streams.Session/Collect",
        r#"{"name":"a","value":1} {"name":"b","value":2} {"name":"c","value":3,"tags":["x"]}"#,
    )
    .await;
    assert_eq!(
        collected,
        vec![json!({"name":"collected","value":5,"counts":{"messages":3}})]
    );
    let chat = grpcurl(
        "streams.Session/Chat",
        r#"{"name":"ping","value":1} {"name":"pong","value":10}"#,
    )
    .await;
    assert_eq!(
        chat,
        vec![
            json!({"name":"ping","value":2}),
            json!({"name":"pong","value":11})
        ]
    );
    let logs = state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None,
        )
        .await;
    let inputs = |method: &str| {
        logs.iter()
            .filter(|log| {
                log.event_type == "grpc_stream_message" && log.request["method"] == method
            })
            .count()
    };
    assert_eq!(inputs("Collect"), 3);
    assert_eq!(inputs("Chat"), 2);
    state.remove_server(id).await.unwrap();
}
