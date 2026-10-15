//! Regression: a pending adapter read must remain cancellable and retain its ID.
#[path = "helpers/quic_peer.rs"]
mod peer;
use bytes::Bytes;
use h3::quic::{Connection, OpenStreams, RecvStream};
use std::{sync::Arc, task::Poll};

#[tokio::test]
async fn http3_pending_h3_read_can_be_stopped_without_panicking() {
    let cert = peer::Certificate::new();
    let tls = netget::server::tls_cert_manager::load_tls_config_from_files(
        cert.cert().to_str().unwrap(),
        cert.key().to_str().unwrap(),
    )
    .unwrap();
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let params = netget::protocol::StartupParams::new(
        cert.trust(),
        netget::utils::quic::client_parameters(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap().to_string();
    let (client, server) = tokio::join!(
        netget::utils::quic::connect(&address, Some(&params), b"h3", 4),
        async { endpoint.accept().await.unwrap().await.unwrap() }
    );
    let (_client_endpoint, connection) = client.unwrap();
    let adapter = h3_quinn::Connection::new(connection.0.clone());
    let mut opener = <h3_quinn::Connection as Connection<Bytes>>::opener(&adapter);
    let mut stream: h3_quinn::BidiStream<Bytes> =
        std::future::poll_fn(|cx| opener.poll_open_bidi(cx))
            .await
            .unwrap();
    std::future::poll_fn(|cx| {
        assert!(matches!(stream.poll_data(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    // The read future has been dropped while Pending, exactly as a timeout or
    // removal does. Upstream 0.0.10 unwraps its temporarily absent stream here.
    stream.stop_sending(0x10c);
    assert_eq!(stream.recv_id().index(), 0);
    server.close(0u32.into(), b"done");
}

#[tokio::test]
async fn http3_client_waits_for_final_response_after_early_hints() {
    let cert = peer::Certificate::new();
    let tls = netget::server::tls_cert_manager::load_tls_config_from_files(
        cert.cert().to_str().unwrap(),
        cert.key().to_str().unwrap(),
    )
    .unwrap();
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .send_grease(false)
            .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let (_, mut request) = resolver.resolve_request().await.unwrap();
        while request.recv_data().await.unwrap().is_some() {}
        request
            .send_response(
                http::Response::builder()
                    .status(103)
                    .header("link", "</style.css>; rel=preload")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        request
            .send_response(http::Response::builder().status(200).body(()).unwrap())
            .await
            .unwrap();
        request
            .send_data(Bytes::from_static(b"final response"))
            .await
            .unwrap();
        request.finish().await.unwrap();
        conn.closed().await;
    });
    let state = peer::state();
    let id = peer::client(
        &state,
        "http3",
        address,
        cert.trust(),
        vec![peer::empty_handler()],
    )
    .await;
    let response = state
        .send_to_client(
            id,
            serde_json::json!({"type":"send_http3_request","method":"GET","path":"/early-hints"}),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(response,netget::state::client_handles::ClientSendOutcome::Executed{detail} if detail.contains("-> 200 (14 byte body)"))
    );
    state.remove_client(id).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}
