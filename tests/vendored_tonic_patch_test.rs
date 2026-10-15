//! Wire regressions for NetGet's tonic receive-limit patch (the `netget-tonic` fork,
//! github.com/netget-net/tonic), independent of OTLP runtime.
#[path = "helpers/fork_source.rs"]
mod fork_source;

#[test]
fn cargo_builds_the_tonic_fork_with_its_license() {
    fork_source::assert_fork_is_built("tonic", "0.12.3");
    let manifest = fork_source::read_fork("netget-tonic", "Cargo.toml");
    assert!(manifest.contains("license = \"MIT\""));
    assert!(fork_source::fork_dir("netget-tonic").join("LICENSE").is_file());
    let compression = fork_source::read_fork("netget-tonic", "src/codec/compression.rs");
    assert!(
        compression.contains("limit"),
        "the decompression bound is gone from the fork's codec/compression.rs"
    );
}
mod wire {
    use prost::Message;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tonic::{
        body::BoxBody,
        codec::{CompressionEncoding, ProstCodec},
        Code,
    };
    use tower::Service;
    const LIMIT: usize = 4 * 1024 * 1024;
    #[derive(Clone, PartialEq, Message)]
    struct Blob {
        #[prost(bytes = "vec", tag = "1")]
        data: Vec<u8>,
    }
    fn blob(size: usize) -> Blob {
        let mut value = Blob {
            data: vec![0; size - 5],
        };
        while value.encoded_len() < size {
            value.data.push(0);
        }
        assert_eq!(value.encoded_len(), size);
        value
    }
    #[derive(Clone)]
    struct Peer {
        calls: Arc<AtomicUsize>,
        oversized_response: Arc<AtomicBool>,
    }
    impl tonic::server::NamedService for Peer {
        const NAME: &'static str = "netget.test.Bounds";
    }
    struct Unary(Peer);
    impl tonic::server::UnaryService<Blob> for Unary {
        type Response = Blob;
        type Future = tonic::codegen::BoxFuture<tonic::Response<Blob>, tonic::Status>;
        fn call(&mut self, _: tonic::Request<Blob>) -> Self::Future {
            let peer = self.0.clone();
            Box::pin(async move {
                peer.calls.fetch_add(1, Ordering::SeqCst);
                Ok(tonic::Response::new(blob(
                    LIMIT + usize::from(peer.oversized_response.load(Ordering::SeqCst)),
                )))
            })
        }
    }
    impl Service<hyper::Request<BoxBody>> for Peer {
        type Response = hyper::Response<BoxBody>;
        type Error = std::convert::Infallible;
        type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: hyper::Request<BoxBody>) -> Self::Future {
            let peer = self.clone();
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(ProstCodec::<Blob, Blob>::default())
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(LIMIT)
                    .max_encoding_message_size(LIMIT + 1);
                Ok(grpc.unary(Unary(peer), req).await)
            })
        }
    }
    struct Fixture {
        task: tokio::task::JoinHandle<()>,
        channel: tonic::transport::Channel,
        peer: Peer,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn start() -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = Peer {
            calls: Arc::new(AtomicUsize::new(0)),
            oversized_response: Arc::new(AtomicBool::new(false)),
        };
        let service = peer.clone();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let connection = listener.accept().await.map(|v| v.0);
            Some((connection, listener))
        });
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
            .unwrap();
        Fixture {
            task,
            channel,
            peer,
        }
    }
    async fn call(fixture: &Fixture, size: usize, gzip: bool) -> Result<Blob, tonic::Status> {
        let mut client = tonic::client::Grpc::new(fixture.channel.clone())
            .max_decoding_message_size(LIMIT)
            .max_encoding_message_size(LIMIT + 1);
        if gzip {
            client = client
                .send_compressed(CompressionEncoding::Gzip)
                .accept_compressed(CompressionEncoding::Gzip);
        }
        client.ready().await.unwrap();
        let mut request = tonic::Request::new(blob(size));
        request.set_timeout(Duration::from_secs(10));
        let response: tonic::Response<Blob> = client
            .unary(
                request,
                "/netget.test.Bounds/Unary".parse().unwrap(),
                ProstCodec::<Blob, Blob>::default(),
            )
            .await?;
        Ok(response.into_inner())
    }
    #[tokio::test]
    async fn request_exact_four_mib_and_limit_plus_one_plain_and_gzip() {
        let fixture = start().await;
        for gzip in [false, true] {
            assert_eq!(
                call(&fixture, LIMIT, gzip).await.unwrap().encoded_len(),
                LIMIT
            );
            let before = fixture.peer.calls.load(Ordering::SeqCst);
            assert_eq!(
                call(&fixture, LIMIT + 1, gzip).await.unwrap_err().code(),
                Code::ResourceExhausted
            );
            assert_eq!(
                fixture.peer.calls.load(Ordering::SeqCst),
                before,
                "over-limit request reached application"
            );
        }
    }
    #[tokio::test]
    async fn response_exact_four_mib_and_limit_plus_one_plain_and_gzip() {
        let fixture = start().await;
        for gzip in [false, true] {
            fixture
                .peer
                .oversized_response
                .store(false, Ordering::SeqCst);
            assert_eq!(call(&fixture, 8, gzip).await.unwrap().encoded_len(), LIMIT);
            fixture
                .peer
                .oversized_response
                .store(true, Ordering::SeqCst);
            assert_eq!(
                call(&fixture, 8, gzip).await.unwrap_err().code(),
                Code::ResourceExhausted
            );
        }
    }
}
