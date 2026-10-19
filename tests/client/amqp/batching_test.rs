//! Does the AMQP client answer the deliveries that arrived during a model call together, when
//! it batches?
//!
//! A stand-in broker, written here on NetGet's own AMQP 0-9-1 codec, completes lapin's handshake,
//! accepts the `consume` the model asks for on `amqp_connected`, then delivers `first`, which
//! the mock model answers slowly, and `second` and `third` while that call runs. They wait in
//! lapin's consumer buffer. Batching off is the control, in the same test as the claim: three
//! model calls, one per delivery. Batching on: two — `first`, then one call triggered by
//! `third` with `second` listed above it as arrived and not yet answered.
//!
//! The peer is a fake because the property under test is the client's own queueing, not
//! interoperability.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::amqp::codec::{self, Decoder, Encoder};
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

const EVENT: &str = "amqp_message_received";

/// Read one frame: (type, channel, payload).
async fn read_frame(r: &mut tokio::net::tcp::OwnedReadHalf) -> Option<(u8, u16, Vec<u8>)> {
    let mut head = [0u8; 7];
    r.read_exact(&mut head).await.ok()?;
    let size = u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize;
    let mut payload = vec![0u8; size + 1];
    r.read_exact(&mut payload).await.ok()?;
    payload.pop(); // frame-end
    Some((head[0], u16::from_be_bytes([head[1], head[2]]), payload))
}

/// A broker that knows just enough of AMQP 0-9-1 for lapin to connect, open a channel and
/// consume. `consuming` fires once Consume-Ok is written; each body sent on `deliver` becomes a
/// Basic.Deliver on that consumer.
async fn broker(
    listener: TcpListener,
    consuming: oneshot::Sender<()>,
    mut deliver: mpsc::UnboundedReceiver<String>,
) {
    let (socket, _) = listener.accept().await.expect("accept");
    let (mut r, mut w) = socket.into_split();
    let mut header = [0u8; 8];
    r.read_exact(&mut header).await.expect("protocol header");
    assert_eq!(header, codec::PROTOCOL_HEADER_091);

    let mut start = Encoder::new();
    start.u8(0);
    start.u8(9);
    start.u32(0); // empty server-properties table
    start.long_string(b"PLAIN");
    start.long_string(b"en_US");
    w.write_all(&codec::method_frame(
        0,
        codec::CLASS_CONNECTION,
        codec::CONNECTION_START,
        start.as_slice(),
    ))
    .await
    .expect("Connection.Start");

    // Methods the client sends, forwarded by a reader task so the writer below can also
    // serve deliveries.
    let (method_tx, mut method_rx) = mpsc::unbounded_channel::<(u16, u16, u16, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((kind, channel, payload)) = read_frame(&mut r).await {
            if kind == codec::FRAME_METHOD && payload.len() >= 4 {
                let class = u16::from_be_bytes([payload[0], payload[1]]);
                let method = u16::from_be_bytes([payload[2], payload[3]]);
                if method_tx
                    .send((channel, class, method, payload[4..].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    let mut consuming = Some(consuming);
    let mut consumer: Option<(u16, String)> = None;
    let mut delivery_tag = 0u64;
    loop {
        tokio::select! {
            method = method_rx.recv() => {
                let Some((channel, class, method, args)) = method else { return };
                let reply = match (class, method) {
                    (codec::CLASS_CONNECTION, codec::CONNECTION_START_OK) => {
                        let mut tune = Encoder::new();
                        tune.u16(16);
                        tune.u32(131_072);
                        tune.u16(0);
                        Some(codec::method_frame(0, class, codec::CONNECTION_TUNE, tune.as_slice()))
                    }
                    (codec::CLASS_CONNECTION, codec::CONNECTION_OPEN) => {
                        let mut ok = Encoder::new();
                        ok.short_string("").unwrap();
                        Some(codec::method_frame(0, class, codec::CONNECTION_OPEN_OK, ok.as_slice()))
                    }
                    (codec::CLASS_CHANNEL, codec::CHANNEL_OPEN) => {
                        let mut ok = Encoder::new();
                        ok.long_string(b"");
                        Some(codec::method_frame(channel, class, codec::CHANNEL_OPEN_OK, ok.as_slice()))
                    }
                    (codec::CLASS_BASIC, codec::BASIC_CONSUME) => {
                        let mut d = Decoder::new(&args);
                        let _reserved = d.u16().unwrap();
                        let _queue = d.short_string().unwrap();
                        let tag = d.short_string().unwrap();
                        let mut ok = Encoder::new();
                        ok.short_string(&tag).unwrap();
                        consumer = Some((channel, tag));
                        Some(codec::method_frame(channel, class, codec::BASIC_CONSUME_OK, ok.as_slice()))
                    }
                    _ => None, // Tune-Ok, Basic.Ack, …
                };
                if let Some(frame) = reply {
                    w.write_all(&frame).await.expect("write");
                    if class == codec::CLASS_BASIC {
                        if let Some(tx) = consuming.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
            body = deliver.recv() => {
                let Some(body) = body else { return };
                let (channel, tag) = consumer.clone().expect("deliver before consume");
                delivery_tag += 1;
                let mut args = Encoder::new();
                args.short_string(&tag).unwrap();
                args.u64(delivery_tag);
                args.u8(0); // redelivered
                args.short_string("").unwrap();
                args.short_string("q").unwrap();
                let mut bytes = codec::method_frame(
                    channel,
                    codec::CLASS_BASIC,
                    codec::BASIC_DELIVER,
                    args.as_slice(),
                );
                bytes.extend(codec::content_header_frame(
                    channel,
                    codec::CLASS_BASIC,
                    body.len() as u64,
                    &[0, 0],
                ));
                for frame in codec::body_frames(channel, body.as_bytes(), 131_072) {
                    bytes.extend(frame);
                }
                w.write_all(&bytes).await.expect("deliver");
            }
        }
    }
}

async fn session(batching: bool) -> Vec<(serde_json::Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("amqp_connected")
            .respond_with_actions(serde_json::json!([{"type": "consume", "queue_name": "q"}]))
            .expect_calls(1)
            .and()
            .on_event(EVENT)
            .and_event_data_contains("message_body", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (consuming_tx, consuming_rx) = oneshot::channel();
    let (deliver, deliver_rx) = mpsc::unbounded_channel();
    let broker_task = tokio::spawn(broker(listener, consuming_tx, deliver_rx));

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "amqp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Consume queue q and note each delivery.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    tokio::time::timeout(Duration::from_secs(15), consuming_rx)
        .await
        .expect("the client never consumed")
        .expect("broker ended");

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    deliver.send("first".to_string()).expect("deliver");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    deliver.send("second".to_string()).expect("deliver");
    tokio::time::sleep(Duration::from_millis(200)).await;
    deliver.send("third".to_string()).expect("deliver");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(d, _)| d["message_body"] == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:#?}",
            calls.iter().map(|(d, _)| d).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = data_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    broker_task.abort();
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn amqp_client_answers_deliveries_that_arrived_during_a_call_together() {
    let bodies = |calls: &[(serde_json::Value, String)]| {
        calls
            .iter()
            .map(|(d, _)| d["message_body"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
    };

    let separate = session(false).await;
    assert_eq!(
        bodies(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each delivery must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        bodies(&batched),
        vec!["first", "third"],
        "the two deliveries that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find(&format!("(1) {EVENT} {{"))
        .map(|at| &before[at..])
        .unwrap_or_default();
    assert!(
        listed.lines().next().unwrap_or_default().contains("second"),
        "the earlier delivery must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}
