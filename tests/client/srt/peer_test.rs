//! NetGet's SRT caller against libsrt's srt-live-transmit as listener (independent, unchanged):
//! it reads a paced H.264/AAC MPEG-TS stream and reports its programme, and it publishes an
//! MPEG-TS file that libsrt writes out and ffprobe reads back. Fails, never skips.
use crate::helpers::srt::*;
use netget::state::{client_handles::ClientSendOutcome, AccessLogOwner};
use serde_json::json;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn client_works_against_libsrt() {
    let slt = tool("srt-live-transmit");
    let ffmpeg = tool("ffmpeg");
    let dir = tempfile::tempdir().unwrap();
    let clip = make_clip(dir.path()).await;
    let state = state();

    // libsrt listens and sends the paced clip to whoever calls.
    let port = free_udp_port();
    let _source = pipeline(&format!("'{ffmpeg}' -hide_banner -nostdin -re -stream_loop -1 -i '{clip}' -c copy -f mpegts - | '{slt}' -q -chunk:1316 file://con 'srt://127.0.0.1:{port}?mode=listener'"));
    tokio::time::sleep(Duration::from_millis(800)).await;
    let reader = client_in(
        &state,
        format!("127.0.0.1:{port}"),
        json!({"stream_id": "#!::r=live/cam,m=request"}),
    )
    .await
    .unwrap();
    let sent = state
        .send_to_client(
            reader,
            json!({"type": "srt_receive", "seconds": 3}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    let r = &logs(
        &state,
        AccessLogOwner::Client(reader.as_u32()),
        "srt_report",
        1,
    )
    .await[0]
        .request;
    assert!(r["ts_packets"].as_u64().unwrap() > 300, "{r}");
    let types: Vec<&str> = r["stream_types"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert!(types.contains(&"h264") && types.contains(&"aac"), "{r}");
    assert!(
        r["statistics"]["rx_packets"].as_u64().unwrap_or(0) > 0,
        "{r}"
    );
    state.remove_client(reader).await;

    // libsrt listens and writes what NetGet's caller publishes.
    let port = free_udp_port();
    let out_path = dir.path().join("received.ts");
    let mut sink = tokio::process::Command::new(&slt)
        .args([
            "-q",
            &format!("srt://127.0.0.1:{port}?mode=listener"),
            "file://con",
        ])
        .stdout(std::fs::File::create(&out_path).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let publisher = client_in(
        &state,
        format!("127.0.0.1:{port}"),
        json!({"stream_id": "#!::r=live/netget,m=publish", "media_root": dir.path()}),
    )
    .await
    .unwrap();
    let sent = state
        .send_to_client(
            publisher,
            json!({"type": "srt_send_file", "path": clip, "bitrate_kbps": 2000}),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    let p = &logs(
        &state,
        AccessLogOwner::Client(publisher.as_u32()),
        "srt_report",
        1,
    )
    .await[0]
        .request;
    let clip_len = std::fs::metadata(&clip).unwrap().len();
    assert_eq!(p["bytes"].as_u64(), Some(clip_len), "{p}");
    state.remove_client(publisher).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    sink.kill().await.unwrap();
    let received = std::fs::metadata(&out_path).unwrap().len();
    assert!(
        received * 10 >= clip_len * 9,
        "libsrt wrote {received} of {clip_len} bytes"
    );
    let found = codecs(&out_path.display().to_string()).await;
    assert!(
        found.contains(&"h264".to_owned()) && found.contains(&"aac".to_owned()),
        "{found:?}"
    );
}

/// Condition 4 of the client bar, from libsrt's side, and the follow-up bound: the mocked
/// model answers the connect, and then every report, by sending a text it chose. libsrt's
/// srt-live-transmit writes what it received to a file, which must hold that text exactly
/// `MAX_FOLLOWUPS` times — none without the model's answers, and no more than the bound.
#[tokio::test(flavor = "multi_thread")]
async fn mocked_model_sends_text_libsrt_writes_and_the_chain_is_bounded() {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    const TEXT: &str = "chosen by the mocked model;";
    let limit = netget::client::srt::MAX_FOLLOWUPS as usize;
    let slt = tool("srt-live-transmit");
    let dir = tempfile::tempdir().unwrap();
    let port = free_udp_port();
    let out_path = dir.path().join("received.bin");
    // Without auto-reconnect it exits when the caller disconnects, flushing what it wrote.
    let mut sink = tokio::process::Command::new(&slt)
        .args([
            "-q",
            "-a:no",
            &format!("srt://127.0.0.1:{port}?mode=listener"),
            "file://con",
        ])
        .stdout(std::fs::File::create(&out_path).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let send = json!([{"type": "srt_send_text", "text": TEXT}]);
    let config = MockLlmBuilder::new()
        .on_event("srt_connected")
        .respond_with_actions(send.clone())
        .expect_calls(1)
        .and()
        .on_event("srt_report")
        .and_event_data_contains("operation", "send_text")
        .respond_with_actions(send)
        .expect_calls(limit)
        .and()
        .build();
    let mock = MockOllamaServer::start(config).await.unwrap();
    let state = netget::state::app_state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = netget::cli::management::ClientForm {
        protocol: "srt".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Send a line of text after each report".into()),
        startup_params: Some(json!({"stream_id": "#!::r=live/netget,m=publish"})),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await
    .unwrap();
    mock.wait_for_expectations(30).await;
    // An unbounded chain keeps going; give it the time to show.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let closed = state
        .send_to_client(id, json!({"type": "disconnect"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(
        matches!(closed, ClientSendOutcome::Disconnected),
        "{closed:?}"
    );
    if tokio::time::timeout(Duration::from_secs(15), sink.wait())
        .await
        .is_err()
    {
        sink.kill().await.unwrap();
    }
    state.remove_client(id).await;
    let received = String::from_utf8_lossy(&std::fs::read(&out_path).unwrap()).into_owned();
    assert_eq!(
        received.matches(TEXT).count(),
        limit,
        "libsrt wrote: {received:?}"
    );
    assert_eq!(mock.call_count().await, limit + 1);
    mock.verify_calls().await.unwrap();
}
