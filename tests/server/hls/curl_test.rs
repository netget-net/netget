//! Real-client validation: fetch the HLS playlist and a segment with `curl`.
//!
//! **Not `#[ignore]`d, and it does not skip.** It used to be `#[ignore]`d for "run manually",
//! which means it never ran anywhere — an `#[ignore]` is a skip gate with better manners, and
//! `CLAUDE.md` names it as one of the three ways evidence fails to execute. If `curl` is absent
//! this test fails and says how to install it.
//!
//! **What this does *not* establish**, and the reason HLS stays `Experimental`: `curl` is a
//! generic HTTP client. It proves the HTTP transport underneath HLS answers, exactly as
//! `reqwest` does for `couchdb`/`openapi`/`spark`; it parses no `#EXTM3U` playlist and decodes
//! no segment, so it says nothing about the layer NetGet actually authors. Real HLS evidence
//! needs a player — `ffprobe` reads an HLS master playlist natively — and that test does not
//! exist yet.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features hls \
//!     --test server -- --test-threads=100 hls::curl
//! ```


use crate::server::helpers::*;
use std::time::Duration;

/// Fail, never skip, when `curl` is absent.
fn require_curl() -> Result<(), Box<dyn std::error::Error>> {
    match std::process::Command::new("curl").arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(format!("`curl --version` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "curl is not available ({e}): this test drives a client NetGet did not write \
             against the HLS server, and skipping it would report a pass for a test that \
             asserted nothing. Install it with `brew install curl` (macOS) or \
             `apt-get install -y curl` (Debian/Ubuntu)."
        )
        .into()),
    }
}

fn curl(url: &str, args: &[&str]) -> (String, String) {
    let mut a: Vec<&str> = vec!["-s", "-i"];
    a.extend_from_slice(args);
    a.push(url);
    let out = std::process::Command::new("curl")
        .args(&a)
        .output()
        .expect("run curl");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[tokio::test]
async fn curl_fetches_playlist_and_segment() -> E2EResult<()> {
    require_curl()?;
    let prompt = "listen on port 0 via hls\n\nServe a 2-segment VOD playlist and a segment body.";
    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("hls")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "hls", "instruction": "hls"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("hls_playlist_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "hls_playlist_response", "target_duration": 6,
                    "segments": [{"uri": "seg0.ts", "duration": 6.0}, {"uri": "seg1.ts", "duration": 6.0}]
                }]))
                .and()
                .on_event("hls_segment_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "hls_segment_response", "content_type": "video/mp2t",
                    "encoding": "hex", "data": "47400010"
                }]))
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let base = format!("http://127.0.0.1:{}", test_state.port);

    let (playlist, _) = {
        let url = format!("{base}/stream.m3u8");
        tokio::task::spawn_blocking(move || curl(&url, &[]))
            .await
            .unwrap()
    };
    println!("curl playlist:\n{playlist}");
    assert!(playlist.contains("200"), "curl playlist status: {playlist}");
    assert!(
        playlist.contains("application/vnd.apple.mpegurl"),
        "content type: {playlist}"
    );
    assert!(playlist.contains("#EXTM3U"), "m3u8 header: {playlist}");
    assert!(playlist.contains("seg0.ts"), "segment listed: {playlist}");

    let (segment, _) = {
        let url = format!("{base}/seg0.ts");
        tokio::task::spawn_blocking(move || curl(&url, &[]))
            .await
            .unwrap()
    };
    println!("curl segment:\n{segment:?}");
    assert!(
        segment.contains("video/mp2t"),
        "segment content type: {segment}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}
