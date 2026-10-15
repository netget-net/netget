//! Real-client validation: drive the RTSP server with ffprobe (ffmpeg's prober).
//!
//! ffprobe performs a real OPTIONS → DESCRIBE → SETUP → PLAY and reads RTP, then reports the
//! stream. Success proves an independent client — ffmpeg's `libavformat`, which shares no code
//! with anything in this repository — interoperates with the RTSP + RTP implementation. This is
//! the whole of RTSP's real-client evidence.
//!
//! **This test is not `#[ignore]`d and it does not skip.** It used to be both: `#[ignore]`d for
//! "run manually", which means nothing ever ran it, so the claim in `metadata()` rested on a
//! test that had never executed on any machine that mattered. An `#[ignore]` is a skip gate with
//! better manners — `CLAUDE.md` names it as one of the three ways evidence fails to execute. If
//! `ffprobe` is absent the test **fails** and says how to install it.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features rtsp,rtp \
//!     --test server -- --test-threads=100 rtsp::ffprobe
//! ```

use crate::server::helpers::*;
use std::time::Duration;

/// Fail, never skip, when `ffprobe` is absent.
fn require_ffprobe() -> Result<(), Box<dyn std::error::Error>> {
    match std::process::Command::new("ffprobe")
        .arg("-version")
        .output()
    {
        Ok(out) if out.status.success() => {
            println!(
                "{}",
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("ffprobe")
            );
            Ok(())
        }
        Ok(out) => Err(format!(
            "`ffprobe -version` exited {}: this test's whole point is driving ffmpeg's own \
             RTSP/RTP client against NetGet's server",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "ffprobe is not available ({e}): this test drives ffmpeg's `libavformat` — an RTSP \
             and RTP implementation that shares no code with this repository — through a real \
             OPTIONS/DESCRIBE/SETUP/PLAY, and it is the only independent evidence behind the \
             RTSP server's maturity rating. Skipping would leave that rating resting on \
             nothing, so this is a failure and not a skip. Install it with `brew install \
             ffmpeg` (macOS) or `apt-get install -y ffmpeg` (Debian/Ubuntu)."
        )
        .into()),
    }
}

#[tokio::test]
async fn ffprobe_reads_rtsp_stream() -> E2EResult<()> {
    require_ffprobe()?;

    let prompt = "listen on port 0 via rtsp\n\nOffer one PCMU audio stream; play a tone on PLAY.";
    let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=NetGet\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
               m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:streamid=0\r\n";

    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(move |mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("rtsp")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "rtsp", "instruction": "rtsp"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("rtsp_options")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_options_response"}]))
                .and()
                .on_event("rtsp_describe")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_describe_response", "sdp": sdp}]))
                .and()
                .on_event("rtsp_setup")
                .respond_with_actions(serde_json::json!([{"type": "rtsp_setup_response"}]))
                .and()
                .on_event("rtsp_play")
                .respond_with_actions(serde_json::json!([{
                    "type": "rtsp_play_response", "content": "tone", "tone_hz": 440, "duration_ms": 4000
                }]))
                .and()
        });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let url = format!("rtsp://127.0.0.1:{}/stream", test_state.port);

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("ffprobe")
            .args([
                "-v",
                "info",
                "-rtsp_transport",
                "udp",
                "-analyzeduration",
                "3000000",
                "-probesize",
                "200000",
                "-show_entries",
                "stream=codec_name,sample_rate",
                "-of",
                "default=noprint_wrappers=1",
                &url,
            ])
            .output()
    })
    .await
    .expect("spawn_blocking join")
    .expect("failed to run ffprobe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("ffprobe stdout:\n{stdout}\nffprobe stderr:\n{stderr}");

    // ffprobe learns the codec from the DESCRIBE SDP; a successful DESCRIBE/SETUP/PLAY prints it.
    assert!(
        stdout.contains("pcm_mulaw")
            || stderr.contains("pcm_mulaw")
            || stderr.contains("Audio: pcm_mulaw"),
        "ffprobe did not recognize the PCMU stream; stdout={stdout} stderr={stderr}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}
