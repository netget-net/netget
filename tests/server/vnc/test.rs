//! End-to-end VNC tests.
//!
//! Every test drives the real `netget` binary with a real RFB 3.8 client implemented below and
//! asserts protocol-level results: the ServerInit geometry and pixel format, and the *decoded
//! pixels* of a FramebufferUpdate against what the mocked model asked for. There is no Rust
//! crate implementing an RFB client that is usable here (the maintained ones are viewers with
//! their own event loops), so the client is hand-rolled — it is roughly 150 lines, and it is
//! the only way to prove the bytes on the wire mean what the server claims.

use super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::server::vnc::PLACEHOLDER_BACKGROUND;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long any single server response may take, including one mocked LLM round-trip.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// One Raw-encoded rectangle out of a FramebufferUpdate.
struct VncRect {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    /// BGRX, four bytes per pixel, as announced in ServerInit.
    pixels: Vec<u8>,
}

impl VncRect {
    /// The BGRX quad at (x, y) within this rectangle.
    fn pixel(&self, x: u16, y: u16) -> [u8; 4] {
        let offset = ((y as usize) * (self.width as usize) + (x as usize)) * 4;
        assert!(
            offset + 4 <= self.pixels.len(),
            "pixel ({x},{y}) is outside the {}x{} rectangle",
            self.width,
            self.height
        );
        self.pixels[offset..offset + 4]
            .try_into()
            .expect("four bytes per pixel")
    }

    /// The RGB triple at (x, y), decoded from the announced BGRX layout.
    fn rgb(&self, x: u16, y: u16) -> (u8, u8, u8) {
        let [b, g, r, _] = self.pixel(x, y);
        (r, g, b)
    }
}

/// What the server sent us.
enum ServerMessage {
    FramebufferUpdate(Vec<VncRect>),
    CutText(String),
}

/// Geometry and pixel format read out of ServerInit.
struct ServerInit {
    width: u16,
    height: u16,
    bits_per_pixel: u8,
    depth: u8,
    big_endian: bool,
    true_color: bool,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    name: String,
}

/// Minimal RFB 3.8 client.
struct VncClient {
    stream: TcpStream,
}

impl VncClient {
    async fn connect(port: u16) -> E2EResult<Self> {
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
        Ok(Self { stream })
    }

    /// ProtocolVersion, security-type negotiation and SecurityResult.
    async fn handshake(&mut self) -> E2EResult<()> {
        let mut version = [0u8; 12];
        self.stream.read_exact(&mut version).await?;
        let version_str = String::from_utf8_lossy(&version).to_string();
        if version_str != "RFB 003.008\n" {
            return Err(format!("expected RFB 003.008, got {version_str:?}").into());
        }
        self.stream.write_all(b"RFB 003.008\n").await?;

        let num_security_types = self.stream.read_u8().await?;
        if num_security_types == 0 {
            let reason_length = self.stream.read_u32().await?;
            let mut reason = vec![0u8; reason_length as usize];
            self.stream.read_exact(&mut reason).await?;
            return Err(format!("connection failed: {}", String::from_utf8_lossy(&reason)).into());
        }
        let mut security_types = vec![0u8; num_security_types as usize];
        self.stream.read_exact(&mut security_types).await?;
        if !security_types.contains(&1) {
            return Err(
                format!("server did not offer security type None: {security_types:?}").into(),
            );
        }
        self.stream.write_u8(1).await?;

        let security_result = self.stream.read_u32().await?;
        if security_result != 0 {
            return Err(format!("SecurityResult was {security_result}, expected 0").into());
        }
        Ok(())
    }

    /// ClientInit, then decode ServerInit.
    async fn initialize(&mut self) -> E2EResult<ServerInit> {
        self.stream.write_u8(1).await?; // shared flag

        let width = self.stream.read_u16().await?;
        let height = self.stream.read_u16().await?;

        let mut pixel_format = [0u8; 16];
        self.stream.read_exact(&mut pixel_format).await?;

        let name_length = self.stream.read_u32().await?;
        if name_length > 4096 {
            return Err(format!("implausible desktop name length {name_length}").into());
        }
        let mut name = vec![0u8; name_length as usize];
        self.stream.read_exact(&mut name).await?;

        Ok(ServerInit {
            width,
            height,
            bits_per_pixel: pixel_format[0],
            depth: pixel_format[1],
            big_endian: pixel_format[2] != 0,
            true_color: pixel_format[3] != 0,
            red_shift: pixel_format[10],
            green_shift: pixel_format[11],
            blue_shift: pixel_format[12],
            name: String::from_utf8_lossy(&name).to_string(),
        })
    }

    async fn request_framebuffer_update(
        &mut self,
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> E2EResult<()> {
        let mut message = vec![3u8, u8::from(incremental)];
        message.extend_from_slice(&x.to_be_bytes());
        message.extend_from_slice(&y.to_be_bytes());
        message.extend_from_slice(&width.to_be_bytes());
        message.extend_from_slice(&height.to_be_bytes());
        self.stream.write_all(&message).await?;
        Ok(())
    }

    async fn send_key_event(&mut self, down: bool, keysym: u32) -> E2EResult<()> {
        let mut message = vec![4u8, u8::from(down), 0, 0];
        message.extend_from_slice(&keysym.to_be_bytes());
        self.stream.write_all(&message).await?;
        Ok(())
    }

    async fn send_pointer_event(&mut self, button_mask: u8, x: u16, y: u16) -> E2EResult<()> {
        let mut message = vec![5u8, button_mask];
        message.extend_from_slice(&x.to_be_bytes());
        message.extend_from_slice(&y.to_be_bytes());
        self.stream.write_all(&message).await?;
        Ok(())
    }

    async fn send_cut_text(&mut self, text: &str) -> E2EResult<()> {
        let bytes = text.as_bytes();
        let mut message = vec![6u8, 0, 0, 0];
        message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        message.extend_from_slice(bytes);
        self.stream.write_all(&message).await?;
        Ok(())
    }

    /// Read one server-to-client message, failing on anything malformed.
    ///
    /// Any deviation from the RFB wire format is an error rather than a printed note: a client
    /// that shrugs at a malformed update cannot tell a working server from a broken one, which
    /// is how this suite used to pass.
    async fn read_message(&mut self) -> E2EResult<ServerMessage> {
        let message_type = self.stream.read_u8().await?;
        match message_type {
            0 => {
                let _padding = self.stream.read_u8().await?;
                let num_rectangles = self.stream.read_u16().await?;
                let mut rects = Vec::new();
                for i in 0..num_rectangles {
                    let x = self.stream.read_u16().await?;
                    let y = self.stream.read_u16().await?;
                    let width = self.stream.read_u16().await?;
                    let height = self.stream.read_u16().await?;
                    let encoding = self.stream.read_i32().await?;
                    // Only Raw (0) is implemented by this server. Anything else means the
                    // stream desynchronised, and we must not guess at the payload length.
                    if encoding != 0 {
                        return Err(format!(
                            "rectangle {} used encoding {encoding}, but only Raw (0) is supported",
                            i + 1
                        )
                        .into());
                    }
                    let mut pixels = vec![0u8; (width as usize) * (height as usize) * 4];
                    self.stream.read_exact(&mut pixels).await?;
                    rects.push(VncRect {
                        x,
                        y,
                        width,
                        height,
                        pixels,
                    });
                }
                Ok(ServerMessage::FramebufferUpdate(rects))
            }
            3 => {
                let mut padding = [0u8; 3];
                self.stream.read_exact(&mut padding).await?;
                let length = self.stream.read_u32().await?;
                if length > 1 << 20 {
                    return Err(format!("implausible ServerCutText length {length}").into());
                }
                let mut text = vec![0u8; length as usize];
                self.stream.read_exact(&mut text).await?;
                // ServerCutText is Latin-1 on the wire.
                Ok(ServerMessage::CutText(
                    text.iter().map(|&b| b as char).collect(),
                ))
            }
            other => Err(format!("unexpected server message type {other}").into()),
        }
    }

    /// Read the single Raw rectangle of a full-screen FramebufferUpdate.
    async fn read_full_update(&mut self, context: &str) -> E2EResult<VncRect> {
        let message = tokio::time::timeout(RESPONSE_TIMEOUT, self.read_message())
            .await
            .map_err(|_| format!("timed out waiting for a FramebufferUpdate ({context})"))??;
        match message {
            ServerMessage::FramebufferUpdate(mut rects) => {
                if rects.len() != 1 {
                    return Err(format!(
                        "expected exactly one Raw rectangle ({context}), got {}",
                        rects.len()
                    )
                    .into());
                }
                Ok(rects.remove(0))
            }
            ServerMessage::CutText(text) => Err(format!(
                "expected a FramebufferUpdate ({context}), got ServerCutText {text:?}"
            )
            .into()),
        }
    }

    async fn read_cut_text(&mut self, context: &str) -> E2EResult<String> {
        let message = tokio::time::timeout(RESPONSE_TIMEOUT, self.read_message())
            .await
            .map_err(|_| format!("timed out waiting for ServerCutText ({context})"))??;
        match message {
            ServerMessage::CutText(text) => Ok(text),
            ServerMessage::FramebufferUpdate(rects) => Err(format!(
                "expected ServerCutText ({context}) but the server sent a FramebufferUpdate with \
                 {} rectangle(s) — it answered an event it should have left alone",
                rects.len()
            )
            .into()),
        }
    }
}

/// Assert a rectangle covers the whole announced framebuffer.
///
/// RFB lets the server answer with any rectangle, and this one deliberately answers with its
/// own framebuffer rather than the extent the client asked for, so the comparison is against
/// ServerInit, not against the request.
fn assert_full_frame(rect: &VncRect, init: &ServerInit, context: &str) {
    assert_eq!(
        (rect.x, rect.y),
        (0, 0),
        "{context}: update must start at the origin"
    );
    assert_eq!(
        (rect.width, rect.height),
        (init.width, init.height),
        "{context}: the rectangle must cover the framebuffer announced in ServerInit"
    );
    assert_eq!(
        rect.pixels.len(),
        (init.width as usize) * (init.height as usize) * 4,
        "{context}: Raw encoding must carry exactly 4 bytes per pixel"
    );
}

/// The RFB handshake, ServerInit geometry from the `width`/`height` startup parameters, and the
/// pixel format the server promises to send.
#[tokio::test]
async fn test_vnc_handshake_and_server_init() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via vnc with a 640x480 screen")
        .with_mock(|mock| {
            mock.on_instruction_containing("vnc")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "VNC",
                    "startup_params": {
                        "width": 640,
                        "height": 480,
                        "desktop_name": "NetGet Test Desktop"
                    },
                    "instruction": "Show a plain screen"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;

    let mut client = VncClient::connect(server.port).await?;
    client.handshake().await?;
    let init = client.initialize().await?;

    // Geometry comes from the startup parameters, not from a constant.
    assert_eq!(
        (init.width, init.height),
        (640, 480),
        "ServerInit must announce the requested framebuffer size"
    );
    assert_eq!(init.name, "NetGet Test Desktop");

    // The pixel format is the contract for every rectangle that follows: 32bpp little-endian
    // BGRX. A test that skipped this could not tell a correct frame from a byte-swapped one.
    assert_eq!(init.bits_per_pixel, 32, "server sends 32 bits per pixel");
    assert_eq!(init.depth, 24, "colour depth is 24");
    assert!(!init.big_endian, "server sends little-endian pixels");
    assert!(init.true_color, "server sends true colour");
    assert_eq!(
        (init.red_shift, init.green_shift, init.blue_shift),
        (16, 8, 0),
        "shifts must describe BGRX byte order"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The whole feature: the model draws the screen, input events reach the model, incremental
/// requests are held open until something changes, and clipboard text flows both ways.
///
/// LLM calls: 7 (startup, one full update, key down, key up, button press, cut text, second
/// full update). Pointer *movement* deliberately costs none.
#[tokio::test]
async fn test_vnc_llm_draws_screen_and_handles_input() -> E2EResult<()> {
    // Screen A: the first frame, drawn in answer to the first full update request.
    let screen_a_bg = (32, 64, 96);
    let screen_a_box = (240, 80, 40);
    // Screen B: drawn in answer to a key press, proving key events reach the model *and* that
    // a held incremental request is answered by the resulting redraw.
    let screen_b_bg = (12, 120, 60);

    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via vnc").with_mock(|mock| {
        // Event rules come first: rules are matched in order, and a rule keyed on the
        // instruction would otherwise answer network events with `open_server`.
        mock.on_event("vnc_framebuffer_update_request")
            .and_event_data_contains("first_request", "true")
            .respond_with_actions(json!([{
                "type": "vnc_render_display",
                "commands": [
                    {"type": "background", "color": "#204060"},
                    {"type": "rectangle", "x": 100, "y": 100, "width": 200, "height": 120,
                     "color": "#f05028", "filled": true}
                ]
            }]))
            .expect_calls(1)
            .and()
            .on_event("vnc_framebuffer_update_request")
            .and_event_data_contains("first_request", "false")
            .respond_with_actions(json!([{"type": "vnc_no_change"}]))
            .expect_calls(1)
            .and()
            .on_event("vnc_key_event")
            .and_event_data_contains("down", "true")
            .respond_with_actions(json!([{
                "type": "vnc_render_display",
                "commands": [{"type": "background", "color": "#0c783c"}]
            }]))
            .expect_calls(1)
            .and()
            .on_event("vnc_key_event")
            .and_event_data_contains("down", "false")
            .respond_with_actions(json!([{"type": "vnc_no_change"}]))
            .expect_calls(1)
            .and()
            .on_event("vnc_pointer_event")
            .respond_with_actions(json!([{"type": "vnc_no_change"}]))
            .expect_calls(1)
            .and()
            .on_event("vnc_client_cut_text")
            .respond_with_actions(json!([{
                "type": "vnc_set_clipboard",
                "text": "netget acknowledges"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("vnc")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "VNC",
                "instruction": "Draw the screen the tests ask for"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let mut client = VncClient::connect(server.port).await?;
    client.handshake().await?;
    let init = client.initialize().await?;

    // ---- 1. A full update request is answered by the model's drawing ----
    client
        .request_framebuffer_update(false, 0, 0, init.width, init.height)
        .await?;
    let frame = client.read_full_update("first full update").await?;
    assert_full_frame(&frame, &init, "first full update");
    assert_eq!(
        frame.rgb(10, 10),
        screen_a_bg,
        "the background must be the colour the model asked for, in the announced BGRX order"
    );
    assert_eq!(
        frame.rgb(200, 160),
        screen_a_box,
        "the rectangle the model asked for must be rasterised where it asked for it"
    );
    assert_eq!(
        frame.rgb(90, 90),
        screen_a_bg,
        "just outside the rectangle must still be the background"
    );

    // ---- 2. An incremental request is held open while nothing changes ----
    client
        .request_framebuffer_update(true, 0, 0, init.width, init.height)
        .await?;

    // ---- 3. A key press redraws, which answers the held request ----
    client.send_key_event(true, 97).await?; // 'a'
    let frame = client.read_full_update("after key press").await?;
    assert_full_frame(&frame, &init, "after key press");
    assert_eq!(
        frame.rgb(10, 10),
        screen_b_bg,
        "the key press must have reached the model and redrawn the screen"
    );

    // ---- 4. Input the model answers with vnc_no_change sends nothing ----
    client.send_key_event(false, 97).await?; // key release -> no_change
    client.send_pointer_event(0, 400, 300).await?; // movement -> no model call at all
    client.send_pointer_event(1, 400, 300).await?; // button press -> no_change

    // ---- 5. Clipboard: client -> model -> client ----
    client.send_cut_text("copied on the client").await?;
    // If any of step 4 had produced a frame it would arrive here first, and this read fails
    // with exactly that complaint.
    let clipboard = client.read_cut_text("after ClientCutText").await?;
    assert_eq!(
        clipboard, "netget acknowledges",
        "the server must push the clipboard text the model chose"
    );

    // ---- 6. A full request must be answered even when nothing changed ----
    client
        .request_framebuffer_update(false, 0, 0, init.width, init.height)
        .await?;
    let frame = client.read_full_update("second full update").await?;
    assert_full_frame(&frame, &init, "second full update");
    assert_eq!(
        frame.rgb(10, 10),
        screen_b_bg,
        "vnc_no_change must resend the last screen, not a blank or placeholder one"
    );

    let output = server.get_output().await;
    assert!(
        output
            .iter()
            .any(|line| line.contains("VNC PointerEvent: move to 400,300")),
        "pointer movement must still be reported even though it costs no model call; output \
         was:\n{}",
        output.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// When the model answers with nothing this protocol can use, the client gets the placeholder
/// screen — not silence, and not a screen that looks like content.
///
/// RFB has no "no answer" reply, so a client that asked for a full update and receives nothing
/// waits forever. Fail-closed here means saying so on screen.
#[tokio::test]
async fn test_vnc_placeholder_when_model_gives_no_usable_answer() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via vnc").with_mock(|mock| {
        mock.on_event("vnc_framebuffer_update_request")
            // A valid action, but not one that draws anything: the model answered without
            // deciding what is on screen.
            .respond_with_actions(json!([{
                "type": "show_message",
                "message": "I do not know what to draw"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("vnc")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "VNC",
                "instruction": "Draw something"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let mut client = VncClient::connect(server.port).await?;
    client.handshake().await?;
    let init = client.initialize().await?;

    client
        .request_framebuffer_update(false, 0, 0, init.width, init.height)
        .await?;
    let frame = client.read_full_update("placeholder").await?;
    assert_full_frame(&frame, &init, "placeholder");
    assert_eq!(
        frame.rgb(5, 5),
        (
            PLACEHOLDER_BACKGROUND.r,
            PLACEHOLDER_BACKGROUND.g,
            PLACEHOLDER_BACKGROUND.b
        ),
        "a client must get the placeholder screen when no answer usable by VNC arrived"
    );

    let output = server.get_output().await;
    assert!(
        output
            .iter()
            .any(|line| line.contains("produced no usable action")),
        "the server must report that the event went unanswered; output was:\n{}",
        output.join("\n")
    );
    // The model was reached and answered with nothing this protocol can use. That is its own
    // silence, not a backend failure, and the two must not share a log line.
    assert!(
        output
            .iter()
            .any(|line| line.contains("decision=model_silent")),
        "a model that answered with no usable action must be tagged decision=model_silent, \
         distinct from decision=fail_closed_llm_error; output was:\n{}",
        output.join("\n")
    );
    assert!(
        !output
            .iter()
            .any(|line| line.contains("decision=fail_closed_llm_error")),
        "the backend answered here, so nothing may be tagged as a backend failure; output \
         was:\n{}",
        output.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A backend failure and a model that said nothing both put the placeholder screen up, so RFB
/// itself cannot tell them apart — the log is the only place the distinction can live.
///
/// This forces `call_llm` into its `Err` arm the way `tests/server/cdp/e2e_test.rs` does: the
/// mock answers the event with something that is not an action at all, so the retry/repair loop
/// exhausts. The assertions are the pair that matters — the peer still gets a screen (RFB has
/// no "no answer" reply, so silence would hang the viewer), and the line carries
/// `decision=fail_closed_llm_error`, never `model_silent` or `model_answer`.
#[tokio::test]
async fn test_vnc_backend_failure_is_tagged_fail_closed() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via vnc").with_mock(|mock| {
        mock.on_instruction_containing("vnc")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "VNC",
                "instruction": "Draw something"
            }]))
            .expect_calls(1)
            .and()
            // Not JSON and not an action: the repair loop exhausts and `call_llm` returns Err.
            .on_event("vnc_framebuffer_update_request")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let mut client = VncClient::connect(server.port).await?;
    client.handshake().await?;
    let init = client.initialize().await?;

    client
        .request_framebuffer_update(false, 0, 0, init.width, init.height)
        .await?;
    let frame = client.read_full_update("backend failure").await?;
    assert_full_frame(&frame, &init, "backend failure");
    assert_eq!(
        frame.rgb(5, 5),
        (
            PLACEHOLDER_BACKGROUND.r,
            PLACEHOLDER_BACKGROUND.g,
            PLACEHOLDER_BACKGROUND.b
        ),
        "a full update must still be answered when the backend failed; RFB has no way to say \
         'no answer', so a viewer that gets nothing waits forever"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;

    let output = server.get_output().await;
    assert!(
        output
            .iter()
            .any(|line| line.contains("decision=fail_closed_llm_error")),
        "a backend failure must be tagged decision=fail_closed_llm_error so it is \
         distinguishable from a model that answered with nothing; output was:\n{}",
        output.join("\n")
    );
    assert!(
        !output.iter().any(|line| {
            line.contains("vnc_framebuffer_update_request") && line.contains("decision=model_")
        }),
        "a backend failure must never be reported as a decision the model took; output was:\n{}",
        output.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
