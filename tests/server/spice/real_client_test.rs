//! NetGet's SPICE server against independent clients, each failing rather than skipping when
//! absent:
//!
//! - **spice-gtk's `spicy-screenshot`** (`apt-get install spice-client-gtk`) links the main and
//!   display channels with the password, renders the display with spice-common's canvas and
//!   writes it out as a PPM. The model's panel and background are read back from that file
//!   pixel by pixel, and the wire it crossed is dissected by tshark's spice dissector.
//! - **spice-gtk's `spicy`** under **Xvfb**, with **xdotool** typing into its window and
//!   clicking it: the keys and the click arrive at the model as `spice_key_event` and
//!   `spice_mouse_event`, and the model's redraw for the key `x` reaches spicy's screen, which
//!   `spicy-screenshot` reads back from a second session.
//! - **spice-html5** (`apt-get install spice-html5 websockify`), an independent JavaScript
//!   implementation, in headless Chrome through websockify: the same screen is read off its
//!   canvas, and a key typed into the page reaches the model.
//!
//! No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, PASSWORD};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::real_server::{run_tool, InstallHint, ToolProcess};
use crate::helpers::recording_relay;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const SPICE_GTK: InstallHint = InstallHint {
    brew: "spice-gtk (spicy and spicy-screenshot need X11 here; run this test on Linux)",
    apt: "spice-client-gtk",
};
const XVFB: InstallHint = InstallHint {
    brew: "xquartz (Xvfb has no Homebrew formula; run this test on Linux)",
    apt: "xvfb",
};
const XDOTOOL: InstallHint = InstallHint {
    brew: "xdotool (needs X11; run this test on Linux)",
    apt: "xdotool",
};
const HTML5: InstallHint = InstallHint {
    brew: "node websockify (Homebrew has no spice-html5: point NETGET_SPICE_HTML5_DIR at a checkout of gitlab.freedesktop.org/spice/spice-html5, and NETGET_CHROME at Chrome)",
    apt: "spice-html5 websockify (with node 22, and NETGET_CHROME naming Chrome)",
};

/// A decoded binary PPM (P6, maxval 255).
struct Ppm {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
}

impl Ppm {
    fn read(path: &Path) -> Ppm {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // Four whitespace-separated header tokens, then exactly one whitespace byte.
        let mut fields = Vec::new();
        let mut i = 0;
        while fields.len() < 4 {
            while bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            while !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            fields.push(String::from_utf8_lossy(&bytes[start..i]).to_string());
        }
        assert_eq!(fields[0], "P6", "not a binary PPM");
        assert_eq!(fields[3], "255");
        let width: u32 = fields[1].parse().unwrap();
        let height: u32 = fields[2].parse().unwrap();
        let rgb = bytes[i + 1..].to_vec();
        assert_eq!(rgb.len(), (width * height * 3) as usize, "truncated PPM");
        Ppm { width, height, rgb }
    }

    fn at(&self, x: u32, y: u32) -> [u8; 3] {
        let i = ((y * self.width + x) * 3) as usize;
        [self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]]
    }
}

fn spice_gtk_version() -> String {
    let out = Command::new("spicy-screenshot")
        .arg("--version")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
        })
        .unwrap_or_default();
    out.trim().to_string()
}

/// `spicy-screenshot` against `port`, writing `out`. Bounded: a client that never finishes is
/// a failure, not a hang.
async fn screenshot(port: u16, password: &str, out: &Path) -> Result<String, String> {
    let mut cmd = Command::new("spicy-screenshot");
    cmd.args([
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-w",
        password,
        "-o",
    ])
    .arg(out);
    match tokio::time::timeout(
        Duration::from_secs(90),
        run_tool(cmd, "spicy-screenshot", SPICE_GTK),
    )
    .await
    {
        Ok(Ok(stdout)) => Ok(stdout),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("spicy-screenshot did not finish in 90 s".into()),
    }
}

fn assert_models_screen(shot: &Ppm, panel: [u8; 3]) {
    assert_eq!((shot.width, shot.height), (support::WIDTH, support::HEIGHT));
    let centre = shot.at(
        support::PANEL_X + support::PANEL_W / 2,
        support::PANEL_Y + support::PANEL_H / 2,
    );
    assert_eq!(centre, panel, "the panel spice-gtk drew is not the model's");
    assert_eq!(
        shot.at(support::WIDTH - 5, support::HEIGHT - 5),
        support::BACKGROUND,
        "the background spice-gtk drew is not the model's"
    );
    // The welcome line: white glyph pixels in the text band, none in the background below it.
    let text_band = (14..48)
        .flat_map(|y| (20..300).map(move |x| (x, y)))
        .filter(|(x, y)| shot.at(*x, *y).iter().all(|c| *c > 200))
        .count();
    assert!(
        text_band > 100,
        "no text in the band the model wrote it ({text_band} white pixels)"
    );
}

#[tokio::test]
async fn spicy_screenshot_renders_the_models_screen_and_tshark_reads_the_wire() {
    let server = support::start(support::policy(), support::params()).await;
    let (relay, streams) = recording_relay::tcp_relay(server.addr()).await;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("shot.ppm");
    screenshot(relay.port(), PASSWORD, &out)
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", server.log_text()));
    println!("spice-gtk: {}", spice_gtk_version());
    let shot = Ppm::read(&out);
    assert_models_screen(&shot, support::PANEL);
    assert_eq!(server.events("spice_connection_request").await.len(), 1);

    // Every channel spicy-screenshot opened, both directions, through tshark's dissector.
    let streams = streams.lock().unwrap().clone();
    assert!(streams.len() >= 2, "expected main and display channels");
    for rec in streams {
        let chunks = rec.lock().unwrap().clone();
        let mut oracle = PcapOracle::tcp("spice");
        for (to_server, bytes) in &chunks {
            oracle = if *to_server {
                oracle.to_server(bytes)
            } else {
                oracle.from_server(bytes)
            };
        }
        oracle.assert_clean();
    }
}

#[tokio::test]
async fn spicy_screenshot_with_a_wrong_password_is_refused() {
    let server = support::start(support::policy(), support::params()).await;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("shot.ppm");
    let refused = screenshot(server.port, "not-it", &out).await;
    assert!(
        refused.is_err(),
        "spicy-screenshot succeeded with a wrong password"
    );
    assert!(!out.exists());
    assert!(
        server
            .wait_for_log("decision=protocol_reject_bad_ticket")
            .await
    );
    assert!(server.events("spice_connection_request").await.is_empty());
}

/// An Xvfb display of its own: `-displayfd` makes the server pick a free number and print it.
async fn display() -> (ToolProcess, String) {
    let mut cmd = Command::new("Xvfb");
    cmd.args([
        "-displayfd",
        "1",
        "-screen",
        "0",
        "1024x768x24",
        "-nolisten",
        "tcp",
        "-noreset",
    ]);
    let xvfb = ToolProcess::spawn(cmd, "Xvfb", XVFB).expect("start Xvfb");
    let n = xvfb
        .wait_for_line("its display number", Duration::from_secs(20), |l| {
            !l.is_empty() && l.chars().all(|c| c.is_ascii_digit())
        })
        .await
        .expect("Xvfb display");
    (xvfb, format!(":{n}"))
}

async fn xdotool(dpy: &str, args: &[&str]) -> String {
    let mut cmd = Command::new("xdotool");
    cmd.env("DISPLAY", dpy).args(args);
    tokio::time::timeout(Duration::from_secs(30), run_tool(cmd, "xdotool", XDOTOOL))
        .await
        .expect("xdotool hung")
        .unwrap_or_else(|e| panic!("xdotool {args:?}: {e}"))
}

#[tokio::test]
async fn spicy_delivers_typed_keys_and_clicks_to_the_model() {
    let server = support::start(support::policy(), support::params()).await;
    let (_xvfb, dpy) = display().await;
    let mut cmd = Command::new("spicy");
    cmd.env("DISPLAY", &dpy)
        .env("GDK_BACKEND", "x11")
        .env("NO_AT_BRIDGE", "1")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &server.port.to_string(),
            "-w",
            PASSWORD,
        ]);
    let spicy = ToolProcess::spawn(cmd, "spicy", SPICE_GTK).expect("start spicy");
    assert!(
        server.wait_for_log("SPICE inputs channel linked").await,
        "spicy never linked its inputs channel: {}\n{}",
        spicy.lines().join("\n"),
        server.log_text()
    );
    assert!(server.wait_for_log("SPICE display channel linked").await);
    // spicy's window is the one that maps last; give it the keyboard and the pointer.
    let windows = xdotool(
        &dpy,
        &["search", "--sync", "--onlyvisible", "--class", "spicy"],
    )
    .await;
    let window = windows
        .lines()
        .last()
        .expect("spicy has no visible window")
        .trim()
        .to_string();
    xdotool(&dpy, &["windowfocus", "--sync", &window]).await;
    let geometry = xdotool(&dpy, &["getwindowgeometry", "--shell", &window]).await;
    println!("spicy window {window}: {geometry}");
    // Click in the middle of the window, then type.
    let (w, h) = geometry
        .lines()
        .fold((0, 0), |(w, h), l| match l.split_once('=') {
            Some(("WIDTH", v)) => (v.parse().unwrap_or(w), h),
            Some(("HEIGHT", v)) => (w, v.parse().unwrap_or(h)),
            _ => (w, h),
        });
    let (cx, cy) = ((w / 2).to_string(), (h / 2).to_string());
    xdotool(&dpy, &["mousemove", "--window", &window, &cx, &cy]).await;
    // Without --window: xdotool then uses XTEST, which GTK treats as real input, rather than
    // XSendEvent, whose synthetic events GTK ignores.
    xdotool(&dpy, &["click", "1"]).await;
    let clicks = server.wait_for_events("spice_mouse_event", 1).await;
    assert!(
        !clicks.is_empty(),
        "the click never reached the model: {}\n{}",
        spicy.lines().join("\n"),
        server.log_text()
    );
    assert_eq!(clicks[0]["request"]["button"], "left");
    let (x, y) = (
        clicks[0]["request"]["x"].as_u64().unwrap(),
        clicks[0]["request"]["y"].as_u64().unwrap(),
    );
    assert!(x < support::WIDTH as u64 && y < support::HEIGHT as u64);
    xdotool(&dpy, &["type", "--delay", "120", "qx"]).await;
    let keys = server.wait_for_events("spice_key_event", 2).await;
    let typed: Vec<String> = keys
        .iter()
        .map(|k| k["request"]["key"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(typed, ["q", "x"], "keys at the model: {typed:?}");

    // The model's answer to `x` is on spicy's screen: the X server's own pixels, read back.
    let want = support::PANEL_AFTER_X;
    let mut seen = 0;
    for _ in 0..40 {
        seen = root_window(&dpy).await.count(want);
        if seen > 20_000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        seen > 20_000,
        "spicy's window never showed the model's green panel ({seen} pixels of {want:?})"
    );
}

/// The root window of an X display as `xwd` dumps it (X11 `XWDFileHeader`, ZPixmap).
struct Xwd {
    pixels: Vec<[u8; 3]>,
}

impl Xwd {
    fn parse(b: &[u8]) -> Xwd {
        let word =
            |i: usize| u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        let header_size = word(0) as usize;
        assert_eq!(word(2), 2, "xwd: not a ZPixmap");
        let (width, height) = (word(4) as usize, word(5) as usize);
        let lsb_first = word(7) == 0;
        let bytes = word(11) as usize / 8;
        assert!(
            bytes == 3 || bytes == 4,
            "xwd: {} bits per pixel",
            bytes * 8
        );
        let line = word(12) as usize;
        let masks = [word(14), word(15), word(16)];
        let ncolors = word(19) as usize;
        let data = &b[header_size + ncolors * 12..];
        let mut pixels = Vec::with_capacity(width * height);
        for y in 0..height {
            for x in 0..width {
                let i = y * line + x * bytes;
                let mut q = [0u8; 4];
                q[..bytes].copy_from_slice(&data[i..i + bytes]);
                let p = if lsb_first {
                    u32::from_le_bytes(q)
                } else {
                    u32::from_be_bytes(q) >> (8 * (4 - bytes))
                };
                let channel = |m: u32| ((p & m) >> m.trailing_zeros()) as u8;
                pixels.push([channel(masks[0]), channel(masks[1]), channel(masks[2])]);
            }
        }
        Xwd { pixels }
    }

    fn count(&self, rgb: [u8; 3]) -> usize {
        self.pixels.iter().filter(|p| **p == rgb).count()
    }
}

async fn root_window(dpy: &str) -> Xwd {
    let mut cmd = Command::new("xwd");
    cmd.env("DISPLAY", dpy).args(["-root", "-silent"]);
    let out = tokio::task::spawn_blocking(move || cmd.output())
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("xwd (apt-get install x11-apps): {e}"));
    assert!(
        out.status.success(),
        "xwd: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Xwd::parse(&out.stdout)
}

/// spice-html5's files: `NETGET_SPICE_HTML5_DIR`, else where Debian's package puts them.
fn spice_html5_dir() -> std::path::PathBuf {
    let dir = std::env::var("NETGET_SPICE_HTML5_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| "/usr/share/spice-html5".into());
    assert!(
        dir.join("spice_auto.html").is_file(),
        "spice-html5 not found at {} — install it (`sudo apt-get install spice-html5`) or point \
         NETGET_SPICE_HTML5_DIR at a checkout of https://gitlab.freedesktop.org/spice/spice-html5. \
         It is the second independent client the server's evidence rests on, so its absence \
         FAILS this test rather than skipping it.",
        dir.display()
    );
    dir
}

#[tokio::test]
async fn spice_html5_in_chrome_renders_the_models_screen_and_types_into_it() {
    let server = support::start(support::policy(), support::params()).await;
    let html5 = spice_html5_dir();
    let web = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cmd = Command::new("websockify");
    cmd.arg("--web")
        .arg(&html5)
        .arg(format!("127.0.0.1:{web}"))
        .arg(format!("127.0.0.1:{}", server.port));
    let _websockify = ToolProcess::spawn(cmd, "websockify", HTML5).expect("start websockify");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", web))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/server/spice/html5.mjs");
    let mut cmd = Command::new("node");
    cmd.arg(&script).args([
        web.to_string(),
        PASSWORD.to_string(),
        (support::PANEL_X + support::PANEL_W / 2).to_string(),
        (support::PANEL_Y + support::PANEL_H / 2).to_string(),
        (support::WIDTH - 5).to_string(),
        (support::HEIGHT - 5).to_string(),
    ]);
    let out = tokio::time::timeout(Duration::from_secs(180), run_tool(cmd, "node", HTML5))
        .await
        .expect("the spice-html5 driver hung")
        .unwrap_or_else(|e| panic!("{e}"));
    let line = out.lines().last().unwrap_or_default();
    let r: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {out}"));
    assert_eq!(r["ok"], true, "{r}\n{}", server.log_text());
    assert_eq!(
        r["size"],
        serde_json::json!([support::WIDTH, support::HEIGHT]),
        "{r}"
    );
    assert_eq!(r["panel"], serde_json::json!(support::PANEL), "{r}");
    assert_eq!(r["corner"], serde_json::json!(support::BACKGROUND), "{r}");
    let keys = server.wait_for_events("spice_key_event", 1).await;
    assert_eq!(
        keys.first().map(|k| k["request"]["key"].clone()),
        Some("x".into()),
        "{r}\n{}",
        server.log_text()
    );
    assert_eq!(r["after"], serde_json::json!(support::PANEL_AFTER_X), "{r}");
}
