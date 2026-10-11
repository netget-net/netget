//! NetGet's RDP client against two independent RDP servers, each failing rather than skipping
//! when absent:
//!
//! - **FreeRDP's shadow server** (`freerdp-shadow-cli3`, `apt-get install freerdp3-shadow-x11`)
//!   sharing an Xvfb display, with **NLA**: CredSSP/NTLM against an NTLM SAM file. The model
//!   clicks into an `xev` window on that display and types; `xev` prints what the X server
//!   received, so the model's input is read back from the far side of the wire. The screen
//!   colours are checked against the root colour `xsetroot` painted.
//! - **xrdp** 0.9 (`apt-get install xrdp`) with **TLS** security, run from a temp-dir
//!   `xrdp.ini` on a loopback port. Its login screen is drawn by xrdp itself; its background
//!   colour, set in that `xrdp.ini`, is checked in the decoded framebuffer.
//!
//! No LLM calls: a script handler plays the model.
use crate::helpers::real_server::{run_tool, InstallHint, RealServer, ToolProcess};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use tokio::sync::mpsc;

const XVFB: InstallHint = InstallHint {
    brew: "xquartz (Xvfb has no Homebrew formula; run this test on Linux)",
    apt: "xvfb",
};
const X11_UTILS: InstallHint = InstallHint {
    brew: "xquartz (run this test on Linux)",
    apt: "x11-utils x11-xserver-utils",
};
const SHADOW: InstallHint = InstallHint {
    brew: "freerdp (the shadow server needs X11; run this test on Linux)",
    apt: "freerdp3-shadow-x11",
};
const XRDP: InstallHint = InstallHint {
    brew: "xrdp has no Homebrew formula; run this test on Linux",
    apt: "xrdp",
};

/// The root window's colour on the shadowed display.
const ROOT: &str = "#20a040";
const PASSWORD: &str = "s3cret-Rdp";
/// NT hash of PASSWORD: MD4 over its UTF-16LE bytes, as
/// `printf s3cret-Rdp | iconv -t UTF-16LE | openssl dgst -md4 -provider legacy -provider default`
/// prints it.
const NT_HASH: &str = "6805728d07a2721919ed119faba06304";

/// An Xvfb display of its own: `-displayfd` makes the server pick a free number and print it.
async fn display() -> (ToolProcess, String) {
    let mut cmd = Command::new("Xvfb");
    // -noreset: otherwise the server resets, root colour and all, when xsetroot disconnects.
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

async fn client(addr: &str, params: Value, handlers: Vec<Value>) -> (AppState, ClientId) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "RDP".into(),
        remote_addr: Some(addr.into()),
        instruction: Some("Use the remote desktop".into()),
        event_handlers: Some(handlers),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect");
    (state, id)
}

async fn wait_event(state: &AppState, id: ClientId, event_type: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == event_type)
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event_type} event"))
}

async fn read_screen(state: &AppState, id: ClientId, grid: u64) -> Value {
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"rdp_read_screen","grid":grid,"settle_ms":700}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let ClientSendOutcome::Executed { detail } = outcome else {
        panic!("{outcome:?}")
    };
    serde_json::from_str(&detail).unwrap()
}

/// On connect: click into the xev window, type, press Enter.
const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='rdp_connected': a=[{'type':'rdp_mouse','x':300,'y':250},{'type':'rdp_type','text':'Hi!'},{'type':'rdp_keys','keys':['enter']}]
print(json.dumps({'actions':a}))"#;

/// Whether two #rrggbb colours are within `tolerance` on every channel. The shadow server's
/// codec converts through YCoCg and comes back a unit off (#20a040 arrives as #209f40);
/// xrdp's login screen is exact.
fn near(color: &Value, want: &str, tolerance: i32) -> bool {
    let rgb = |s: &str| -> Option<[i32; 3]> {
        let s = s.strip_prefix('#')?;
        let c = |i: usize| i32::from_str_radix(s.get(i..i + 2)?, 16).ok();
        Some([c(0)?, c(2)?, c(4)?])
    };
    match (color.as_str().and_then(rgb), rgb(want)) {
        (Some(a), Some(b)) => a.iter().zip(b).all(|(x, y)| (x - y).abs() <= tolerance),
        _ => false,
    }
}

/// The KeyPress keysym names xev printed, in order.
fn key_presses(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_press = false;
    for l in lines {
        if l.starts_with("KeyPress event") {
            in_press = true;
        } else if l.starts_with("KeyRelease event") || l.ends_with(" event, serial") {
            in_press = false;
        }
        if in_press {
            if let Some(rest) = l.split("keysym 0x").nth(1) {
                // "48, H), same_screen YES,"
                if let Some(name) = rest.split([',', ')']).nth(1) {
                    out.push(name.trim().to_string());
                }
                in_press = false;
            }
        }
    }
    out
}

#[tokio::test]
async fn nla_to_freerdp_shadow_server_types_and_clicks_into_xev() {
    let (_xvfb, dpy) = display().await;
    let mut set_root = Command::new("xsetroot");
    set_root.env("DISPLAY", &dpy).args(["-solid", ROOT]);
    run_tool(set_root, "xsetroot", X11_UTILS)
        .await
        .expect("xsetroot");
    let mut xev_cmd = Command::new("xev");
    xev_cmd
        .env("DISPLAY", &dpy)
        .args(["-geometry", "400x300+100+100"]);
    let xev = ToolProcess::spawn(xev_cmd, "xev", X11_UTILS).expect("xev");
    xev.wait_for_line("its first event", Duration::from_secs(10), |l| {
        l.starts_with("MapNotify") || l.starts_with("Expose")
    })
    .await
    .expect("xev window mapped");

    let shadow = RealServer::builder("freerdp-shadow-cli3", SHADOW)
        .config_file("sam", &format!("alice::{}:{NT_HASH}:::\n", "0".repeat(32)))
        .env("DISPLAY", &dpy)
        .args([
            "/port:{port}",
            "/bind-address:127.0.0.1",
            "/sec:nla",
            "/sam-file:{dir}/sam",
        ])
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .expect("start freerdp-shadow-cli3");

    let (state, id) = client(
        &shadow.addr(),
        json!({"username":"alice","password":PASSWORD,"security":"nla","width":1024,"height":768}),
        vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}})],
    )
    .await;
    let connected = wait_event(&state, id, "rdp_connected").await;
    assert_eq!(connected["security"], "nla", "{connected}");
    assert_eq!(
        (connected["width"].as_u64(), connected["height"].as_u64()),
        (Some(1024), Some(768)),
        "{connected}"
    );

    // The click reached the X server at the point the model named.
    xev.wait_for_line("the model's click", Duration::from_secs(20), |l| {
        l.contains("root:(300,250)") && !l.is_empty()
    })
    .await
    .expect("xev saw no event at the click point");
    xev.wait_for_line("a ButtonPress", Duration::from_secs(10), |l| {
        l.starts_with("ButtonPress event")
    })
    .await
    .expect("xev saw no ButtonPress");
    // And the keystrokes, in order: shift+h, i, shift+1, Return.
    let want = ["Shift_L", "H", "i", "Shift_L", "exclam", "Return"];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let presses = loop {
        let presses = key_presses(&xev.lines());
        if presses.len() >= want.len() || tokio::time::Instant::now() > deadline {
            break presses;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(presses, want, "xev:\n{}", xev.lines().join("\n"));

    // The screen: the root colour everywhere the xev window is not.
    let screen = read_screen(&state, id, 8).await;
    assert!(near(&screen["dominant_color"], ROOT, 2), "{screen}");
    assert!(screen["dominant_share"].as_f64().unwrap() > 0.7, "{screen}");
    assert!(near(&screen["grid"][7][7], ROOT, 2), "{screen}");
    // The xev window (100..500, 100..400) is white: cell (2, 2) of 8 lies inside it.
    assert!(near(&screen["grid"][2][2], "#ffffff", 2), "{screen}");
    assert!(screen["graphics_updates"].as_u64().unwrap() > 0, "{screen}");

    // A disconnect logs off and closes.
    let outcome = state
        .send_to_client(id, json!({"type":"disconnect"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn nla_with_a_wrong_password_is_refused() {
    let (_xvfb, dpy) = display().await;
    let shadow = RealServer::builder("freerdp-shadow-cli3", SHADOW)
        .config_file("sam", &format!("alice::{}:{NT_HASH}:::\n", "0".repeat(32)))
        .env("DISPLAY", &dpy)
        .args([
            "/port:{port}",
            "/bind-address:127.0.0.1",
            "/sec:nla",
            "/sam-file:{dir}/sam",
        ])
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .expect("start freerdp-shadow-cli3");
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let err = ClientForm {
        protocol: "RDP".into(),
        remote_addr: Some(shadow.addr()),
        instruction: Some(String::new()),
        startup_params: Some(json!({"username":"alice","password":"wrong","security":"nla"})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect_err("a wrong password must not connect");
    assert!(
        format!("{err:#}").contains("connection sequence"),
        "{err:#}"
    );
}

const LOGIN_BG: &str = "#3060c0";

fn xrdp_ini() -> String {
    format!(
        "[Globals]\nini_version=1\nfork=false\nport=tcp://127.0.0.1:{{port}}\nuse_vsock=false\n\
security_layer=tls\ncrypt_level=none\ncertificate={{dir}}/cert.pem\nkey_file={{dir}}/key.pem\n\
ssl_protocols=TLSv1.2, TLSv1.3\nautorun=\nallow_channels=true\nmax_bpp=32\nuse_fastpath=both\n\
ls_top_window_bg_color={}\nblue={}\nls_width=350\nls_height=430\nls_bg_color=dedede\n\
ls_logo_filename=\n\
[Logging]\nLogFile={{dir}}/xrdp.log\nLogLevel=DEBUG\nEnableSyslog=false\nEnableConsole=true\nConsoleLevel=DEBUG\n\
[Channels]\nrdpdr=false\nrdpsnd=false\ndrdynvc=false\ncliprdr=false\nrail=false\nxrdpvr=false\n\
[Xorg]\nname=Xorg\nlib=libxup.so\nusername=ask\npassword=ask\nip=127.0.0.1\nport=-1\ncode=20\n",
        LOGIN_BG.trim_start_matches('#'),
        LOGIN_BG.trim_start_matches('#'),
    )
}

#[tokio::test]
async fn tls_to_xrdp_reads_the_login_screen() {
    let xrdp = RealServer::builder("xrdp", XRDP)
        .config_file("xrdp.ini", &xrdp_ini())
        .setup_command(
            "openssl",
            InstallHint {
                brew: "openssl",
                apt: "openssl",
            },
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-keyout",
                "{dir}/key.pem",
                "-out",
                "{dir}/cert.pem",
            ],
        )
        .args(["--nodaemon", "--config", "{dir}/xrdp.ini"])
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .expect("start xrdp");
    let silent = vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})];
    // No username: xrdp shows its own login screen rather than trying to log on.
    let (state, id) = client(
        &xrdp.addr(),
        json!({"security":"tls","width":800,"height":600}),
        silent,
    )
    .await;
    let connected = wait_event(&state, id, "rdp_connected").await;
    assert_eq!(connected["security"], "tls", "{connected}");
    assert_eq!(connected["width"], 800, "{connected}");

    let screen = read_screen(&state, id, 4).await;
    // The login window sits in the middle; the corners are xrdp's background colour.
    assert_eq!(
        screen["dominant_color"],
        LOGIN_BG,
        "{screen}\n{}",
        xrdp.log()
    );
    assert_eq!(screen["grid"][0][0], LOGIN_BG, "{screen}");
    assert_eq!(screen["grid"][3][3], LOGIN_BG, "{screen}");
    // The login box in the middle is drawn in ls_bg_color.
    assert_eq!(screen["grid"][1][1], "#dedede", "no login window: {screen}");
    assert_eq!(screen["grid"][2][2], "#dedede", "no login window: {screen}");
}
