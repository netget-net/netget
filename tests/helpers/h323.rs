//! Shared harness for the H.323 suites (server and client): in-process NetGet gatekeepers,
//! endpoints and clients with a python policy standing in for the model, and a live loopback
//! capture dissected by tshark's h225, q931 and h245 dissectors.
#![allow(dead_code)]

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// The RasMessage CHOICE index of each RAS message (H.225.0), as tshark's `h225.RasMessage`
/// prints it.
pub mod ras {
    pub const GRQ: u32 = 0;
    pub const GCF: u32 = 1;
    pub const GRJ: u32 = 2;
    pub const RRQ: u32 = 3;
    pub const RCF: u32 = 4;
    pub const RRJ: u32 = 5;
    pub const URQ: u32 = 6;
    pub const UCF: u32 = 7;
    pub const ARQ: u32 = 9;
    pub const ACF: u32 = 10;
    pub const ARJ: u32 = 11;
    pub const DRQ: u32 = 15;
    pub const DCF: u32 = 16;
    pub const LRQ: u32 = 18;
    pub const LCF: u32 = 19;
}

/// The h323-message-body CHOICE index of each call-signalling UUIE.
pub mod body {
    pub const SETUP: u32 = 0;
    pub const CALL_PROCEEDING: u32 = 1;
    pub const CONNECT: u32 = 2;
    pub const ALERTING: u32 = 3;
    pub const RELEASE_COMPLETE: u32 = 5;
    pub const FACILITY: u32 = 6;
    pub const EMPTY: u32 = 8;
}

/// A collected log of everything an instance printed.
fn log_sink() -> (mpsc::UnboundedSender<String>, Arc<Mutex<Vec<String>>>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    (tx, log)
}

/// A running in-process H.323 server and everything it printed.
pub struct Node {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Node {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub fn addr(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    pub async fn wait_for_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !self.log_text().contains(needle) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Every event of `kind` the server raised: what the model was shown.
    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Server(self.id.as_u32()), kind).await
    }

    pub async fn wait_for_events(&self, kind: &str, n: usize) -> Vec<Value> {
        wait_events(
            &self.state,
            AccessLogOwner::Server(self.id.as_u32()),
            kind,
            n,
        )
        .await
    }
}

async fn events_of(state: &AppState, owner: AccessLogOwner, kind: &str) -> Vec<Value> {
    let mut v: Vec<Value> = state
        .list_access_logs_for(Some(owner), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
    v.into_iter().map(|e| e["request"].clone()).collect()
}

async fn wait_events(state: &AppState, owner: AccessLogOwner, kind: &str, n: usize) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let v = events_of(state, owner, kind).await;
        if v.len() >= n || tokio::time::Instant::now() > deadline {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A python policy as the routing table's single `*` rule.
pub fn script(code: &str) -> Option<Vec<Value>> {
    Some(vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": code}
    })])
}

/// Start `protocol` ("H323" or "H323-Gatekeeper") in-process on `port` (0 for any).
/// `handlers` is the routing table; `None` sends every event to the model at `llm`.
pub async fn start_server(
    protocol: &str,
    port: u16,
    handlers: Option<Vec<Value>>,
    params: Value,
    llm: &str,
) -> Node {
    let state = AppState::new_with_options(false, llm.into());
    state
        .set_llm_client(netget::llm::OllamaClient::new(llm))
        .await;
    state.set_ollama_model(Some("mock-model".into())).await;
    let (tx, log) = log_sink();
    let id = ServerForm {
        protocol: protocol.into(),
        port: Some(port),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an H.323 node".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the H.323 server never reported its address");
    Node {
        state,
        id,
        port,
        log,
    }
}

/// A NetGet H.323 client and everything it printed.
pub struct ClientNode {
    pub state: AppState,
    pub id: ClientId,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl ClientNode {
    pub fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    pub async fn events(&self, kind: &str) -> Vec<Value> {
        events_of(&self.state, AccessLogOwner::Client(self.id.as_u32()), kind).await
    }

    pub async fn wait_for_events(&self, kind: &str, n: usize) -> Vec<Value> {
        wait_events(
            &self.state,
            AccessLogOwner::Client(self.id.as_u32()),
            kind,
            n,
        )
        .await
    }
}

pub async fn start_client(
    remote: &str,
    handlers: Option<Vec<Value>>,
    params: Value,
    llm: &str,
) -> Result<ClientNode, String> {
    let state = AppState::new_with_options(false, llm.into());
    state
        .set_llm_client(netget::llm::OllamaClient::new(llm))
        .await;
    state.set_ollama_model(Some("mock-model".into())).await;
    let (tx, log) = log_sink();
    let id = ClientForm {
        protocol: "H323".into(),
        remote_addr: Some(remote.into()),
        instruction: Some("Be an H.323 endpoint".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(llm), tx)
    .await
    .map_err(|e| format!("{e:#}"))?;
    Ok(ClientNode { state, id, log })
}

/// A free loopback port, for a peer told where to listen.
pub fn free_port(udp: bool) -> u16 {
    if udp {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

// ---------------------------------------------------------------------------------------------
// Live capture
// ---------------------------------------------------------------------------------------------

/// One H.323 frame as tshark dissected it out of a live capture.
#[derive(Debug, Clone, Default)]
pub struct Frame {
    pub number: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// RasMessage index, for RAS.
    pub ras: Option<u32>,
    /// h323-message-body index, for call signalling.
    pub body: Option<u32>,
    pub q931_type: Option<u32>,
    /// H.245 messages tunnelled in it: (request|response|command|indication, index).
    pub h245: Vec<(String, u32)>,
    pub cause: Option<u32>,
    pub experts: Vec<(u32, String)>,
}

fn loopback() -> &'static str {
    if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    }
}

/// A live `dumpcap` on loopback for one test. Needs capture permission: root, `setcap
/// cap_net_raw,cap_net_admin=eip` on dumpcap (what CI does), or membership of `access_bpf` on
/// macOS. Missing dumpcap or permission is a failure, not a skip.
pub struct LiveCapture {
    probe: std::net::UdpSocket,
    probe_port: u16,
    seen: Arc<Mutex<String>>,
    child: tokio::process::Child,
    path: std::path::PathBuf,
    udp_ports: Vec<u16>,
    _dir: tempfile::TempDir,
}

impl LiveCapture {
    /// Capture RAS on `udp_ports` and call signalling on `tcp_ports`, both directions.
    pub async fn start(udp_ports: &[u16], tcp_ports: &[u16]) -> LiveCapture {
        use tokio::io::AsyncReadExt;
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let probe_port = free_port(true);
        let mut terms: Vec<String> = udp_ports.iter().map(|p| format!("udp port {p}")).collect();
        terms.extend(tcp_ports.iter().map(|p| format!("tcp port {p}")));
        terms.push(format!("udp port {probe_port}"));
        let bpf = terms.join(" or ");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h323.pcapng");
        let mut child = tokio::process::Command::new("dumpcap")
            .args(["-i", loopback(), "-f", &bpf, "-w"])
            .arg(&path)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "dumpcap is required for the live H.323 capture ({e}): sudo apt-get install \
                     tshark, and give it capture rights (sudo setcap \
                     cap_net_raw,cap_net_admin=eip $(command -v dumpcap)). This test fails \
                     rather than skips."
                )
            });
        let mut stderr = child.stderr.take().unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let sink = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let ready = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let _ = probe.send_to(b"capture-probe", ("127.0.0.1", probe_port));
                if seen.lock().unwrap().contains("Packets:") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            ready.is_ok(),
            "dumpcap never captured on loopback: {}",
            seen.lock().unwrap()
        );
        LiveCapture {
            probe,
            probe_port,
            seen,
            child,
            path,
            udp_ports: udp_ports.to_vec(),
            _dir: dir,
        }
    }

    fn reported(&self) -> u64 {
        let text = self.seen.lock().unwrap().clone();
        text.rsplit("Packets: ")
            .next()
            .map(|t| {
                t.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .and_then(|d| d.parse().ok())
            .unwrap_or(0)
    }

    /// Stop the capture (after a probe shows dumpcap read past everything before it) and
    /// dissect every H.323 frame in it.
    pub async fn finish(mut self) -> Vec<Frame> {
        let before = self.reported();
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let _ = self
                    .probe
                    .send_to(b"capture-probe", ("127.0.0.1", self.probe_port));
                tokio::time::sleep(Duration::from_millis(200)).await;
                if self.reported() > before {
                    return;
                }
            }
        })
        .await;
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGINT,
            );
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        // For a human: NETGET_H323_PCAP_DIR keeps every capture, to open in Wireshark.
        if let Ok(dir) = std::env::var("NETGET_H323_PCAP_DIR") {
            let name = format!("h323-{}-{}.pcapng", std::process::id(), self.probe_port);
            let _ = std::fs::copy(&self.path, std::path::Path::new(&dir).join(name));
        }
        let mut cmd = std::process::Command::new("tshark");
        cmd.arg("-r").arg(&self.path).arg("-n");
        for p in &self.udp_ports {
            cmd.arg("-d").arg(format!("udp.port=={p},h225"));
        }
        // No decode-as for the call-signalling ports: Wireshark finds Q.931 in TPKT on any TCP
        // port by itself, and `-d tcp.port==N,tpkt` picks the TPKT heuristic meant for RDP,
        // after which nothing is dissected as H.225.0 at all.
        cmd.args([
            "-Y",
            "h225 || q931 || h245",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=a",
            "-e",
            "frame.number",
            "-e",
            "udp.srcport",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "tcp.dstport",
            "-e",
            "h225.RasMessage",
            "-e",
            "h225.h323_message_body",
            "-e",
            "q931.message_type",
            "-e",
            "h245.request",
            "-e",
            "h245.response",
            "-e",
            "h245.command",
            "-e",
            "h245.indication",
            "-e",
            "q931.cause_value",
            "-e",
            "_ws.expert.severity",
            "-e",
            "_ws.expert.message",
        ]);
        let out = cmd
            .output()
            .expect("tshark is required: sudo apt-get install tshark");
        assert!(
            out.status.success(),
            "tshark: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        parse_frames(&String::from_utf8_lossy(&out.stdout))
    }
}

fn parse_frames(text: &str) -> Vec<Frame> {
    let nums =
        |s: &str| -> Vec<u64> { s.split(',').filter_map(|x| x.trim().parse().ok()).collect() };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split('\t').collect();
            let get = |i: usize| c.get(i).copied().unwrap_or("");
            let first = |i: usize| nums(get(i)).first().map(|v| *v as u32);
            let port = |a: usize, b: usize| first(a).or(first(b)).unwrap_or(0) as u16;
            let mut h245 = Vec::new();
            for (i, kind) in [
                (8, "request"),
                (9, "response"),
                (10, "command"),
                (11, "indication"),
            ] {
                for v in nums(get(i)) {
                    h245.push((kind.to_string(), v as u32));
                }
            }
            let sevs = nums(get(13));
            let msgs: Vec<String> = get(14).split(',').map(|s| s.to_string()).collect();
            Frame {
                number: get(0).parse().unwrap_or(0),
                src_port: port(1, 2),
                dst_port: port(3, 4),
                ras: first(5),
                body: first(6),
                q931_type: first(7),
                h245,
                cause: first(12),
                experts: sevs
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (*s as u32, msgs.get(i).cloned().unwrap_or_default()))
                    .collect(),
            }
        })
        .collect()
}

/// Every frame dissected without a Warn-or-worse expert info.
pub fn assert_clean(frames: &[Frame]) {
    assert!(
        !frames.is_empty(),
        "the capture holds no H.323 frames at all"
    );
    for f in frames {
        for (sev, msg) in &f.experts {
            assert!(
                *sev < 0x0060_0000,
                "tshark flags frame {}: {msg}\n{frames:#?}",
                f.number
            );
        }
    }
}

/// Every frame NetGet sent (from one of `netget_ports`) dissected without a Warn-or-worse
/// expert info. A third-party peer's frames are dissected too — they are what NetGet decoded —
/// but not judged: Ubuntu 24.04's tshark 4.2.2 trips its own `recursion_depth <= 100`
/// assertion on H323Plus's RAS messages (their H.460 generic data), which says nothing about
/// NetGet.
pub fn assert_netget_clean(frames: &[Frame], netget_ports: &[u16]) {
    assert!(
        !frames.is_empty(),
        "the capture holds no H.323 frames at all"
    );
    let ours: Vec<&Frame> = frames
        .iter()
        .filter(|f| netget_ports.contains(&f.src_port))
        .collect();
    assert!(
        !ours.is_empty(),
        "no frame from NetGet ({netget_ports:?}) in the capture: {frames:#?}"
    );
    for f in ours {
        for (sev, msg) in &f.experts {
            assert!(
                *sev < 0x0060_0000,
                "tshark flags NetGet's frame {}: {msg}\n{frames:#?}",
                f.number
            );
        }
    }
}

/// Every frame sent *to* one of `peer_ports` — what NetGet's client sent a third-party server —
/// dissected without a Warn-or-worse expert info.
pub fn assert_clean_towards(frames: &[Frame], peer_ports: &[u16]) {
    let ours: Vec<&Frame> = frames
        .iter()
        .filter(|f| peer_ports.contains(&f.dst_port))
        .collect();
    assert!(
        !ours.is_empty(),
        "no frame towards {peer_ports:?} in the capture: {frames:#?}"
    );
    for f in ours {
        for (sev, msg) in &f.experts {
            assert!(
                *sev < 0x0060_0000,
                "tshark flags NetGet's frame {}: {msg}\n{frames:#?}",
                f.number
            );
        }
    }
}

/// The RAS message indices sent from `port`, in order.
pub fn ras_from(frames: &[Frame], port: u16) -> Vec<u32> {
    frames
        .iter()
        .filter(|f| f.src_port == port)
        .filter_map(|f| f.ras)
        .collect()
}

/// The h323-message-body indices sent from `port`, in order.
pub fn bodies_from(frames: &[Frame], port: u16) -> Vec<u32> {
    frames
        .iter()
        .filter(|f| f.src_port == port)
        .filter_map(|f| f.body)
        .collect()
}

/// The tunnelled H.245 messages sent from `port`.
pub fn h245_from(frames: &[Frame], port: u16) -> Vec<(String, u32)> {
    frames
        .iter()
        .filter(|f| f.src_port == port)
        .flat_map(|f| f.h245.clone())
        .collect()
}
