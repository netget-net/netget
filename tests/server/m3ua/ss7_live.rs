//! Real-peer plumbing for the SS7 suites (Linux): a live loopback capture read back by tshark,
//! and the jSS7 driver. Shared by `tests/server/m3ua` and `tests/client/m3ua`.
#![allow(dead_code)]

use std::time::Duration;

/// One frame of a live capture as tshark read it.
#[derive(Debug, Clone)]
pub struct Frame {
    pub number: u32,
    pub src_port: u16,
    pub ppids: Vec<u32>,
    pub streams: Vec<u32>,
    /// M3UA message class of each message in the frame (1 is Transfer).
    pub classes: Vec<u32>,
    /// Wireshark's Info column: it names every MAP/CAP component
    /// (`invoke sendRoutingInfoForSM`, `returnResultLast anyTimeInterrogation`).
    pub info: String,
    pub experts: Vec<(u32, String)>,
}

/// A live `dumpcap` on loopback for one real-peer test. Missing dumpcap, or no permission to
/// capture, is a failure rather than a skip.
pub struct LiveCapture {
    probe: std::net::UdpSocket,
    probe_port: u16,
    seen: std::sync::Arc<std::sync::Mutex<String>>,
    child: tokio::process::Child,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl LiveCapture {
    /// Capture SCTP to or from any of `ports`. Returns once dumpcap has demonstrably captured a
    /// packet: "Capturing on" is printed before the capture is live, so a UDP probe (in the
    /// filter, never dissected as SS7) is sent until dumpcap counts one.
    pub async fn start(ports: &[u16]) -> LiveCapture {
        use tokio::io::AsyncReadExt;
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let probe_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sctp: Vec<String> = ports.iter().map(|p| format!("sctp port {p}")).collect();
        let bpf = format!("{} or udp port {probe_port}", sctp.join(" or "));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ss7.pcapng");
        let mut child = tokio::process::Command::new("dumpcap")
            .args(["-i", "lo", "-f", &bpf, "-w"])
            .arg(&path)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "dumpcap is required for the live SS7 capture ({e}): sudo apt-get install \
                     tshark, and give it capture rights (sudo setcap \
                     cap_net_raw,cap_net_admin=eip $(command -v dumpcap)). This test fails \
                     rather than skips."
                )
            });
        let mut stderr = child.stderr.take().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
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
            "dumpcap never captured on lo: {}",
            seen.lock().unwrap()
        );
        LiveCapture {
            probe,
            probe_port,
            seen,
            child,
            path,
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

    /// Stop the capture once a probe shows dumpcap read past everything sent so far, and return
    /// every M3UA frame tshark dissected in it.
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
        let out = std::process::Command::new("tshark")
            .arg("-r")
            .arg(&self.path)
            .args([
                "-n",
                "-Y",
                "m3ua",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-e",
                "frame.number",
                "-e",
                "sctp.srcport",
                "-e",
                "sctp.data_payload_proto_id",
                "-e",
                "sctp.data_sid",
                "-e",
                "m3ua.message_class",
                "-e",
                "_ws.col.info",
                "-e",
                "_ws.expert.severity",
                "-e",
                "_ws.expert.message",
            ])
            .output()
            .expect("tshark is required: sudo apt-get install tshark");
        assert!(
            out.status.success(),
            "tshark: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let nums = |s: &str| -> Vec<u32> {
            s.split(',')
                .filter_map(|x| {
                    let x = x.trim();
                    x.strip_prefix("0x")
                        .map(|h| u32::from_str_radix(h, 16).ok())
                        .unwrap_or_else(|| x.parse().ok())
                })
                .collect()
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let c: Vec<&str> = line.split('\t').collect();
                let get = |i: usize| c.get(i).copied().unwrap_or("");
                let sevs = nums(get(6));
                let msgs: Vec<String> = get(7).split(',').map(str::to_string).collect();
                Frame {
                    number: get(0).parse().unwrap_or(0),
                    src_port: get(1).split(',').next().unwrap_or("0").parse().unwrap_or(0),
                    ppids: nums(get(2)),
                    streams: nums(get(3)),
                    classes: nums(get(4)),
                    info: get(5).to_string(),
                    experts: sevs
                        .iter()
                        .enumerate()
                        .map(|(i, s)| (*s, msgs.get(i).cloned().unwrap_or_default()))
                        .collect(),
                }
            })
            .collect()
    }
}

/// Assert a live capture is clean SIGTRAN: no Warn-or-worse expert info, PPID 3 on every DATA
/// chunk, NetGet's management on stream 0 and its DATA off stream 0, and NetGet's frames (from
/// `netget_port`) name each of `netget_sent` in Wireshark's Info column.
pub fn assert_capture(frames: &[Frame], netget_port: u16, netget_sent: &[&str]) {
    assert!(
        !frames.is_empty(),
        "the capture holds no M3UA frames at all"
    );
    for f in frames {
        for (sev, msg) in &f.experts {
            assert!(
                *sev < 0x0060_0000,
                "tshark flags frame {}: {msg} ({frames:#?})",
                f.number
            );
        }
        assert!(
            f.ppids.iter().all(|p| *p == 3),
            "frame {} has PPIDs {:?}",
            f.number,
            f.ppids
        );
        if f.src_port == netget_port {
            for (class, sid) in f.classes.iter().zip(&f.streams) {
                if *class == 1 {
                    assert_ne!(*sid, 0, "NetGet sent DATA on stream 0: {f:?}");
                } else {
                    assert_eq!(*sid, 0, "NetGet sent management off stream 0: {f:?}");
                }
            }
        }
    }
    for needle in netget_sent {
        assert!(
            frames
                .iter()
                .any(|f| f.src_port == netget_port && f.info.contains(needle)),
            "no frame from NetGet (port {netget_port}) shows {needle:?}: {frames:#?}"
        );
    }
}

/// The jSS7 driver jar: NETGET_JSS7_PEER, printed by tests/server/m3ua/install_peers.py.
pub fn jss7_command() -> std::process::Command {
    let jar = std::env::var("NETGET_JSS7_PEER").unwrap_or_else(|_| {
        panic!(
            "NETGET_JSS7_PEER is not set. Build the jSS7 peer with: sudo apt-get install \
             openjdk-17-jdk-headless maven && python3 tests/server/m3ua/install_peers.py <dir>, \
             then export what it prints. This test fails rather than skips."
        )
    });
    let mut c = std::process::Command::new("java");
    // The driver's arguments carry UTF-8 text (SMS, USSD); under the POSIX locale the JVM reads
    // argv as ASCII and every non-ASCII character arrives as replacement characters.
    c.env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .arg("-Dsun.jnu.encoding=UTF-8")
        .arg("-Dfile.encoding=UTF-8")
        .arg("-jar")
        .arg(jar);
    c
}

pub const JSS7_HINT: crate::helpers::real_server::InstallHint =
    crate::helpers::real_server::InstallHint {
        brew: "(none: the jSS7 peer is exercised over SCTP, which macOS lacks)",
        apt:
            "openjdk-17-jdk-headless maven, then python3 tests/server/m3ua/install_peers.py <dir> \
              (builds the jSS7 8.0.112 driver and prints NETGET_JSS7_PEER)",
    };

pub const OSMO_STP_HINT: crate::helpers::real_server::InstallHint =
    crate::helpers::real_server::InstallHint {
        brew: "(none: osmo-stp needs SCTP, which macOS lacks)",
        apt: "osmo-stp",
    };

/// A free port for the peer's own end of an association.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The value of `key=` on a driver line.
pub fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Decode the driver's percent-encoded text.
pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// A running osmo-stp with its config in a temporary directory.
pub struct OsmoStp {
    process: crate::helpers::real_server::ToolProcess,
    _dir: tempfile::TempDir,
}

impl OsmoStp {
    pub fn lines(&self) -> Vec<String> {
        self.process.lines()
    }
}

/// Start osmo-stp with `cs7` (a `cs7 instance` block), logging to stderr and its VTY on a free
/// port so parallel tests do not collide on 4239. Returns once its M3UA server is bound.
pub async fn osmo_stp(cs7: &str) -> OsmoStp {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osmo-stp.cfg");
    let config = format!(
        "log stderr\n logging filter all 1\n logging color 0\n logging print category 1\n \
         logging level lss7 info\n logging level linp error\nline vty\n bind 127.0.0.1 {}\n{cs7}",
        free_port()
    );
    std::fs::write(&path, config).unwrap();
    let mut cmd = std::process::Command::new("osmo-stp");
    cmd.arg("-c").arg(&path);
    let process = crate::helpers::real_server::ToolProcess::spawn(cmd, "osmo-stp", OSMO_STP_HINT)
        .unwrap_or_else(|e| panic!("{e}"));
    process
        .wait_for_line("its M3UA server", Duration::from_secs(20), |l| {
            l.contains("binding m3ua Server")
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    OsmoStp { process, _dir: dir }
}
