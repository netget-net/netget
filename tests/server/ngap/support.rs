//! Shared helpers for the NGAP suites: SCTP framing for the pcap oracle, and the lab transport's
//! length prefix.
#![allow(dead_code)]

use crate::helpers::pcap_oracle::PcapOracle;

/// CRC-32C (Castagnoli), as SCTP's checksum (RFC 4960 appendix B). Bitwise and slow, which is
/// fine for a test, and written here so the checksum is not computed by the code under test.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One SCTP packet (RFC 4960 section 3) carrying `payload` in a single unfragmented DATA chunk
/// with PPID 60 — the IP payload the oracle's `ip_proto(.., 132)` framing wants.
pub fn sctp_data_packet(src: u16, dst: u16, tsn: u32, stream: u16, payload: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0x00, 0x03]; // DATA, flags B|E
    chunk.extend_from_slice(&((16 + payload.len()) as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&stream.to_be_bytes());
    chunk.extend_from_slice(&0u16.to_be_bytes()); // stream sequence
    chunk.extend_from_slice(&60u32.to_be_bytes()); // PPID: NGAP
    chunk.extend_from_slice(payload);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    let mut packet = Vec::new();
    packet.extend_from_slice(&src.to_be_bytes());
    packet.extend_from_slice(&dst.to_be_bytes());
    packet.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // verification tag
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&chunk);
    let crc = crc32c(&packet);
    // The CRC is stored little-endian (RFC 4960 appendix B).
    packet[8..12].copy_from_slice(&crc.to_le_bytes());
    packet
}

/// Run tshark's ngap dissector over PDUs that crossed the wire, `true` for those NetGet sent.
/// Each PDU becomes its own SCTP DATA chunk with PPID 60, which is how a real capture looks.
pub fn assert_ngap_clean(pdus: &[(bool, Vec<u8>)]) {
    let mut oracle = PcapOracle::ip_proto("ngap", 132);
    for (i, (from_netget, pdu)) in pdus.iter().enumerate() {
        let (src, dst) = if *from_netget {
            (38412, 40001)
        } else {
            (40001, 38412)
        };
        let stream = if netget::server::ngap::codec::is_ue_associated(pdu) {
            1
        } else {
            0
        };
        oracle = oracle.frame(&sctp_data_packet(src, dst, 1 + i as u32, stream, pdu));
    }
    oracle.assert_clean();
}

/// The lab transport's framing: a 4-octet big-endian length, then the PDU.
pub fn lab_frame(pdu: &[u8]) -> Vec<u8> {
    let mut out = (pdu.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(pdu);
    out
}

/// Read one lab-framed PDU.
pub async fn read_lab(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= 65_535, "NetGet framed a {len}-octet PDU");
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Hex without separators, for literal vectors.
pub fn unhex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(clean).expect("test vector is hex")
}

/// One NGAP frame as tshark dissected it out of a live capture.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub number: u32,
    pub src_port: u16,
    /// Every NGAP procedure code in the frame (SCTP may bundle several messages).
    pub procedures: Vec<u8>,
    /// The PDU choice of each: 0 initiating, 1 successful, 2 unsuccessful.
    pub pdu_kinds: Vec<u8>,
    pub ppids: Vec<u32>,
    pub experts: Vec<(u32, String)>,
}

/// One frame's 5G NAS as tshark's nas-5gs dissector read it.
#[derive(Debug, Clone)]
pub struct NasFrame {
    pub number: u32,
    pub src_port: u16,
    pub security_headers: Vec<u8>,
    pub mm_types: Vec<u8>,
    pub sm_types: Vec<u8>,
    pub experts: Vec<u32>,
}

/// A live `dumpcap` on loopback for the duration of a real-peer test (Linux only). Requires
/// capture permission: root, or `setcap cap_net_raw,cap_net_admin=eip` on dumpcap, which the CI
/// job does. Missing dumpcap or permission is a failure, not a skip.
#[cfg(target_os = "linux")]
pub struct LiveCapture {
    probe: std::net::UdpSocket,
    probe_port: u16,
    seen: std::sync::Arc<std::sync::Mutex<String>>,
    child: tokio::process::Child,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

#[cfg(target_os = "linux")]
impl LiveCapture {
    /// Capture SCTP to or from `port` on loopback. Returns once dumpcap has demonstrably captured
    /// a packet: "Capturing on" is printed before the capture is live, and an NG Setup that
    /// follows within a millisecond was observed to go unrecorded. So a UDP probe datagram (in
    /// the filter, never dissected as NGAP) is sent until dumpcap reports a packet.
    pub async fn start(port: u16) -> LiveCapture {
        use tokio::io::AsyncReadExt;
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let probe_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let bpf = format!("sctp port {port} or udp port {probe_port}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ngap.pcapng");
        let mut child = tokio::process::Command::new("dumpcap")
            .args(["-i", "lo", "-f", &bpf, "-w"])
            .arg(&path)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "dumpcap is required for the live NGAP capture ({e}): sudo apt-get install \
                     tshark, and give it capture rights (sudo setcap \
                     cap_net_raw,cap_net_admin=eip $(command -v dumpcap)). This test fails \
                     rather than skips."
                )
            });
        // dumpcap's packet counter is redrawn with carriage returns, so stderr is read raw.
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
        let ready = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let _ = probe.send_to(b"capture-probe", ("127.0.0.1", probe_port));
                if seen.lock().unwrap().contains("Packets:") {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

    /// The packet count dumpcap last reported.
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

    /// Stop the capture and dissect every NGAP frame and, separately, every 5G NAS message in it.
    /// NAS protected with NEA0 is read through (`nas-5gs.null_decipher`), so the messages inside
    /// security headers are named too.
    pub async fn finish_with_nas(self) -> (Vec<CapturedFrame>, Vec<NasFrame>) {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("ngap.pcapng");
        // `finish` deletes the capture with its directory; keep a copy for the second pass.
        let frames = self.finish_keeping(Some(&keep)).await;
        let out = std::process::Command::new("tshark")
            .arg("-r")
            .arg(&keep)
            .args([
                "-n",
                "-o",
                "nas-5gs.null_decipher:TRUE",
                "-Y",
                "nas-5gs",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=a",
                "-e",
                "frame.number",
                "-e",
                "sctp.srcport",
                "-e",
                "nas-5gs.security_header_type",
                "-e",
                "nas-5gs.mm.message_type",
                "-e",
                "nas-5gs.sm.message_type",
                "-e",
                "_ws.expert.severity",
            ])
            .output()
            .expect("tshark is required: sudo apt-get install tshark");
        assert!(
            out.status.success(),
            "tshark: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let nums = |s: &str| -> Vec<u64> {
            s.split(',')
                .filter_map(|x| {
                    let x = x.trim();
                    x.strip_prefix("0x")
                        .map(|h| u64::from_str_radix(h, 16).ok())
                        .unwrap_or_else(|| x.parse().ok())
                })
                .collect()
        };
        let nas = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let c: Vec<&str> = line.split('\t').collect();
                let get = |i: usize| c.get(i).copied().unwrap_or("");
                NasFrame {
                    number: get(0).parse().unwrap_or(0),
                    src_port: get(1).split(',').next().unwrap_or("0").parse().unwrap_or(0),
                    security_headers: nums(get(2)).into_iter().map(|v| v as u8).collect(),
                    mm_types: nums(get(3)).into_iter().map(|v| v as u8).collect(),
                    sm_types: nums(get(4)).into_iter().map(|v| v as u8).collect(),
                    experts: nums(get(5)).into_iter().map(|v| v as u32).collect(),
                }
            })
            .collect();
        (frames, nas)
    }

    /// Stop the capture and dissect every NGAP frame in it.
    ///
    /// SIGINT stops dumpcap at once, and packets still in the kernel's capture block are lost —
    /// observed as the last NGAP messages of a test going missing. So a probe datagram is sent
    /// first and the capture is stopped only once dumpcap's count shows it read past it.
    pub async fn finish(self) -> Vec<CapturedFrame> {
        self.finish_keeping(None).await
    }

    async fn finish_keeping(mut self, keep: Option<&std::path::Path>) -> Vec<CapturedFrame> {
        let before = self.reported();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let _ = self
                    .probe
                    .send_to(b"capture-probe", ("127.0.0.1", self.probe_port));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), self.child.wait()).await;
        if let Some(k) = keep {
            std::fs::copy(&self.path, k).expect("copying the capture");
        }
        let out = std::process::Command::new("tshark")
            .arg("-r")
            .arg(&self.path)
            .args([
                "-n",
                "-Y",
                "ngap",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-e",
                "frame.number",
                "-e",
                "sctp.srcport",
                "-e",
                "ngap.procedureCode",
                "-e",
                "ngap.NGAP_PDU",
                "-e",
                "sctp.data_payload_proto_id",
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
        parse_fields(&String::from_utf8_lossy(&out.stdout))
    }
}

fn parse_fields(text: &str) -> Vec<CapturedFrame> {
    let nums =
        |s: &str| -> Vec<u64> { s.split(',').filter_map(|x| x.trim().parse().ok()).collect() };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split('\t').collect();
            let get = |i: usize| c.get(i).copied().unwrap_or("");
            let sevs = nums(get(5));
            let msgs: Vec<String> = get(6).split(',').map(|s| s.to_string()).collect();
            CapturedFrame {
                number: get(0).parse().unwrap_or(0),
                src_port: get(1).split(',').next().unwrap_or("0").parse().unwrap_or(0),
                procedures: nums(get(2)).into_iter().map(|v| v as u8).collect(),
                pdu_kinds: nums(get(3)).into_iter().map(|v| v as u8).collect(),
                ppids: nums(get(4)).into_iter().map(|v| v as u32).collect(),
                experts: sevs
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (*s as u32, msgs.get(i).cloned().unwrap_or_default()))
                    .collect(),
            }
        })
        .collect()
}

/// Assert a live capture is clean NGAP: every frame dissected without a Warn-or-worse expert
/// info, every DATA chunk carried PPID 60, and the frames NetGet sent (from `netget_port`) include
/// each `(procedure, pdu kind)` in `netget_sent`.
pub fn assert_capture(frames: &[CapturedFrame], netget_port: u16, netget_sent: &[(u8, u8)]) {
    assert!(
        !frames.is_empty(),
        "the capture holds no NGAP frames at all"
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
            f.ppids.iter().all(|p| *p == 60),
            "frame {} has PPIDs {:?}",
            f.number,
            f.ppids
        );
    }
    for (code, kind) in netget_sent {
        assert!(
            frames.iter().any(|f| f.src_port == netget_port
                && f.procedures.iter().zip(&f.pdu_kinds).any(|(c, k)| c == code && k == kind)),
            "no frame from NetGet (port {netget_port}) carries procedure {code} kind {kind}: {frames:#?}"
        );
    }
}

/// NetGet's user plane sends a session's downlink to UDP port 2152 of the gNB's address, so a lab
/// gNB on loopback has to own 127.0.0.1:2152 (macOS has no other 127/8 address to spread over).
/// Every lab test that binds it holds this first, so parallel tests take turns instead of failing
/// to bind.
pub static GTPU_2152: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
