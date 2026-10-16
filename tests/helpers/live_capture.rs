//! A real capture on a real interface, judged by tshark — for the protocols whose bytes only
//! exist on a link (PROFINET's DCP and cyclic frames), where `pcap_oracle`'s synthesised
//! framing cannot stand in.
//!
//! `tshark -i <iface> -w <file>` runs for the length of the test; afterwards every packet
//! NetGet sent (selected by its source MAC) is checked: no Expert Info at Warn or above, and
//! the caller names the protocol fields that must have been read. Packets from the peer are
//! in the capture as context — a stateful dissector needs the request to read the response —
//! and are not judged; they are the peer's business. Needs root (or capture rights) and
//! tshark; neither is a skip.
#![allow(dead_code)]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Expert severity at which a packet fails (PI_WARN).
const SEV_WARN: u64 = 0x0060_0000;

pub struct LiveCapture {
    child: Child,
    pub path: PathBuf,
    _dir: tempfile::TempDir,
}

impl LiveCapture {
    /// Start capturing on `iface`; returns once tshark says it is capturing.
    pub fn start(iface: &str) -> LiveCapture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.pcapng");
        let mut child = Command::new("tshark")
            .args(["-n", "-q", "-i", iface, "-w"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "cannot run tshark ({e}): apt-get install tshark (or brew install wireshark)"
                )
            });
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut seen = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(l) if l.contains("Capturing on") => break,
                Ok(l) => seen.push(l),
                Err(_) if Instant::now() > deadline => {
                    let _ = child.kill();
                    panic!(
                        "tshark never started capturing on {iface}: {}",
                        seen.join("\n")
                    )
                }
                Err(_) => {
                    if let Ok(Some(st)) = child.try_wait() {
                        panic!(
                            "tshark exited {st} before capturing on {iface}: {}",
                            seen.join("\n")
                        )
                    }
                }
            }
        }
        LiveCapture {
            child,
            path,
            _dir: dir,
        }
    }

    /// Wait until the capture file holds a packet from `from` whose `field` contains `needle` —
    /// the writer buffers, so the last packets of a test reach the file a moment after they
    /// cross the wire. Returns whether it appeared within `secs`.
    pub fn wait_for(&self, from: &str, field: &str, needle: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.fields(&[field]).iter().any(|r| {
                r[0].eq_ignore_ascii_case(from) && r.get(1).is_some_and(|v| v.contains(needle))
            }) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        false
    }

    /// Stop the capture (SIGINT, so the file is complete) and return its path.
    pub fn stop(&mut self) -> &Path {
        // SAFETY: kill(2) on our own child's pid.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGINT);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return &self.path;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        &self.path
    }

    /// Read `fields` for every packet: one row per packet, each cell as `-T fields` prints it
    /// (repeated occurrences joined by `,`). `eth.src` is always the first column.
    pub fn fields(&self, fields: &[&str]) -> Vec<Vec<String>> {
        let mut cmd = Command::new("tshark");
        cmd.arg("-r").arg(&self.path).args([
            "-n",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=a",
            "-e",
            "eth.src",
        ]);
        for f in fields {
            cmd.arg("-e").arg(f);
        }
        let out = cmd.output().expect("tshark");
        assert!(
            out.status.success(),
            "tshark -r failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }

    /// Every packet whose source MAC is `ours` must carry no Expert Info at Warn or above.
    /// Returns the protocol chains of those packets.
    pub fn assert_clean_from(&self, ours: &str) -> Vec<String> {
        self.assert_clean_from_allowing(ours, &[])
    }

    /// As [`assert_clean_from`](Self::assert_clean_from), except for Warn-level messages
    /// containing one of `allowed` — for what NetGet is required to copy from the peer's own
    /// frame (an ESC returns a master's frame with the master's source address, so a master
    /// that uses a group address, as SOEM does by default, gets it back). Say why at the call
    /// site.
    pub fn assert_clean_from_allowing(&self, ours: &str, allowed: &[&str]) -> Vec<String> {
        let rows = self.fields(&[
            "frame.number",
            "frame.protocols",
            "_ws.expert.severity",
            "_ws.expert.message",
        ]);
        let mut chains = Vec::new();
        let mut failures = Vec::new();
        for r in &rows {
            if !r[0].eq_ignore_ascii_case(ours) {
                continue;
            }
            chains.push(r.get(2).cloned().unwrap_or_default());
            let sevs: Vec<u64> = r
                .get(3)
                .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
                .unwrap_or_default();
            let warns = sevs.iter().filter(|s| **s >= SEV_WARN).count();
            let messages = r.get(4).map(String::as_str).unwrap_or("");
            let excused: usize = allowed.iter().map(|a| messages.matches(a).count()).sum();
            if warns > excused {
                failures.push(format!(
                    "packet #{} ({}): {}",
                    r[1],
                    r.get(2).map(String::as_str).unwrap_or(""),
                    r.get(4).map(String::as_str).unwrap_or("")
                ));
            }
        }
        assert!(!chains.is_empty(), "no packet from {ours} in the capture");
        assert!(
            failures.is_empty(),
            "tshark found problems in NetGet's packets:\n{}",
            failures.join("\n")
        );
        chains
    }
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
