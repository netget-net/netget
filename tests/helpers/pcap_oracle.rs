//! The pcap oracle — an **independent** decoder for the bytes NetGet puts on the wire.
//!
//! Every other assertion in this suite is NetGet agreeing with itself, or with one
//! third-party client that can agree with one bug. `tshark` is neither: it is a
//! spec-literate dissector for ~109 of the protocols in this registry, written by
//! people who read the RFCs, and it is already installed. Point it at what a server
//! emitted and it will say whether the bytes are the protocol they claim to be.
//!
//! # How it works
//!
//! The test captures what NetGet wrote **from its own socket** — no capture
//! privilege, no interface, no `sudo`. It hands those bytes here. This module
//! fabricates the framing tshark needs around them (Ethernet + IPv4 + TCP/UDP, or a
//! raw Ethernet frame for the link-layer protocols), writes a one-off pcap file, and
//! runs `tshark` over it with a `-d` decode-as clause naming the dissector.
//!
//! The dissector name comes from [`netget::tui::wireshark::wire_for`], which is the
//! one place in this tree where every Wireshark name has already been checked against
//! this machine's `tshark -d` / `-Y`. Nothing here invents a name.
//!
//! # Why the pcap is hand-built rather than produced by `text2pcap`
//!
//! `text2pcap` can wrap a hex dump in Ethernet/IP/TCP headers (`-e`, `-i`, `-T`,
//! `-u`) and would have saved the fifty lines below. It was rejected for three
//! reasons, each of which showed up as a *false failure* while calibrating:
//!
//! 1. **TCP sequence numbers.** A stream needs per-direction sequence tracking or
//!    tshark reports retransmissions and out-of-order segments — Warn-severity
//!    expert info, i.e. exactly what this oracle fails on. Building the segments
//!    here means the numbers are right by construction.
//! 2. **A connection needs to open and close.** Several dissectors desegment until
//!    the stream ends: `whois`'s answer is dissected only once a FIN is seen (this
//!    was measured, not assumed — without the FIN the reply is plain `tcp`).
//!    `text2pcap` emits data segments only.
//! 3. **No second process, no hex round-trip.** The bytes are already in memory;
//!    formatting them as an offset-prefixed hex dump for another binary to parse
//!    back is a second place to get the offsets wrong.
//!
//! # What counts as a failure
//!
//! * any **Expert Info at Warn severity or above** on any packet — this is where
//!   `[Malformed Packet]`, bad checksums, "option longer than the package" and every
//!   wrong-flag-bit class live;
//! * the requested dissector **not appearing** in `frame.protocols` for a direction
//!   that carried bytes — i.e. tshark fell back to `data`/plain TCP because it could
//!   not make sense of the framing. This check has no expert info behind it at all:
//!   an 802.3 frame carrying an EtherType where the length belongs dissects as
//!   `eth:ethertype:data` in complete silence, and that is the shape of a defect
//!   Programme 2 found in CDP by hand.
//!
//! Everything below Warn is *reported but not failed*. That is deliberate: the
//! synthetic capture legitimately produces Chat and Note entries ("Connection
//! establish request (SYN)", "WHOIS has no mechanism to indicate encoding"), and a
//! noisy oracle is an ignored oracle.
//!
//! # `tshark` missing is a failure, not a skip
//!
//! This repository's own rule: a gate that prints `SKIP` and returns `Ok(())` is a
//! silent pass, and a silent pass is how four Beta ratings came to rest on nothing.
//! If `tshark` is not on `PATH` the oracle panics and says how to install it.

#![allow(dead_code)]

use netget::tui::wireshark::{wire_for, Transport};
use std::io::Write;
use std::process::Command;

// ---------------------------------------------------------------------------
// Expert Info severities, as Wireshark encodes them in `_ws.expert.severity`.
// ---------------------------------------------------------------------------

const SEV_COMMENT: u32 = 0x0010_0000;
const SEV_CHAT: u32 = 0x0020_0000;
const SEV_NOTE: u32 = 0x0040_0000;
/// The bar. Anything at or above this fails the oracle.
const SEV_WARN: u32 = 0x0060_0000;
const SEV_ERROR: u32 = 0x0080_0000;

fn severity_name(sev: u32) -> &'static str {
    match sev {
        s if s >= SEV_ERROR => "Error",
        s if s >= SEV_WARN => "Warn",
        s if s >= SEV_NOTE => "Note",
        s if s >= SEV_CHAT => "Chat",
        s if s >= SEV_COMMENT => "Comment",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Synthetic addressing. None of it is real; it exists so the dissector has a
// conversation to hang state on and so the two directions are distinguishable.
// ---------------------------------------------------------------------------

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const CLIENT_IP: [u8; 4] = [10, 11, 0, 1];
const SERVER_IP: [u8; 4] = [10, 11, 0, 2];
const CLIENT_PORT: u16 = 40001;

/// Used when the protocol has no canonical port worth naming. The `-d` clause
/// makes the dissector apply regardless; see [`canonical_port`] for why some
/// protocols still need their real one.
const SYNTHETIC_SERVER_PORT: u16 = 40404;

/// `DLT_EN10MB` — the only link type this module writes.
const LINKTYPE_ETHERNET: u32 = 1;

/// Which way a chunk of bytes travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Bytes the test's client wrote to NetGet.
    ToServer,
    /// Bytes NetGet wrote back — the ones the oracle is really here for.
    FromServer,
}

impl Dir {
    fn label(self) -> &'static str {
        match self {
            Dir::ToServer => "client→server",
            Dir::FromServer => "server→client",
        }
    }
}

/// How the captured bytes should be framed for tshark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// Payload of a TCP stream; two directions, handshake and FIN synthesised.
    Tcp,
    /// Payload of UDP datagrams; one packet per chunk.
    Udp,
    /// The caller supplies whole Ethernet frames — `lldp`, `cdp`, `stp`, `arp`.
    Ethernet,
    /// The caller supplies an IP payload for this protocol number — `icmp` (1),
    /// `igmp` (2), `ospf` (89), `vrrp` (112).
    IpProto(u8),
}

/// Some dissectors decide *request vs response* from which side holds the
/// protocol's registered port, and say so at Warn severity when neither does.
/// Modbus is the measured case: on an arbitrary port every packet raises
/// "Cannot classify packet type. Try setting Modbus/TCP Port preference…", and
/// on 502 the same bytes are clean. Since the port in this capture is a
/// fabrication either way, fabricate the one the dissector expects.
///
/// A protocol absent from this table gets [`SYNTHETIC_SERVER_PORT`], which is
/// fine for every dissector measured so far.
fn canonical_port(protocol: &str, framing: Framing) -> u16 {
    let name = protocol.trim().to_ascii_lowercase().replace('-', "_");
    let port = match name.as_str() {
        "http" | "hls" | "rss" | "npm" | "pypi" | "openapi" | "openai" | "ollama" | "s3"
        | "sqs" | "dynamo" | "kubernetes" | "webdav" | "jsonrpc" | "xmlrpc" | "oauth2"
        | "elasticsearch" | "couchdb" | "git" | "mcp" | "proxy" => 80,
        "dns" | "doh" => 53,
        "ntp" => 123,
        "snmp" => 161,
        "syslog" => 514,
        "radius" => 1812,
        "tftp" => 69,
        "coap" => 5683,
        "stun" | "turn" => 3478,
        "sip" => 5060,
        "h323" => 1720,
        "h323_gatekeeper" => 1719,
        "mdns" => 5353,
        "llmnr" => 5355,
        "ssdp" => 1900,
        "netbios_ns" => 137,
        "dhcp" | "bootp" => 67,
        "modbus" => 502,
        "redis" => 6379,
        "mysql" => 3306,
        "postgresql" => 5432,
        "mssql" => 1433,
        "mongodb" => 27017,
        "cassandra" => 9042,
        "memcached" => 11211,
        "zabbix" => 10051,
        "gearman" => 4730,
        "ldap" => 389,
        "imap" => 143,
        "pop3" => 110,
        "smtp" => 25,
        "nntp" => 119,
        "irc" => 6667,
        "telnet" => 23,
        "ftp" => 21,
        "ssh" => 22,
        "whois" => 43,
        "finger" => 79,
        "gopher" => 70,
        "mqtt" => 1883,
        "amqp" => 5672,
        "kafka" => 9092,
        "bgp" => 179,
        "rtsp" => 554,
        "vnc" => 5900,
        "socks5" => 1080,
        "bitcoin" => 8333,
        "nfs" => 2049,
        "smb" => 445,
        "rdp" => 3389,
        "zookeeper" => 2181,
        "openflow" => 6653,
        _ => return SYNTHETIC_SERVER_PORT,
    };
    // A UDP-only port number reused on TCP (or the reverse) is harmless — the
    // `-d` clause names the transport explicitly — so no filtering by framing is
    // needed. The parameter is kept so the table can grow one if it ever is.
    let _ = framing;
    port
}

/// One packet's worth of what tshark said about it.
#[derive(Debug, Clone)]
pub struct PacketVerdict {
    pub number: u32,
    /// `eth:ethertype:ip:udp:dns`
    pub protocols: String,
    /// Every expert info raised on this packet, most severe first.
    pub experts: Vec<(u32, String)>,
    pub dir: Option<Dir>,
}

/// What the oracle found. Returned by [`PcapOracle::check`]; most callers want
/// [`PcapOracle::assert_clean`] instead, which turns this into a panic with the
/// bytes attached.
#[derive(Debug, Clone)]
pub struct PcapReport {
    pub packets: Vec<PacketVerdict>,
    pub failures: Vec<String>,
    /// The `-d` clause used, if any.
    pub decode_as: Option<String>,
}

impl PcapReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Builder. See the module docs.
///
/// ```rust,ignore
/// PcapOracle::udp("dns")
///     .to_server(&query)
///     .from_server(&reply)
///     .assert_clean();
/// ```
pub struct PcapOracle {
    protocol: String,
    framing: Framing,
    port: u16,
    chunks: Vec<(Dir, Vec<u8>)>,
    /// Expert messages containing any of these substrings are demoted to
    /// informational. Use sparingly and say why at the call site.
    allowed: Vec<String>,
    require_dissector: bool,
    close_stream: bool,
    /// When set, the client's packets are in the capture only so the dissector has a
    /// request to key on; nothing about them is judged. See
    /// [`PcapOracle::peer_input_is_context`].
    peer_input_is_context: bool,
    /// Extra dissector names accepted in `frame.protocols`, for the handful of
    /// cases where the chain names a sub-dissector rather than the `-d` target.
    extra_names: Vec<String>,
}

impl PcapOracle {
    /// Bytes carried on a TCP stream. Supply each direction's bytes in the order
    /// they crossed the wire; adjacent chunks in the same direction are coalesced
    /// (TCP is a byte stream, so where the read boundaries fell is not a property
    /// of the protocol).
    pub fn tcp(protocol: &str) -> Self {
        Self::new(protocol, Framing::Tcp)
    }

    /// Bytes carried in UDP datagrams. Each chunk becomes exactly one datagram,
    /// because for UDP the boundary *is* a property of the protocol.
    pub fn udp(protocol: &str) -> Self {
        Self::new(protocol, Framing::Udp)
    }

    /// Whole Ethernet frames, destination MAC first — `lldp`, `cdp`, `stp`.
    pub fn ethernet(protocol: &str) -> Self {
        Self::new(protocol, Framing::Ethernet)
    }

    /// An IPv4 payload for the given protocol number — `icmp` (1), `igmp` (2),
    /// `ospf` (89), `vrrp` (112).
    pub fn ip_proto(protocol: &str, proto: u8) -> Self {
        Self::new(protocol, Framing::IpProto(proto))
    }

    fn new(protocol: &str, framing: Framing) -> Self {
        Self {
            port: canonical_port(protocol, framing),
            protocol: protocol.to_string(),
            framing,
            chunks: Vec::new(),
            allowed: Vec::new(),
            require_dissector: true,
            close_stream: true,
            peer_input_is_context: false,
            extra_names: Vec::new(),
        }
    }

    /// Override the fabricated server port. Only matters for dissectors that key
    /// on it; see [`canonical_port`].
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Bytes the test wrote to NetGet.
    //
    // `wrong_self_convention` reads `to_`/`from_` as conversions. Here they name a
    // *direction on the wire*, which is the whole vocabulary of this builder and reads
    // correctly at every call site; renaming them to satisfy the lint would make the
    // API worse.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_server(mut self, bytes: &[u8]) -> Self {
        self.chunks.push((Dir::ToServer, bytes.to_vec()));
        self
    }

    /// Bytes NetGet wrote back.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_server(mut self, bytes: &[u8]) -> Self {
        self.chunks.push((Dir::FromServer, bytes.to_vec()));
        self
    }

    /// A frame, for [`PcapOracle::ethernet`] / [`PcapOracle::ip_proto`].
    pub fn frame(mut self, bytes: &[u8]) -> Self {
        self.chunks.push((Dir::FromServer, bytes.to_vec()));
        self
    }

    /// Demote every expert info whose message contains `needle`. Each use needs a
    /// reason at the call site: this is how an oracle stops finding things.
    pub fn allow_expert_containing(mut self, needle: &str) -> Self {
        self.allowed.push(needle.to_string());
        self
    }

    /// Accept this name in `frame.protocols` as evidence the dissector engaged,
    /// in addition to the ones derived from `wire_for`.
    pub fn also_named(mut self, name: &str) -> Self {
        self.extra_names.push(name.to_string());
        self
    }

    /// Stop requiring that the dissector appear at all. Only correct where the
    /// protocol has no Wireshark dissector and the oracle is being used purely
    /// for the expert-info check.
    pub fn without_dissector_check(mut self) -> Self {
        self.require_dissector = false;
        self
    }

    /// Judge only the bytes NetGet emitted; treat the client's packets purely as
    /// context for the dissector.
    ///
    /// The request is normally worth judging too — it is free, and a stateful
    /// dissector needs it in the capture anyway. But for a **tunnelling** protocol the
    /// request carries a payload the *test* invented, and tshark recurses into it: a
    /// GTP-U G-PDU whose inner UDP destination port is 53 is handed to the DNS
    /// dissector, which then reports the one-byte fixture payload as a malformed DNS
    /// message. That is a true statement about the test's own bytes and says nothing
    /// about the server, so failing on it would be exactly the false positive that
    /// gets an oracle ignored.
    ///
    /// Use this only where the peer's payload is arbitrary user traffic, or where the peer
    /// is a third-party client whose own bytes the dissector flags in a field NetGet does
    /// not read — IBM's Linux CLI driver puts NUL bytes inside its DRDA EXTNAM, which
    /// tshark's ASCII view of the parameter reports as trailing stray characters
    /// (`tests/server/db2/real_client_test.rs`). It does not weaken the check on NetGet's
    /// own direction, which is what the oracle is for.
    pub fn peer_input_is_context(mut self) -> Self {
        self.peer_input_is_context = true;
        self
    }

    /// Do not synthesise the FIN exchange. The default is to send one, because
    /// dissectors that desegment to the end of the stream (`whois`) produce
    /// nothing without it.
    pub fn without_close(mut self) -> Self {
        self.close_stream = false;
        self
    }

    // -----------------------------------------------------------------------
    // Running
    // -----------------------------------------------------------------------

    /// Dissect and panic with everything a human needs if the bytes are not the
    /// protocol they claim to be.
    pub fn assert_clean(self) {
        let bytes_for_report: Vec<(Dir, Vec<u8>)> = self.chunks.clone();
        let protocol = self.protocol.clone();
        let report = match self.check() {
            Ok(r) => r,
            Err(e) => panic!("pcap oracle could not run for `{protocol}`: {e}"),
        };
        if report.is_clean() {
            return;
        }
        let mut msg = format!(
            "\n\n=== pcap oracle rejected `{protocol}`'s frames ===\n\
             tshark decode-as: {}\n",
            report.decode_as.as_deref().unwrap_or(
                "(none — no dissector \
                 registered for this protocol in src/tui/wireshark.rs)"
            )
        );
        for f in &report.failures {
            msg.push_str(&format!("  ✗ {f}\n"));
        }
        msg.push_str("\n--- what tshark saw ---\n");
        for p in &report.packets {
            msg.push_str(&format!(
                "  #{} {:<14} {}\n",
                p.number,
                p.dir.map(|d| d.label()).unwrap_or(""),
                p.protocols
            ));
            for (sev, m) in &p.experts {
                msg.push_str(&format!("       [{}] {}\n", severity_name(*sev), m));
            }
        }
        msg.push_str("\n--- the bytes ---\n");
        for (dir, b) in &bytes_for_report {
            msg.push_str(&format!("  {} ({} bytes)\n", dir.label(), b.len()));
            msg.push_str(&hexdump(b, 8));
        }
        panic!("{msg}");
    }

    /// Dissect and return the verdict instead of panicking. `Err` means tshark
    /// itself could not be run or refused the arguments — never "the bytes were
    /// bad", which is a `failures` entry on `Ok`.
    pub fn check(self) -> Result<PcapReport, String> {
        require_tshark();
        self.check_framing_matches_the_table()?;

        let (pcap, dirs) = self.build_pcap();

        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let path = dir.path().join("oracle.pcap");
        {
            let mut f = std::fs::File::create(&path).map_err(|e| format!("create pcap: {e}"))?;
            f.write_all(&pcap).map_err(|e| format!("write pcap: {e}"))?;
        }

        let wire = wire_for(&self.protocol);
        // Check the name against the tshark that is actually installed, before handing it
        // over. `-d tcp.port==N,<name>` with a name this build does not know makes tshark
        // exit 1 saying `Unknown protocol -- "<name>"`, which arrives here as
        // "pcap oracle could not run" and reads like a NetGet defect. It is not: it means
        // this Wireshark predates the dissector. That is how `redis` broke CI - `resp`
        // arrived in Wireshark 4.0 and ubuntu-22.04 ships 3.6.
        //
        // This is a verification, not a fallback, and deliberately so. A dissector that is
        // absent is NOT skipped: the oracle is an independent-decoder check and a silent skip
        // turns it into decoration, the same failure mode as a skip-when-missing client gate.
        // It only replaces an opaque error with one that names the fix.
        if let Some(name) = wire.decode_as {
            if !dissector_is_known(name) {
                return Err(format!(
                    "this tshark ({}) has no `{name}` dissector, so `{}`'s frames cannot be \
                     judged.\n\
                     This is an environment defect, not a defect in the bytes: `{name}` is the \
                     name `netget::tui::wireshark::wire_for` gives Wireshark's dissector for \
                     this protocol, verified against `tshark -G protocols` on a current build.\n\
                     Install a Wireshark new enough to have it - `resp` (Redis), for one, \
                     arrived in 4.0.0, and Ubuntu 22.04 ships 3.6.\n\
                     The oracle does NOT skip when the dissector is missing: a skip is a silent \
                     pass, which is the whole thing this check exists to prevent.",
                    tshark_version(),
                    self.protocol,
                ));
            }
        }
        let decode_as = wire.decode_as.and_then(|name| match self.framing {
            Framing::Tcp => Some(format!("tcp.port=={},{}", self.port, name)),
            Framing::Udp => Some(format!("udp.port=={},{}", self.port, name)),
            // A link-layer or IP-level protocol is reached by its own
            // registration (EtherType, LLC SAP, ip.proto); there is no port to
            // hang a decode-as clause on.
            Framing::Ethernet | Framing::IpProto(_) => None,
        });

        let mut cmd = Command::new("tshark");
        cmd.arg("-r")
            .arg(&path)
            // No name resolution: a test must not perform a DNS lookup, and
            // resolution is the slowest thing tshark does.
            .arg("-n");
        if let Some(d) = &decode_as {
            cmd.arg("-d").arg(d);
        }
        cmd.args([
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-e",
            "frame.number",
            "-e",
            "frame.protocols",
            "-e",
            "_ws.expert.severity",
            "-e",
            "_ws.expert.message",
        ]);

        let out = cmd.output().map_err(|e| format!("running tshark: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "tshark exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut packets = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            let number: u32 = cols.first().unwrap_or(&"0").parse().unwrap_or(0);
            let protocols = cols.get(1).unwrap_or(&"").to_string();
            // Severities are numeric, so splitting on the aggregator comma is
            // unambiguous. Messages may themselves contain commas, so they are
            // zipped positionally and used only for the human-readable report.
            let sevs: Vec<u32> = cols
                .get(2)
                .unwrap_or(&"")
                .split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            let raw_msgs = cols.get(3).unwrap_or(&"").to_string();
            let msgs: Vec<String> = if sevs.len() <= 1 {
                vec![raw_msgs.clone()]
            } else {
                raw_msgs.split(',').map(|s| s.trim().to_string()).collect()
            };
            let experts = sevs
                .iter()
                .enumerate()
                .map(|(i, s)| (*s, msgs.get(i).cloned().unwrap_or_default()))
                .collect();
            packets.push(PacketVerdict {
                number,
                protocols,
                experts,
                dir: dirs
                    .get((number as usize).saturating_sub(1))
                    .copied()
                    .flatten(),
            });
        }

        let mut failures = Vec::new();

        // 1. Expert info at Warn or above.
        for p in &packets {
            if self.peer_input_is_context && p.dir == Some(Dir::ToServer) {
                continue;
            }
            for (sev, msg) in &p.experts {
                if *sev < SEV_WARN {
                    continue;
                }
                if self.allowed.iter().any(|a| msg.contains(a.as_str())) {
                    continue;
                }
                failures.push(format!(
                    "packet #{} ({}): Expert Info [{}] {}",
                    p.number,
                    p.dir.map(|d| d.label()).unwrap_or("—"),
                    severity_name(*sev),
                    if msg.is_empty() { "(no message)" } else { msg }
                ));
            }
        }

        // 2. The dissector engaged, in every direction that carried bytes.
        if self.require_dissector {
            let names = self.expected_names();
            if !names.is_empty() {
                for want_dir in [Dir::ToServer, Dir::FromServer] {
                    if self.peer_input_is_context && want_dir == Dir::ToServer {
                        continue;
                    }
                    let carried = self
                        .chunks
                        .iter()
                        .any(|(d, b)| *d == want_dir && !b.is_empty());
                    if !carried {
                        continue;
                    }
                    let seen = packets.iter().any(|p| {
                        p.dir == Some(want_dir)
                            && p.protocols
                                .split(':')
                                .any(|tok| names.iter().any(|n| n == tok))
                    });
                    if !seen {
                        failures.push(format!(
                            "no {} packet was dissected as {} — tshark fell back to the \
                             generic decoder, which means it could not make sense of the \
                             framing (chains seen: {})",
                            want_dir.label(),
                            names.join(" or "),
                            packets
                                .iter()
                                .filter(|p| p.dir == Some(want_dir))
                                .map(|p| p.protocols.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                }
            }
        }

        Ok(PcapReport {
            packets,
            failures,
            decode_as,
        })
    }

    /// Dissect the same capture [`PcapOracle::check`] builds and return the values tshark
    /// reads for `names`, one row per packet (each cell as `-T fields` prints it: repeated
    /// occurrences joined by `,`). For asserting what the independent dissector *read* — a
    /// sequence number, a reason, an address — not only that it raised no expert info.
    pub fn fields(self, names: &[&str]) -> Result<Vec<Vec<String>>, String> {
        require_tshark();
        self.check_framing_matches_the_table()?;
        let (pcap, _) = self.build_pcap();
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let path = dir.path().join("oracle.pcap");
        std::fs::write(&path, &pcap).map_err(|e| format!("write pcap: {e}"))?;
        let wire = wire_for(&self.protocol);
        let mut cmd = Command::new("tshark");
        cmd.arg("-r").arg(&path).arg("-n");
        if let Some(name) = wire.decode_as {
            let clause = match self.framing {
                Framing::Tcp => Some(format!("tcp.port=={},{}", self.port, name)),
                Framing::Udp => Some(format!("udp.port=={},{}", self.port, name)),
                Framing::Ethernet | Framing::IpProto(_) => None,
            };
            if let Some(c) = clause {
                cmd.arg("-d").arg(c);
            }
        }
        cmd.args(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a"]);
        for n in names {
            cmd.arg("-e").arg(n);
        }
        let out = cmd.output().map_err(|e| format!("running tshark: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "tshark exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect())
    }

    /// Refuse a call that frames the bytes differently from how the protocol
    /// actually travels, because the result would be a confident, wrong verdict:
    /// `PcapOracle::tcp("ntp")` builds a TCP stream, tshark declines to apply the
    /// NTP dissector to it, and the oracle reports a framing defect in a server
    /// that has none. `wire_for` is the authority on the transport, as it is on
    /// the dissector name.
    fn check_framing_matches_the_table(&self) -> Result<(), String> {
        let t = wire_for(&self.protocol).transport;
        let ok = match (self.framing, t) {
            (Framing::Tcp, Transport::Tcp | Transport::TcpOrUdp) => true,
            (Framing::Udp, Transport::Udp | Transport::TcpOrUdp) => true,
            // A raw/link-layer protocol is reached through Ethernet or an IP
            // protocol number; which of the two is the caller's business, since
            // the table stores a BPF expression rather than a layer.
            (Framing::Ethernet | Framing::IpProto(_), Transport::Raw(_)) => true,
            // `lldp`-style protocols occasionally also run over a UDP test
            // transport in this tree; allow the caller to say so explicitly.
            (Framing::Udp, Transport::Raw(_)) => true,
            _ => false,
        };
        if ok {
            return Ok(());
        }
        Err(format!(
            "`{}` travels over {:?} according to src/tui/wireshark.rs, but the oracle was \
             asked to frame it as {:?}. Framing it the wrong way makes tshark decline the \
             dissector and the oracle would report a defect that is not there.",
            self.protocol, t, self.framing
        ))
    }

    /// The protocol tokens that may appear in `frame.protocols` as evidence the
    /// right dissector ran. Derived from `wire_for`, never invented here: the
    /// `decode_as` name plus each alternative in the display filter (`smb2 || smb`
    /// gives both), plus anything the caller added.
    fn expected_names(&self) -> Vec<String> {
        let wire = wire_for(&self.protocol);
        let mut names: Vec<String> = Vec::new();
        if let Some(d) = wire.decode_as {
            names.push(d.to_string());
        }
        if let Some(disp) = wire.display {
            for alt in disp.split("||") {
                let alt = alt.trim();
                // Only bare protocol names are usable as chain tokens; a real
                // filter expression (`tcp.port == 80`) is not.
                if !alt.is_empty()
                    && alt
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                    && !alt.contains('.')
                {
                    names.push(alt.to_string());
                }
            }
        }
        names.extend(self.extra_names.iter().cloned());
        names.sort();
        names.dedup();
        names
    }

    // -----------------------------------------------------------------------
    // pcap construction
    // -----------------------------------------------------------------------

    /// Returns the pcap bytes and, per packet index, which direction it belongs
    /// to (`None` for the synthetic handshake/teardown packets).
    fn build_pcap(&self) -> (Vec<u8>, Vec<Option<Dir>>) {
        let mut frames: Vec<(Vec<u8>, Option<Dir>)> = Vec::new();

        match self.framing {
            Framing::Ethernet => {
                for (dir, bytes) in &self.chunks {
                    frames.push((bytes.clone(), Some(*dir)));
                }
            }
            Framing::IpProto(proto) => {
                for (dir, bytes) in &self.chunks {
                    let (src, dst, smac, dmac) = match dir {
                        Dir::ToServer => (CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC),
                        Dir::FromServer => (SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC),
                    };
                    let ip = ipv4(src, dst, proto, bytes);
                    frames.push((ethernet(dmac, smac, 0x0800, &ip), Some(*dir)));
                }
            }
            Framing::Udp => {
                for (dir, bytes) in &self.chunks {
                    let (src, dst, smac, dmac, sp, dp) = match dir {
                        Dir::ToServer => (
                            CLIENT_IP,
                            SERVER_IP,
                            CLIENT_MAC,
                            SERVER_MAC,
                            CLIENT_PORT,
                            self.port,
                        ),
                        Dir::FromServer => (
                            SERVER_IP,
                            CLIENT_IP,
                            SERVER_MAC,
                            CLIENT_MAC,
                            self.port,
                            CLIENT_PORT,
                        ),
                    };
                    let seg = udp_segment(src, dst, sp, dp, bytes);
                    let ip = ipv4(src, dst, 17, &seg);
                    frames.push((ethernet(dmac, smac, 0x0800, &ip), Some(*dir)));
                }
            }
            Framing::Tcp => {
                // Coalesce adjacent same-direction chunks: where a read boundary
                // fell is an artefact of the test, not of the protocol, and a
                // segment that ends mid-PDU makes the dissector wait for more.
                let mut merged: Vec<(Dir, Vec<u8>)> = Vec::new();
                for (dir, bytes) in &self.chunks {
                    if bytes.is_empty() {
                        continue;
                    }
                    match merged.last_mut() {
                        Some((d, buf)) if *d == *dir => buf.extend_from_slice(bytes),
                        _ => merged.push((*dir, bytes.clone())),
                    }
                }

                // Per-direction next sequence number, in absolute terms.
                let mut seq = [1u32, 1u32]; // [ToServer, FromServer]
                let idx = |d: Dir| match d {
                    Dir::ToServer => 0usize,
                    Dir::FromServer => 1usize,
                };

                let emit = |dir: Dir,
                            flags: u8,
                            data: &[u8],
                            seq: &mut [u32; 2],
                            frames: &mut Vec<(Vec<u8>, Option<Dir>)>,
                            tag: Option<Dir>,
                            port: u16| {
                    let (src, dst, smac, dmac, sp, dp) = match dir {
                        Dir::ToServer => (
                            CLIENT_IP,
                            SERVER_IP,
                            CLIENT_MAC,
                            SERVER_MAC,
                            CLIENT_PORT,
                            port,
                        ),
                        Dir::FromServer => (
                            SERVER_IP,
                            CLIENT_IP,
                            SERVER_MAC,
                            CLIENT_MAC,
                            port,
                            CLIENT_PORT,
                        ),
                    };
                    let me = idx(dir);
                    let peer = 1 - me;
                    // A SYN carries no acknowledgement; setting one while the ACK
                    // flag is clear raises a Note ("acknowledgment number field is
                    // nonzero while the ACK flag is not set") that need not exist.
                    let ack = if flags & 0x10 != 0 { seq[peer] } else { 0 };
                    let seg = tcp_segment(src, dst, sp, dp, seq[me], ack, flags, data);
                    let ip = ipv4(src, dst, 6, &seg);
                    frames.push((ethernet(dmac, smac, 0x0800, &ip), tag));
                    seq[me] += data.len() as u32 + u32::from(flags & 0x03 != 0);
                };

                const SYN: u8 = 0x02;
                const SYN_ACK: u8 = 0x12;
                const ACK: u8 = 0x10;
                const PSH_ACK: u8 = 0x18;
                const FIN_ACK: u8 = 0x11;

                emit(
                    Dir::ToServer,
                    SYN,
                    &[],
                    &mut seq,
                    &mut frames,
                    None,
                    self.port,
                );
                emit(
                    Dir::FromServer,
                    SYN_ACK,
                    &[],
                    &mut seq,
                    &mut frames,
                    None,
                    self.port,
                );
                emit(
                    Dir::ToServer,
                    ACK,
                    &[],
                    &mut seq,
                    &mut frames,
                    None,
                    self.port,
                );

                // IPv4's Total Length is 16 bits, so a run of more than ~64 KiB in one
                // direction cannot be one segment: its length field wraps and tshark sees a
                // truncated packet followed by bytes it "never captured". Split long runs the
                // way a real stack would; tshark reassembles them.
                const MAX_SEGMENT_PAYLOAD: usize = 32 * 1024;
                for (dir, bytes) in &merged {
                    for segment in bytes.chunks(MAX_SEGMENT_PAYLOAD) {
                        emit(
                            *dir,
                            PSH_ACK,
                            segment,
                            &mut seq,
                            &mut frames,
                            Some(*dir),
                            self.port,
                        );
                    }
                }

                if self.close_stream {
                    // The FIN is not decoration. `whois` dissects its answer only
                    // once the stream is seen to end; without this the reply is
                    // reported as plain `tcp` and the oracle would fail a correct
                    // server. Tagged with the direction it closes so a dissector
                    // that flushes on FIN still counts for that direction.
                    emit(
                        Dir::ToServer,
                        FIN_ACK,
                        &[],
                        &mut seq,
                        &mut frames,
                        Some(Dir::ToServer),
                        self.port,
                    );
                    emit(
                        Dir::FromServer,
                        FIN_ACK,
                        &[],
                        &mut seq,
                        &mut frames,
                        Some(Dir::FromServer),
                        self.port,
                    );
                }
            }
        }

        let mut out = Vec::new();
        // pcap global header, little-endian.
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // version major
        out.extend_from_slice(&4u16.to_le_bytes()); // version minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        let mut dirs = Vec::with_capacity(frames.len());
        for (i, (frame, dir)) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_700_000_000u32).to_le_bytes());
            out.extend_from_slice(&((i as u32) * 1000).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(frame);
            dirs.push(*dir);
        }
        (out, dirs)
    }
}

// ---------------------------------------------------------------------------
// Framing primitives
// ---------------------------------------------------------------------------

fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20u16 + payload.len() as u16;
    let mut h = Vec::with_capacity(20 + payload.len());
    h.push(0x45);
    h.push(0x00);
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    h.push(64); // ttl
    h.push(proto);
    h.extend_from_slice(&[0, 0]); // checksum placeholder
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = ones_complement(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn pseudo_header(src: [u8; 4], dst: [u8; 4], proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.push(0);
    p.push(proto);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p
}

fn udp_segment(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    let mut buf = pseudo_header(src, dst, 17, seg.len());
    buf.extend_from_slice(&seg);
    // RFC 768: an all-zero computed checksum is transmitted as all ones.
    let ck = match ones_complement(&buf) {
        0 => 0xffff,
        c => c,
    };
    seg[6..8].copy_from_slice(&ck.to_be_bytes());
    seg
}

#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(5 << 4); // data offset 5 words, no options
    seg.push(flags);
    seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(payload);
    let mut buf = pseudo_header(src, dst, 6, seg.len());
    buf.extend_from_slice(&seg);
    let ck = ones_complement(&buf);
    seg[16..18].copy_from_slice(&ck.to_be_bytes());
    seg
}

fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// A hex+ASCII dump, indented, for the panic message. The bytes are the whole
/// point of a finding: "tshark rejected it" without them is not actionable.
pub fn hexdump(bytes: &[u8], indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut s = String::new();
    for (off, chunk) in bytes.chunks(16).enumerate() {
        s.push_str(&format!("{pad}{:08x}  ", off * 16));
        for (i, b) in chunk.iter().enumerate() {
            s.push_str(&format!("{b:02x} "));
            if i == 7 {
                s.push(' ');
            }
        }
        for i in chunk.len()..16 {
            s.push_str("   ");
            if i == 7 {
                s.push(' ');
            }
        }
        s.push_str(" |");
        for b in chunk {
            s.push(if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        s.push_str("|\n");
    }
    if bytes.is_empty() {
        s.push_str(&format!("{pad}(empty)\n"));
    }
    s
}

/// Hard-fail when `tshark` is absent.
///
/// The repository's rule is explicit: a gate that prints `SKIP` and returns
/// success is a silent pass, and this oracle exists precisely because silent
/// passes let wrong bytes through. Missing `tshark` is an environment defect,
/// not a reason to assert nothing.
pub fn require_tshark() {
    static CHECK: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    let r = CHECK.get_or_init(|| match Command::new("tshark").arg("--version").output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()),
        Ok(o) => Err(format!(
            "`tshark --version` exited {:?}: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(e.to_string()),
    });
    if let Err(e) = r {
        panic!(
            "\n\nThe pcap oracle needs `tshark` and it is not usable ({e}).\n\
             It is NOT skipped when missing: a skip-when-missing gate is a silent pass, \
             and this test exists to stop malformed frames reaching a green build.\n\
             Install it:  brew install wireshark   (macOS)\n\
             \x20            apt-get install -y tshark   (Debian/Ubuntu CI)\n"
        );
    }
}

/// The first line of `tshark --version`, or a placeholder. Only for error messages.
fn tshark_version() -> String {
    Command::new("tshark")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "version unknown".to_string())
}

/// Every protocol filter name the installed tshark knows, from `tshark -G protocols`.
///
/// Column 3 of that table is the display-filter name, which is exactly what `-d` wants.
/// Queried once per process: it is ~3000 lines and every oracle call would otherwise pay
/// for it.
fn known_dissectors() -> &'static std::collections::BTreeSet<String> {
    static NAMES: std::sync::OnceLock<std::collections::BTreeSet<String>> =
        std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let out = match Command::new("tshark").arg("-G").arg("protocols").output() {
            Ok(o) if o.status.success() => o.stdout,
            // An empty set would make every protocol look unknown, which is a worse lie
            // than not checking. `require_tshark` has already established that tshark
            // runs, so this is the "-G protocols changed shape" case: let the real run
            // produce the real error.
            _ => return std::collections::BTreeSet::new(),
        };
        String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|l| l.split('\t').nth(2))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Does the installed tshark know this dissector name?
///
/// Answers `true` when the name table could not be read at all, so a change in
/// `-G protocols`' output cannot turn this verification into a blanket refusal.
fn dissector_is_known(name: &str) -> bool {
    let names = known_dissectors();
    names.is_empty() || names.contains(name)
}

/// Is `tshark` usable? For the oracle's own tests, which must distinguish
/// "the validator rejected the frame" from "the validator could not run".
pub fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
