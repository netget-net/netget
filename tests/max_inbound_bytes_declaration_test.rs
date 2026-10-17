//! A server that buffers a peer-chosen number of bytes must **declare** the ceiling.
//!
//! `ProtocolMetadataV2::max_inbound_bytes` exists so the question "what is the largest thing a
//! stranger can make this server allocate?" has an answer that can be grepped, tested and
//! reviewed. A bound that lives only as a literal inside a read loop cannot be any of those.
//!
//! # Why this is a declaration check rather than an unbounded-read detector
//!
//! No source scan can decide whether a read is bounded. The bound may be a `MAX_*` const, the
//! width of a length field (`db2` and `mssql` are safe only because their length is a `u16`),
//! a third-party codec (`postgresql` is bounded by pgwire's own `max_size` check), or the fact
//! that a body is never read at all (`npm`, `oci_registry` and `rss` drop `Incoming` unread).
//! Each of those is correct and none of them looks alike.
//!
//! So the rule is the one thing a scan *can* enforce: every protocol either declares a number
//! or appears below with a reason a human wrote. The baseline is the work queue, and the
//! reasons are what stop it from becoming an exemption list — an entry saying "fixed-size
//! datagram, the buffer is the bound" is a finished answer, and an entry saying "unbounded,
//! reported" is not.
//!
//! # Why a source scan rather than a registry walk
//!
//! The same reason as `decision_tag_ratchet_test` and `event_emit_sites_test`: a registry walk
//! only sees the protocols compiled into that build, and the blocking CI job compiles 6 of 116.
//! Reading `src/server/*/actions.rs` holds at every feature set.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test max_inbound_bytes_declaration_test

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Server protocols that do not declare `max_inbound_bytes`, each with the reason.
///
/// **Shrink-only.** Removing an entry is the work; adding one is not an option. A new protocol
/// that reads a peer-chosen number of bytes declares its bound.
///
/// The reasons fall into six kinds, and the difference between them matters — three are
/// finished answers and three are open work:
///
/// 1. **Fixed-size read** — one `recv_from` into one fixed buffer, contents moved into an event
///    and dropped. The allocation is a compile-time constant, so a declaration would be a knob
///    that does nothing. *Finished.*
/// 2. **Delegates** — the BLE profiles have no read loop; `BluetoothBle` owns the radio.
///    `wireguard` owns no socket at all: the kernel or `wireguard-go` does. *Finished.*
/// 3. **Structural** — the peer's length field is a `u16` or narrower, so the type is the
///    ceiling. Worth knowing rather than declaring, because there is no constant to move.
///    *Finished, but see the note below.*
/// 4. **Third-party bound** — a crate checks the declared length before buffering. *Finished*
///    where the check was actually read; the entry says which line.
/// 5. **Body never read** — the request body is dropped rather than collected, so there is
///    nothing to bound. *Finished.*
/// 6. **Unbounded** — a real defect, named here so it is visible rather than absent.
///    *Open work.*
///
/// A note on kind 3: "the type is the bound" is the weakest of the finished answers, because it
/// is invisible at the read site. `dot` records this in its own source — an earlier
/// `dns_len > 65535` guard was dead code "and read as a bound that was not there". If one of
/// these grows a wider length field, nothing here will notice.
const UNDECLARED_BASELINE: &[(&str, &str)] = &[
    // ---- 1. Fixed-size read: the buffer is the bound ----
    ("arp", "pcap snaplen; fixed frame, no accumulation"),
    ("bootp", "single recv_from into a fixed 1500-byte buffer"),
    (
        "can",
        "single recv_from into a fixed 4096-byte buffer; a CAN frame is 72 bytes",
    ),
    (
        "datalink",
        "pcap snaplen; its MAX_HEX_BYTES_TO_MODEL is prompt truncation, not a read bound",
    ),
    ("dhcp", "single recv_from into a fixed 1500-byte buffer"),
    ("dhcpv6", "single recv_from into a fixed 1500-byte buffer"),
    (
        "dns",
        "UDP: single recv_from into a fixed 4096-byte buffer. TCP (since October 2026): the \
         two-byte length prefix is the ceiling, 65535, read with read_u16 and allocated per \
         message; kind 3 as well as kind 1",
    ),
    (
        "icmp",
        "single raw-socket recv into a fixed 65535-byte buffer",
    ),
    ("igmp", "single recv_from into a fixed 65535-byte buffer"),
    ("isis", "pcap snaplen; fixed frame, no accumulation"),
    ("lldp", "single recv_from into a fixed 65535-byte buffer"),
    ("mdns", "no peer input path of its own"),
    ("named_pipe", "single read into a fixed 8192-byte buffer"),
    (
        "ndp",
        "single recv_from into a fixed 65535-byte buffer; no fragment reassembly",
    ),
    (
        "netbios_ns",
        "fixed MAX_DATAGRAM+1 buffer; oversize is detected and dropped",
    ),
    ("ntp", "single recv_from into a fixed 1024-byte buffer"),
    (
        "ospf",
        "single recv into a fixed 65535-byte buffer; the neighbour map is aged by retain",
    ),
    ("pty", "single read into a fixed 8192-byte buffer"),
    (
        "rawip",
        "single recv_from into a fixed 65535-byte buffer; no reassembly",
    ),
    ("rip", "single recv_from into a fixed 512-byte buffer"),
    (
        "rtp",
        "single recv_from into a fixed 65535-byte buffer; no jitter buffer",
    ),
    (
        "sip",
        "UDP only; single recv_from into a fixed 65535-byte buffer",
    ),
    ("snmp", "single recv_from into a fixed 65535-byte buffer"),
    ("stdio", "single read into a fixed 8192-byte buffer"),
    ("stun", "single recv_from into a fixed 2048-byte buffer"),
    (
        "syslog",
        "UDP only; single recv_from into a fixed 65535-byte buffer",
    ),
    (
        "tftp",
        "single recv_from into a fixed 516-byte buffer; blocks are not assembled",
    ),
    (
        "torrent_dht",
        "fixed 65535-byte buffer; bencode depth is bounded separately",
    ),
    (
        "tuntap",
        "read sized from the operator's MTU, not from anything a peer sends",
    ),
    (
        "turn",
        "fixed RELAY_MTU buffer, so no message size is peer-chosen; its unbounded growth was \
         the permission map, now capped at MAX_PERMISSIONS with expiry enforced on write",
    ),
    ("udp", "single recv_from into a fixed 65535-byte buffer"),
    (
        "vrrp",
        "single recv_from into fixed 2048/65535-byte buffers",
    ),
    (
        "wol",
        "fixed 2048-byte buffer; a non-magic datagram is dropped before any model call",
    ),
    // ---- 2. Delegates: no read loop of its own ----
    (
        "bluetooth_ble",
        "the radio dispatcher owns every read; profiles delegate to it",
    ),
    ("bluetooth_ble_battery", "delegates to bluetooth_ble"),
    (
        "bluetooth_ble_beacon",
        "advertising payload only; nothing is read from a peer",
    ),
    ("bluetooth_ble_cycling", "delegates to bluetooth_ble"),
    ("bluetooth_ble_data_stream", "delegates to bluetooth_ble"),
    ("bluetooth_ble_environmental", "delegates to bluetooth_ble"),
    ("bluetooth_ble_file_transfer", "delegates to bluetooth_ble"),
    ("bluetooth_ble_gamepad", "delegates to bluetooth_ble"),
    ("bluetooth_ble_heart_rate", "delegates to bluetooth_ble"),
    ("bluetooth_ble_keyboard", "delegates to bluetooth_ble"),
    ("bluetooth_ble_mouse", "delegates to bluetooth_ble"),
    ("bluetooth_ble_presenter", "delegates to bluetooth_ble"),
    ("bluetooth_ble_proximity", "delegates to bluetooth_ble"),
    ("bluetooth_ble_remote", "delegates to bluetooth_ble"),
    ("bluetooth_ble_running", "delegates to bluetooth_ble"),
    ("bluetooth_ble_thermometer", "delegates to bluetooth_ble"),
    ("bluetooth_ble_weight_scale", "delegates to bluetooth_ble"),
    (
        "wireguard",
        "NetGet opens no socket: the UDP port belongs to the kernel module or wireguard-go, \
         driven through defguard_wireguard_rs; NetGet reads only interface statistics from \
         that local backend",
    ),
    // ---- 3. Structural: the peer's length field is a u16 or narrower ----
    (
        "db2",
        "DRDA DSS length is a u16, so a message cannot exceed 65535",
    ),
    (
        "dot",
        "RFC 7858 length prefix is a u16; no accumulation across messages",
    ),
    (
        "mssql",
        "TDS packet length is a u16; the underflow guard precedes the subtraction",
    ),
    (
        "socks5",
        "every variable field is preceded by a u8 length, so 255 is the maximum",
    ),
    (
        "tor_relay",
        "cell length is a u16 and is never used to allocate",
    ),
    (
        "torrent_tracker",
        "one fixed 8192-byte read, no accumulation",
    ),
    // ---- 4. Bounded inside a third-party crate ----
    (
        "postgresql",
        "pgwire codec.rs rejects on the declared msg_len before buffering",
    ),
    // ---- 5. The request body is never read ----
    (
        "npm",
        "hyper Incoming is dropped unread; the registry serves GETs only",
    ),
    (
        "oci_registry",
        "hyper Incoming is dropped unread; push is not supported",
    ),
    ("rss", "hyper Incoming is dropped unread"),
    // ---- 6. Open work ----
    // None.
];

fn server_action_files() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let root = Path::new("src/server");
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();

        // Nested families (`usb/*`) keep their `actions.rs` one level deeper. Where a
        // directory has such children, they are the protocols and the parent is not — the
        // flat walk this replaced is why `usb_keyboard` and `usb_mouse` sat unexamined in a
        // neighbouring ratchet's baseline.
        let mut nested = Vec::new();
        if let Ok(children) = std::fs::read_dir(&dir) {
            for child in children.flatten() {
                let sub = child.path();
                if sub.is_dir() && sub.join("actions.rs").is_file() {
                    nested.push((
                        format!("{}_{}", name, child.file_name().to_string_lossy()),
                        sub.join("actions.rs"),
                    ));
                }
            }
        }
        if !nested.is_empty() {
            nested.sort();
            out.extend(nested);
            continue;
        }
        let actions = dir.join("actions.rs");
        if actions.is_file() && implements_a_protocol(&actions) {
            out.push((name, actions));
        }
    }
    out.sort();
    out
}

/// Whether an `actions.rs` is a protocol's, rather than a helper that happens to share the
/// file name.
///
/// `http_common` has an `actions.rs` — the executor behind `send_http_response` — and no
/// `metadata()`, no `impl Protocol` and no registry entry, so it has nothing to declare a bound
/// on, and a baseline entry for it would be neither a finished answer nor a defect. Its bound,
/// `MAX_REQUEST_BODY_BYTES`, is declared by the protocols that use it (`http`, `http2`,
/// `pypi`). The test for "is a protocol" is the one thing every
/// protocol has and a helper cannot: `fn metadata(`, outside comments.
/// `every_directory_the_walker_skips_is_a_helper` checks the skip cannot hide a protocol.
fn implements_a_protocol(actions: &Path) -> bool {
    std::fs::read_to_string(actions)
        .map(|src| strip_comments(&src).contains("fn metadata("))
        .unwrap_or(false)
}

/// Strip `//` comments, leaving `//` inside a string literal alone.
///
/// Prose *about* the convention must not count as a declaration. This repository has hit the
/// matching-comment false positive at least three times — a doc comment quoting the pattern a
/// ratchet looks for, reported as the defect it documents — and the inverse matters just as
/// much here: a protocol whose only `max_inbound_bytes` is in a `///` explaining why it has
/// none would go green while declaring nothing.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            let bytes = line.as_bytes();
            let mut in_string = false;
            let mut i = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' if in_string => i += 1,
                    b'"' => in_string = !in_string,
                    b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                        return line[..i].to_string()
                    }
                    _ => {}
                }
                i += 1;
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_server_declares_max_inbound_bytes_or_is_baselined_with_a_reason() {
    let baselined: BTreeSet<&str> = UNDECLARED_BASELINE.iter().map(|(p, _)| *p).collect();

    let mut new_offenders = Vec::new();
    let mut fixed = Vec::new();

    for (protocol, path) in server_action_files() {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let declares = strip_comments(&src).contains(".max_inbound_bytes(");

        match (declares, baselined.contains(protocol.as_str())) {
            (false, false) => new_offenders.push(protocol),
            (true, true) => fixed.push(protocol),
            _ => {}
        }
    }

    assert!(
        new_offenders.is_empty(),
        "these servers declare no `max_inbound_bytes` and are not in the baseline:\n  {}\n\n\
         Declare the bound the code enforces:\n    \
         .max_inbound_bytes(crate::server::<p>::MAX_REQUEST_BYTES)\n\n\
         If the protocol genuinely reads nothing whose length a peer chooses — a fixed-size \
         datagram, a delegating profile — add it to UNDECLARED_BASELINE with the reason, and \
         make the reason the evidence rather than a category.",
        new_offenders.join("\n  ")
    );

    assert!(
        fixed.is_empty(),
        "these servers now declare `max_inbound_bytes` but are still in the baseline:\n  {}\n\n\
         The baseline is shrink-only — remove them.",
        fixed.join("\n  ")
    );
}

/// A directory the walker skips must be a helper, never a protocol.
///
/// The skip in `server_action_files` keys on `fn metadata(` in `actions.rs`. If a protocol ever
/// put its metadata somewhere else, the skip would silently exempt it — the dangerous direction,
/// since this ratchet exists to catch an undeclared bound. So: nothing under a skipped directory
/// may implement `Protocol` or `Server`, in any file.
#[test]
fn every_directory_the_walker_skips_is_a_helper() {
    let mut hiding = Vec::new();
    let mut skipped = Vec::new();
    let Ok(entries) = std::fs::read_dir("src/server") else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let actions = dir.join("actions.rs");
        if !actions.is_file() || implements_a_protocol(&actions) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        skipped.push(name.clone());
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        for file in files.flatten() {
            let src = std::fs::read_to_string(file.path()).unwrap_or_default();
            let src = strip_comments(&src);
            if src.contains("impl Protocol for") || src.contains("impl Server for") {
                hiding.push(format!("{name}/{}", file.file_name().to_string_lossy()));
            }
        }
    }
    println!("skipped as helpers: {skipped:?}");
    assert!(
        hiding.is_empty(),
        "these directories have an actions.rs with no `fn metadata(`, so the walker skips them, \
         but they implement Protocol or Server — a protocol the declaration check cannot see:\n  \
         {}",
        hiding.join("\n  ")
    );
}

/// Every baseline entry must name a protocol that exists, and must carry a real reason.
///
/// Without this the list rots in the quiet direction: a protocol is renamed or removed, its
/// entry stays, and the ratchet silently stops covering something. The same shape as the
/// stale-`#[ignore]` trap — a marker that is never reached says whatever it likes.
#[test]
fn every_baseline_entry_names_a_real_protocol_and_gives_a_reason() {
    let known: BTreeSet<String> = server_action_files().into_iter().map(|(p, _)| p).collect();

    let mut stale = Vec::new();
    let mut unreasoned = Vec::new();
    for (protocol, reason) in UNDECLARED_BASELINE {
        if !known.contains(*protocol) {
            stale.push(*protocol);
        }
        // Long enough that "n/a" or "TODO" cannot pass for an answer.
        if reason.len() < 20 {
            unreasoned.push(*protocol);
        }
    }

    assert!(
        stale.is_empty(),
        "baseline entries naming no protocol under src/server/: {stale:?}"
    );
    assert!(
        unreasoned.is_empty(),
        "baseline entries whose reason says nothing: {unreasoned:?}"
    );
}
