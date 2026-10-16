//! Every UDP-serving protocol must declare `.connectionless()` in its metadata.
//!
//! `AppState::cleanup_old_connections` — the 10-second idle sweep ticked by the TUI
//! and the MCP loop — only reaps connection entries for servers whose
//! `ProtocolMetadataV2::connectionless` is set. That is deliberate: UDP/raw servers
//! track one bookkeeping entry per remote address and nothing ever closes them, so
//! the sweep is the only thing standing between an idle UDP server and an
//! ever-growing connection map. (The old behaviour — sweeping *every* server — was
//! the dangerous direction: it evicted live TCP-style connections mid-conversation.
//! See the root CLAUDE.md, "The 10-second idle sweep".)
//!
//! A new UDP protocol that forgets the flag therefore leaks idle entries until its
//! server stops, and nothing at runtime says so. This audit closes that gap the
//! same way `event_action_declarations_test` closes its own: walk the registry and
//! check every registered protocol at build time.
//!
//! The UDP-ness of a protocol is read from its **source on disk**: if any `.rs`
//! file under `src/server/<dir>/` mentions `UdpSocket` (the `tokio::net` one and
//! the `std::net` one both mean datagram handling; `create_reusable_udp_socket`
//! from `socket_helpers` is matched too, in case a protocol adopts the helper
//! without naming the type), the protocol serves datagrams and must declare
//! `.connectionless()`. Declaring it *without* using `UdpSocket` is fine — `isis`
//! does, legitimately: raw link-level frames have per-remote entries with exactly
//! the same nothing-ever-closes-them shape.
//!
//! Like every registry-walking audit, this covers only the protocols compiled into
//! the current feature set; the `registry-audit` CI job runs the audits at
//! `--all-features` for that reason.

use std::path::{Path, PathBuf};

use netget::llm::actions::protocol_trait::Protocol;
use netget::protocol::server_registry::registry;

/// Protocols that legitimately use a `UdpSocket` while being connection-oriented
/// (e.g. a UDP *side channel* on an otherwise stream-based server), as registry
/// names. Empty, and meant to stay that way: when this audit flags a protocol,
/// the fix is `.connectionless()` on its metadata builder, and an entry lands
/// here only with a comment justifying why the sweep must NOT reap its entries.
const CONNECTIONLESS_EXCEPTIONS: &[&str] = &[
    // Riding UDP is not the test — "has no connection concept" is, and the root `CLAUDE.md`
    // records the cost of getting that backwards. Declaring `.connectionless()` on a UDP
    // protocol that carries a *session* is actively harmful: the 10-second idle sweep evicts
    // an entry whose peer is mid-exchange, and a peer is idle for the whole of an LLM call.
    // TFTP had exactly that, and live transfers were reaped out from under themselves.
    //
    // Each of these three keeps per-peer state that the next packet is interpreted against,
    // so each is connection-oriented in every way but the transport.

    // A transfer: block N+1 only means anything against block N's ACK, and the whole of it is
    // idle while the model is deciding what the next block contains.
    "TFTP",
    // A TLS session carried inside P_CONTROL_V1 packets, then the key-method-2 exchange.
    // Reaping mid-handshake would drop a peer that is behaving correctly.
    "OpenVPN",
    // 802.1X is a session machine — EAP identity, challenge, then the admission decision.
    // The gap between request and response is exactly where the model sits.
    "EAPOL",
    // A BFD session is exactly a connection: discriminators, a state machine, timers, and an
    // entry that lives as long as the session and is closed when it ends (Down and silent for
    // a minute). Each packet is interpreted against the last; a quiet spell is the Detection
    // Time's to judge, never a 10-second sweep's.
    "BFD",
    // A KNXnet/IP tunnel is a connection: CONNECT_REQUEST assigns a channel, every tunnelling
    // request carries a sequence number checked against the last, and the specification's
    // heartbeat (CONNECTIONSTATE_REQUEST) keeps it alive; a tunnel silent for 120 s is dropped
    // by the server itself. A 10-second sweep would cut a tunnel that is behaving correctly.
    "KNX/IP",
    // GELF also serves live TCP sessions, which must survive a slow handler. Its UDP
    // path creates only a temporary entry for one decoded message and explicitly
    // removes it after dispatch on success or error. Chunk reassembly is bounded and
    // expired by its own 1-second timer; no per-remote UDP entries await the idle sweep.
    "GELF",
    // IPFIX creates one temporary row for each decoded message while its common handler
    // runs, then removes that row after success, error or default collection. Reaping a
    // parked manual/model handler would hide a live request. No per-remote rows await
    // the idle sweep; template/session state has a separate owned 1-second expiry timer.
    "IPFIX",
    // sFlow also removes each temporary datagram row when its common handler ends.
    // Reaping it while manual/model work is parked would hide a live request;
    // diagnostic sequence state expires independently on its owned 1-second timer.
    "sFlow",
    // NetFlow v9 owns the same temporary datagram row lifecycle: each common
    // handler removes its row on completion. The idle sweep must leave a parked
    // request visible; its template/session cache expires on a separate owned timer.
    "NetFlowV9",
    // The portmapper serves TCP connections (tracked, and closed when they end) and UDP calls
    // on the same port. A UDP call creates no per-remote row at all — each datagram is one
    // call, answered and forgotten — so the idle sweep has nothing to reap there, and must not
    // reap the TCP rows a slow handler is answering on.
    "SunRPC",
    // ypserv is the same shape as the portmapper whose RPC layer it shares: tracked TCP
    // connections (an ALL can take the whole of an LLM call) and UDP calls that create no row,
    // each answered and forgotten. The sweep has nothing to reap on UDP and must not reap TCP.
    "NIS",
    // SRT is a connection protocol over UDP: a handshake, then ARQ and timestamped delivery
    // owned by srt-tokio. Its row is closed when that connection ends; a quiet publisher
    // between frames is still a live session.
    "SRT",
    // An MQTT-SN client session: CONNECT, registered topic ids, subscriptions and sleep.
    // The row closes on DISCONNECT, a lost keep-alive, or a will; a sleeping client is idle
    // by design and must keep its session.
    "MQTT-SN",
    // An LwM2M registration lives for its declared lifetime and is closed on deregistration or
    // expiry by the server's own timer; reaping it after ten quiet seconds would drop every
    // registered device between updates.
    "LwM2M",
    // The H.323 endpoint is TCP call signalling: one connection per call, closed when the call
    // ends, and a connected call is legitimately silent on it for minutes while the parties
    // talk. Its UdpSocket use is the per-call RTP/RTCP pair (owned by the call and dropped with
    // it), plus the gatekeeper sharing its directory — which does declare .connectionless().
    // A 10-second sweep would evict live calls.
    "H323",
    // PROFINET's connections are application relationships: a row is added when a Connect is
    // accepted and removed on Release, the watchdog, or an abort — and a device-access AR is
    // legitimately silent between record reads. DCP and the RPC datagrams outside an AR create
    // no row, so the sweep would have nothing of its own to reap and live ARs to lose.
    "PROFINET",
    // EtherCAT's rows are the masters driving the segment: one is added on a master's first
    // frame and the engine closes it after 30 s without one. A master is legitimately quiet for
    // longer than 10 s between configuration steps (and polls nothing while a person answers a
    // parked state change), and what it configured — station addresses, SyncManagers, the AL
    // state — lives in the slave, not in a row the sweep could usefully reap.
    "EtherCAT",
];

/// Registry names whose source directory does not follow any of the mechanical
/// name→dir conventions below. Only protocols that would otherwise go
/// unmapped; keep it short and let the mechanical candidates do the work.
fn dir_alias(protocol_name: &str) -> Option<&'static str> {
    match protocol_name {
        "USB-MassStorage" => Some("usb/msc"),
        "DynamoDB" => Some("dynamo"),
        "SamlIdp" => Some("saml_idp"),
        "SamlSp" => Some("saml_sp"),
        "FluentForward" => Some("fluent_forward"),
        "NetFlowV9" => Some("netflow_v9"),
        "PrometheusRemoteWrite" => Some("prometheus_remote_write"),
        _ => None,
    }
}

/// Candidate `src/server/<dir>` names for a registry protocol name.
///
/// Registry names are display-ish ("Torrent-DHT", "IPSec/IKEv2", "SSH Agent",
/// "usb-fido2"); directories are lowercase snake_case, with the USB family
/// nested ("usb/fido2"). Try, in order:
/// 1. an explicit alias (`dir_alias`)
/// 2. lowercase with `-`/` ` mapped to `_`   (Torrent-DHT → torrent_dht)
/// 3. the same with `_` mapped to `/`        (usb_fido2 → usb/fido2)
/// 4. lowercase with separators removed      (XML-RPC → xmlrpc)
/// 5. the first `-`/` `-separated token      (Bitcoin P2P → bitcoin)
/// Anything after a `/` in the name is dropped first (IPSec/IKEv2 → ipsec).
fn dir_candidates(protocol_name: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(alias) = dir_alias(protocol_name) {
        candidates.push(alias.to_string());
    }

    let lower = protocol_name.to_lowercase();
    let lower = lower.split('/').next().unwrap_or(&lower).to_string();

    let underscored: String = lower
        .chars()
        .map(|c| if c == '-' || c == ' ' { '_' } else { c })
        .collect();
    candidates.push(underscored.clone());
    candidates.push(underscored.replace('_', "/"));
    candidates.push(
        lower
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect(),
    );
    if let Some(first) = lower.split(['-', ' ']).next() {
        candidates.push(first.to_string());
    }

    candidates.dedup();
    candidates
}

/// The protocol's source directory on disk, if any candidate exists.
fn source_dir(server_root: &Path, protocol_name: &str) -> Option<PathBuf> {
    dir_candidates(protocol_name)
        .into_iter()
        .map(|candidate| server_root.join(candidate))
        .find(|path| path.is_dir())
}

/// Whether any `.rs` file in `dir` (recursively — `radius` and `syslog` touch
/// their socket from `actions.rs`, the USB family nests submodules) mentions a
/// UDP socket.
fn mentions_udp_socket(dir: &Path) -> bool {
    const MARKERS: [&str; 2] = ["UdpSocket", "create_reusable_udp_socket"];

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if mentions_udp_socket(&path) {
                return true;
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if let Ok(source) = std::fs::read_to_string(&path) {
            if MARKERS.iter().any(|marker| source.contains(marker)) {
                return true;
            }
        }
    }
    false
}

/// The audit: every registered protocol whose source serves UDP datagrams must
/// declare `.connectionless()`, or the idle sweep never reaps its per-remote
/// entries and an idle server leaks them until it stops.
#[test]
fn every_udp_serving_protocol_declares_connectionless() {
    // Tests run with CWD = the crate root, but don't depend on it.
    let server_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server");
    assert!(
        server_root.is_dir(),
        "src/server not found at {} — the audit cannot read protocol sources",
        server_root.display()
    );

    let mut findings: Vec<String> = Vec::new();
    let mut unmapped: Vec<String> = Vec::new();
    let mut udp_checked = 0usize;
    let mut excepted_seen = 0usize;

    let all = registry().all_protocols();
    for (name, protocol) in &all {
        let Some(dir) = source_dir(&server_root, name) else {
            // No candidate directory: report it rather than silently skipping,
            // so a rename that breaks the mapping is visible in the output.
            unmapped.push(name.clone());
            continue;
        };
        if !mentions_udp_socket(&dir) {
            continue;
        }
        udp_checked += 1;

        if protocol.metadata().connectionless {
            continue;
        }
        if CONNECTIONLESS_EXCEPTIONS.contains(&name.as_str()) {
            excepted_seen += 1;
            continue;
        }
        findings.push(format!(
            "[{}] {} uses a UdpSocket but its metadata() does not declare \
             .connectionless() — the 10s idle sweep will never reap its per-remote \
             connection entries, so an idle server leaks them until it stops. Add \
             .connectionless() to the ProtocolMetadataV2 builder in its actions.rs \
             (or, if the socket is genuinely a side channel of a connection-oriented \
             server, add the protocol to CONNECTIONLESS_EXCEPTIONS with a comment \
             saying why).",
            name,
            dir.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&dir)
                .display(),
        ));
    }

    if !unmapped.is_empty() {
        eprintln!(
            "note: {} registered protocol(s) map to no src/server directory and were \
             not source-checked: {}",
            unmapped.len(),
            unmapped.join(", ")
        );
    }
    if excepted_seen > 0 {
        eprintln!(
            "note: {} UDP-using protocol(s) are quarantined in CONNECTIONLESS_EXCEPTIONS",
            excepted_seen
        );
    }
    eprintln!(
        "connectionless audit coverage: {} registered protocol(s) in this build, {} of \
         them UDP-serving and checked. Protocols behind uncompiled features are \
         invisible here — the registry-audit CI job runs this at --all-features.",
        all.len(),
        udp_checked
    );

    assert!(
        findings.is_empty(),
        "{} UDP-serving protocol(s) do not declare .connectionless():\n\n{}",
        findings.len(),
        findings.join("\n\n")
    );
}

/// The audit proves nothing if the mapping or the source scan silently breaks:
/// in a build that compiles the `udp` feature, the plain UDP server must be
/// found, must read as UDP-serving, and must already carry the flag. If this
/// fails, fix the audit, not the protocol.
#[test]
fn the_audit_recognises_the_reference_udp_protocol() {
    let server_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server");

    let (name, protocol) = registry()
        .all_protocols()
        .into_iter()
        .find(|(name, _)| name == "UDP")
        .expect("the udp feature registers the UDP protocol");

    let dir = source_dir(&server_root, &name)
        .expect("the UDP protocol must map to a src/server directory");
    assert!(
        mentions_udp_socket(&dir),
        "src/server/udp must read as UDP-serving — if the socket type moved, update \
         the audit's markers"
    );
    assert!(
        protocol.metadata().connectionless,
        "the reference UDP protocol declares .connectionless()"
    );
}

/// The registry sweep is only as wide as the compiled feature set; make an
/// empty registry a failure rather than a vacuous pass, like the other audits.
#[test]
fn the_audit_has_something_to_inspect() {
    assert!(
        !registry().all_protocols().is_empty(),
        "no protocol is registered in this build; the audit above inspected nothing"
    );
}
