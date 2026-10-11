//! A server with a TCP accept loop and no **peer handle** leaves the operator holding a
//! decision they cannot act on.
//!
//! `[ message this peer ]` and `[ disconnect this peer ]` are drawn on every live peer row, and
//! `src/tui/projection.rs` enables them from `AppState::has_peer_handle` alone. Without a
//! handle both stay dim and say why — the protocol's own reason where it declares
//! `request_only` (HTTP and the protocols on plain HTTP request/response, which have no way to
//! message a peer unprompted at all), "not implemented here yet" everywhere else. That is
//! merely an absence right up until the moment it is not: a `manual` rule parks the peer's
//! event for a **human** (`src/state/intercepts.rs`, 300s by default), the dashboard flags the
//! connection `⚠ waiting for YOUR answer` — and the operator is being asked to decide about a
//! connection they cannot inspect, cannot answer out of band, and cannot hang up. Manual-first
//! is the dashboard's whole premise, so the affordance is at its least optional exactly where
//! it is missing.
//!
//! Adopting it is ~40 lines (`src/server/whois/mod.rs` is the reference), so the cost of the
//! gap is not the work. It is that nobody notices: a missing button reports nothing, fails no
//! test, and looks like a design decision.
//!
//! # The rule
//!
//! Over `src/server/*/mod.rs` and `src/server/*/*/mod.rs`, with `//` comments stripped first,
//! a protocol **runs a TCP accept loop** when its `mod.rs` contains any of
//! `TcpListener`, `accept_bounded::accept_bounded(` or `listener.accept().await` — and is not a
//! Unix-domain listener wearing the third of those (see the false-positive note). Such a
//! protocol must either call `peer_support::register_peer_channel`, declare an exchange-only
//! `request_only` contract with no raw-output actions, or appear in
//! [`NO_PEER_HANDLE_BASELINE`] with a reason.
//!
//! **The baseline may only shrink.** A protocol that gains a handle and stays listed fails the
//! test as a stale entry, so the list cannot rot in the direction that hides progress.
//!
//! # Reasons are checked, not asserted
//!
//! The usual failure of a baseline-with-comments is that the comment stops being true and
//! nothing notices — this repository has the class recorded several times over. So most
//! reasons here are a **key with a source marker**, and the test asserts the marker is still
//! present in that protocol's `mod.rs`. If `openai` stops serving through hyper, its reason
//! stops being true and the build fails, rather than the file quietly lying. The six entries
//! reviewed by hand carry [`Reason::Reviewed`] and their argument is in the table below, which
//! is the only kind of entry a reader has to take on trust.
//!
//! # Anchoring, and the measurement that made it wider
//!
//! `PROTOCOL_QUALITY.md` measured this as "13 of 32 TCP servers", anchored on the token
//! `TcpListener` in `mod.rs`. That anchor **under-reports by a factor of three**: 62 of the 92
//! TCP accept-loop servers never name the type, because they bind through
//! `accept_bounded`/`socket_helpers` or take a `listener` from a helper and only ever write
//! `listener.accept().await`. `ftp`, `smtp`, `imap`, `tcp` and `telnet` are all in that group,
//! and `tcp` and `telnet` are the two protocols the project `CLAUDE.md` names as *having* the
//! affordance. A scan anchored on one filename or one token is the recurring shape of a wrong
//! number here, so this test uses the wider rule and states the narrower figure only as
//! history.
//!
//! # False positives, measured
//!
//! The naive rule matched **94** directories, of which **2 are not TCP at all**:
//! `socket_file` and `ssh_agent` accept on a `UnixListener` and were caught by
//! `listener.accept().await`. Both are excluded explicitly — a Unix-domain listener with no
//! `TcpListener` and no `accept_bounded` is not a TCP accept loop — which is a 2.1% naive
//! false-positive rate and zero after the exclusion. A build-failing check earns nothing by
//! being approximately right: `startup_param_drift_test.rs` records what happens next, which is
//! that people edit the baseline instead of the code.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test peer_handle_coverage_ratchet_test

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Why a TCP accept-loop server has no peer handle.
///
/// Every variant but [`Reason::Reviewed`] and [`Reason::Unreviewed`] names a token that must
/// still be present in the protocol's `mod.rs`, so the reason is re-derived on every run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reason {
    /// hyper owns the socket from `serve_connection` onward. There is no write half to share,
    /// and raw bytes pushed alongside hyper's framing would desynchronise the HTTP/1.1 or
    /// HTTP/2 stream rather than reach the peer as a message.
    HyperOwnsSocket,
    /// hyper-util owns HTTP/1 or HTTP/2 framing through its auto connection builder;
    /// tonic services answer only their correlated gRPC requests on that connection.
    HyperAutoOwnsSocket,
    /// `axum::serve` owns its own accept loop, and this server additionally relays the public
    /// socket to a loopback backend — so the handler's peer is the relay, not the client.
    AxumOwnsSocket,
    /// USB/IP: the "peer" is a USB host attaching a device, and the protocol's vocabulary is
    /// URBs against endpoints, not a byte stream anything could be injected into. An
    /// `ActionResult::Output` written to that socket is not a message the host can read; it is
    /// garbage in the middle of a URB reply.
    ///
    /// **This doc comment claimed for a while that no protocol carried the reason any more,
    /// because "all six USB servers adopted a peer handle in September 2026". They did not, and
    /// none of them registers one today** — `grep -rn register_peer_channel src/server/usb/`
    /// finds nothing. The six lines were deleted because this test asked for them to be, and it
    /// asked for the wrong reason: `runs_tcp_accept_loop` matched only the fully-qualified
    /// `accept_bounded::accept_bounded(`, so a server that imports the function and calls it
    /// bare read as **not a TCP accept loop at all**. `the_baseline_only_shrinks` says
    /// "now register a peer handle (**or** no longer run a TCP accept loop)", and whoever acted
    /// on it took the first branch.
    ///
    /// Two lessons, and the second is the one that generalises. A source-reading check must
    /// match every spelling of the thing — this is the third instance in one pass, after the TCP
    /// bounds ratchet missing 60 of 92 servers and the hidden-protocol ratchet knowing only the
    /// builder form of a declaration. And **an assertion message that offers two causes invites
    /// the reader to pick the flattering one**; this one now names which cause applies to which
    /// protocol.
    UsbIp,
    /// A WebSocket: the write side is a `SplitSink` behind a writer task, not an `AsyncWrite`.
    /// `peer_support` writes `ActionResult::Output` bytes straight to the socket, which for a
    /// WebSocket is an unframed payload the peer will reject.
    WebSocketFrames,
    /// A byte-for-byte tunnel: once `copy_bidirectional` starts, the socket is moved into it
    /// for the life of the connection and anything injected would land inside whatever
    /// protocol the tunnel carries.
    Tunnel,
    /// The SSH transport is russh's; NetGet never holds the socket after the handshake.
    RusshOwnsSocket,
    /// A Carbon plaintext collector receives metrics but has no server-message grammar.
    OneWayMetricCollector,
    /// A GELF collector observes incoming logs; GELF defines no server replies.
    OneWayLogCollector,
    /// Forward ACKs echo the current inbound batch's transport-owned chunk token.
    CorrelatedForwardReplies,
    /// NUT renders a reply against the current parsed request and authentication state.
    CorrelatedRequestReplies,
    /// Reviewed by hand in the September 2026 peer-handle pass; see the table below.
    Reviewed,
    /// Not reviewed in that pass. Not a claim that a handle is impossible — a claim that
    /// nobody has looked. Shrinking this is the next piece of work.
    Unreviewed,
}

impl Reason {
    /// The token that must still appear in the protocol's `mod.rs` for this reason to hold.
    fn marker(self) -> Option<&'static str> {
        match self {
            Reason::HyperOwnsSocket => Some("hyper::server::conn"),
            Reason::HyperAutoOwnsSocket => Some("hyper_util::server::conn::auto"),
            Reason::AxumOwnsSocket => Some("axum::serve"),
            Reason::UsbIp => Some("usbip"),
            Reason::WebSocketFrames => Some("tokio_tungstenite"),
            Reason::Tunnel => Some("copy_bidirectional"),
            Reason::RusshOwnsSocket => Some("russh"),
            Reason::OneWayMetricCollector => Some("GRAPHITE_BATCH_EVENT"),
            Reason::OneWayLogCollector => Some("actions::GELF_MESSAGE_EVENT"),
            Reason::CorrelatedForwardReplies => Some("codec::encode_ack(&chunk)"),
            Reason::CorrelatedRequestReplies => Some("wire::render(&request"),
            Reason::Reviewed | Reason::Unreviewed => None,
        }
    }

    fn holds_for(self, server: &ServerSource) -> bool {
        match self {
            Self::HyperOwnsSocket => server.hyper_owns_socket(),
            _ => self.marker().is_none_or(|marker| server.has(marker)),
        }
    }
}

/// TCP accept-loop servers with no peer handle, and why.
///
/// **May only shrink.** Adopting the handle means deleting the line; a line left behind for a
/// protocol that has one fails the test.
///
/// The six [`Reason::Reviewed`] entries were each read (five in the September 2026 pass, `dns` in October) and refused
/// for a specific reason, which is recorded here because no marker can carry it:
///
/// * **`dot`** — DNS over TLS frames every message with a two-byte length prefix that the
///   *session* writes, not the action. `DnsProtocol`'s `Output` is a bare DNS message, so
///   `peer_support` writing it verbatim would desynchronise the connection permanently. And an
///   unsolicited DNS response carries a transaction id no resolver is waiting on, so there is
///   nothing useful to send even if the framing were right.
/// * **`dns`** (October 2026, when DNS gained TCP) — the `dot` argument exactly: the
///   connection loop writes each message behind its two-byte length, `DnsProtocol`'s `Output`
///   is a bare message, and an unsolicited answer carries a transaction id no client is
///   waiting on. A zone transfer is several messages to one query, framed the same way.
/// * **`llmnr`** — declares `.connectionless()`, so `AppState::cleanup_old_connections` evicts
///   its connection rows after ten seconds of silence *by design*. A handle would be registered
///   against a row the sweep is about to remove. Its TCP reply is length-prefixed by the
///   session too, exactly as `dot`'s is.
/// * **`mysql`** — the write half is moved into `opensrv`'s `AsyncMysqlIntermediary::run_on`,
///   which owns the packet loop and the sequence numbering. Sharing it is not just awkward:
///   MySQL packets carry a sequence id, so an out-of-band write desynchronises the client even
///   if the bytes are valid.
/// * **`nfs`** — NetGet binds the public listener and relays every connection to `nfsserve` on
///   a loopback port (`src/server/nfs/guard.rs`). The handler's peer is the relay, and an
///   injected RPC record would have to carry the xid of a call the client made, which nothing
///   outside the exchange knows.
/// * **`postgresql`** — `pgwire::tokio::process_socket` takes a concrete `TcpStream` and never
///   exposes it again; `src/server/postgresql/mod.rs` already records that this is why the idle
///   watchdog aborts the task rather than sending a FATAL. The same absence of a seam is why
///   there is no write half to hand `peer_support`.
const NO_PEER_HANDLE_BASELINE: &[(&str, Reason)] = &[
    // Restored 16 September 2026. These six were deleted a day earlier on this test's own
    // instruction, and the instruction was wrong: `runs_tcp_accept_loop` could not see a server
    // that calls `accept_bounded` bare, so it reported them as no longer running an accept loop
    // and `the_baseline_only_shrinks` asked for the lines to go. None of the six registers a
    // peer handle — `grep -rn register_peer_channel src/server/usb/` finds nothing — so the
    // exemption was real the whole time. See `Reason::UsbIp`.
    ("usb/fido2", Reason::UsbIp),
    ("usb/keyboard", Reason::UsbIp),
    ("usb/mouse", Reason::UsbIp),
    ("usb/msc", Reason::UsbIp),
    ("usb/serial", Reason::UsbIp),
    ("usb/smartcard", Reason::UsbIp),
    ("couchdb", Reason::HyperOwnsSocket),
    ("docker", Reason::HyperOwnsSocket),
    ("doh", Reason::HyperOwnsSocket),
    ("dns", Reason::Reviewed),
    ("dot", Reason::Reviewed),
    ("dynamo", Reason::HyperOwnsSocket),
    ("elasticsearch", Reason::HyperOwnsSocket),
    // Acceptance/rejection applies to one inbound batch; only its hidden chunk token can
    // produce the correlated ACK. Injected bytes have no unsolicited Forward reply meaning.
    ("fluent_forward", Reason::CorrelatedForwardReplies),
    // collect_gelf_message only observes; neither UDP nor TCP defines collector reply bytes.
    ("gelf", Reason::OneWayLogCollector),
    ("etcd", Reason::HyperOwnsSocket),
    ("git", Reason::HyperOwnsSocket),
    // Carbon plaintext defines no replies; collect_graphite_batch observes received metrics.
    ("graphite", Reason::OneWayMetricCollector),
    ("hls", Reason::Unreviewed),
    ("http", Reason::HyperOwnsSocket),
    // Hyper owns each HTTP connection and frames each write request response.
    ("influxdb", Reason::HyperOwnsSocket),
    ("ipp", Reason::HyperOwnsSocket),
    ("jsonrpc", Reason::HyperOwnsSocket),
    ("kubernetes", Reason::HyperOwnsSocket),
    ("ldap", Reason::Unreviewed),
    ("llmnr", Reason::Reviewed),
    // Hyper owns each HTTP connection; accept/reject decisions answer one Loki push request.
    ("loki", Reason::HyperOwnsSocket),
    ("maven", Reason::HyperOwnsSocket),
    ("mcp", Reason::AxumOwnsSocket),
    ("mercurial", Reason::HyperOwnsSocket),
    ("mysql", Reason::Reviewed),
    ("nfc", Reason::Unreviewed),
    ("nfs", Reason::Reviewed),
    ("npm", Reason::HyperOwnsSocket),
    // Replies get request identities from wire::render and writes require session auth.
    ("nut", Reason::CorrelatedRequestReplies),
    ("oauth2", Reason::HyperOwnsSocket),
    ("oci_registry", Reason::HyperOwnsSocket),
    ("ollama", Reason::HyperOwnsSocket),
    ("openai", Reason::HyperOwnsSocket),
    ("openapi", Reason::HyperOwnsSocket),
    ("openid", Reason::HyperOwnsSocket),
    // Hyper owns HTTP/1 and HTTP/2 sockets; tonic frames each correlated gRPC export reply.
    ("otlp", Reason::HyperAutoOwnsSocket),
    ("postgresql", Reason::Reviewed),
    ("prometheus", Reason::HyperOwnsSocket),
    ("proxy", Reason::Tunnel),
    ("pypi", Reason::HyperOwnsSocket),
    ("rss", Reason::HyperOwnsSocket),
    ("s3", Reason::HyperOwnsSocket),
    ("saml_idp", Reason::HyperOwnsSocket),
    ("saml_sp", Reason::HyperOwnsSocket),
    ("snowflake", Reason::HyperOwnsSocket),
    ("socks5", Reason::Tunnel),
    ("spark", Reason::HyperOwnsSocket),
    ("sqs", Reason::HyperOwnsSocket),
    ("ssh", Reason::RusshOwnsSocket),
    ("vault", Reason::HyperOwnsSocket),
    ("webdav", Reason::HyperOwnsSocket),
    ("webrtc", Reason::WebSocketFrames),
    ("webrtc_signaling", Reason::WebSocketFrames),
    ("websocket", Reason::WebSocketFrames),
    ("xmlrpc", Reason::HyperOwnsSocket),
    ("yarn", Reason::HyperOwnsSocket),
];

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

/// Drop `//` comments so prose *about* a token is not read as the token.
///
/// This repository has hit the matching-prose false positive at least three times, most
/// recently on a ratchet that flagged its own explanatory comment.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn server_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server")
}

/// `<protocol>` or `<family>/<protocol>` for every `mod.rs` under `src/server`.
fn server_mod_files() -> Vec<(String, PathBuf)> {
    let root = server_root();
    let mut out = Vec::new();
    let mut dirs = vec![(String::new(), root.clone())];
    while let Some((prefix, dir)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let key = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            let module = path.join("mod.rs");
            if module.is_file() {
                out.push((key.clone(), module));
            }
            // One level of nesting is all the tree has (`usb/serial`, `bluetooth_ble_*` are
            // flat), and recursing further would walk into nothing.
            if prefix.is_empty() {
                dirs.push((key, path));
            }
        }
    }
    out.sort();
    out
}

struct ServerSource {
    name: String,
    body: String,
    // Metadata and protocol actions usually live beside mod.rs, in actions.rs. Read the
    // complete directory so declarations are not missed just because they moved files.
    contract: String,
}

impl ServerSource {
    fn has(&self, needle: &str) -> bool {
        self.body.contains(needle)
    }

    fn has_hyper_connection_marker(&self) -> bool {
        if self.has("hyper::server::conn") {
            return true;
        }
        // A grouped import has the same path, but `server::conn` must be an item
        // directly under `hyper`, rather than an unrelated import elsewhere.
        for (at, _) in self.body.match_indices("use") {
            let is_word = |c: char| c.is_alphanumeric() || c == '_';
            if self.body[..at].chars().next_back().is_some_and(is_word)
                || self.body[at + 3..].chars().next().is_some_and(is_word)
            {
                continue;
            }
            let import: String = self.body[at + 3..]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let Some(group) = import.strip_prefix("hyper::{") else {
                continue;
            };
            let mut depth = 0;
            let mut start = 0;
            for (end, character) in group.char_indices() {
                if (character == ',' || character == '}') && depth == 0 {
                    let item = &group[start..end];
                    if item == "server::conn" || item.starts_with("server::conn::") {
                        return true;
                    }
                    if character == '}' {
                        break;
                    }
                    start = end + 1;
                } else if character == '{' {
                    depth += 1;
                } else if character == '}' {
                    depth -= 1;
                }
            }
        }
        false
    }

    /// Does this server run a TCP accept loop of its own?
    ///
    /// Three spellings, because the tree has three. `listener.accept().await` is the one that
    /// catches a server whose listener came from a helper — which is 62 of the 92, including
    /// both protocols the project `CLAUDE.md` cites as having a peer handle.
    fn runs_tcp_accept_loop(&self) -> bool {
        // **Both spellings of the bounded accept.** Matching only the fully-qualified
        // `accept_bounded::accept_bounded(` reported eleven servers — the whole registry and
        // cloud family — as no longer running a TCP accept loop the moment they adopted it,
        // because they `use crate::server::accept_bounded::accept_bounded` and then call it
        // bare. The failure was loud here only because this baseline is shrink-only; the
        // equivalent miss in a "must have a bound" check would have exempted them silently.
        //
        // This is the third time in one pass that a source-reading check matched one spelling
        // of a thing rather than the thing: see `tests/tcp_server_bounds_ratchet_test.rs`, whose
        // derivation missed 60 of 92 servers, and `no_protocol_is_hidden_from_the_model_test`,
        // which knew only the builder form of a metadata declaration.
        let matched = self.has("TcpListener")
            || self.has("accept_bounded(")
            || self.has("listener.accept().await");
        if !matched {
            return false;
        }
        // The one false positive of the rule above: a Unix-domain listener also spells its
        // accept `listener.accept().await`. `socket_file` and `ssh_agent` are the two, and a
        // peer handle over an `AF_UNIX` stream is a separate question from this one.
        let unix_only =
            self.has("UnixListener") && !self.has("TcpListener") && !self.has("accept_bounded(");
        !unix_only
    }

    fn registers_peer_handle(&self) -> bool {
        self.contract.contains("register_peer_channel")
    }

    fn hyper_owns_socket(&self) -> bool {
        self.has_hyper_connection_marker() || self.has("hyper_util::server::conn")
    }

    fn declares_exchange_only(&self) -> bool {
        let declared = self.contract.contains(".request_only(")
            || regex::Regex::new(r"request_only:\s*Some\(")
                .unwrap()
                .is_match(&self.contract);
        // A raw-output action can be injected without an exchange identity, contradicting
        // this exemption. The separate declaration test also rejects an existing handle.
        declared && !self.contract.contains("ActionResult::Output")
    }
}

fn load_servers() -> Vec<ServerSource> {
    server_mod_files()
        .into_iter()
        .map(|(name, path)| {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let mut contract = String::new();
            for file in std::fs::read_dir(path.parent().expect("protocol directory"))
                .expect("read protocol directory")
            {
                let file = file.expect("protocol file").path();
                if file.extension().is_some_and(|extension| extension == "rs") {
                    contract.push_str(&strip_comments(
                        &std::fs::read_to_string(&file).expect("read protocol source"),
                    ));
                    contract.push('\n');
                }
            }
            if contract.contains("ics_support::spawn") {
                contract.push_str(&strip_comments(
                    &std::fs::read_to_string("src/server/ics_support.rs")
                        .expect("shared ICS peer owner"),
                ));
            }
            ServerSource {
                name,
                body: strip_comments(&raw),
                contract,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn every_tcp_accept_loop_server_has_a_peer_handle_or_a_reason() {
    let servers = load_servers();
    let baselined: BTreeSet<&str> = NO_PEER_HANDLE_BASELINE.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        baselined.len(),
        NO_PEER_HANDLE_BASELINE.len(),
        "NO_PEER_HANDLE_BASELINE lists a protocol twice"
    );

    let mut undeclared = Vec::new();
    for server in &servers {
        if !server.runs_tcp_accept_loop() || server.registers_peer_handle() {
            continue;
        }
        if !baselined.contains(server.name.as_str()) && !server.declares_exchange_only() {
            undeclared.push(server.name.clone());
        }
    }

    assert!(
        undeclared.is_empty(),
        "these servers run a TCP accept loop and register no peer handle, so the dashboard's\n\
         [ message this peer ] / [ disconnect this peer ] are dim on every one of their peers —\n\
         including a peer whose event is parked waiting for a human's answer:\n\n  {}\n\n\
         Adopt the handle (`src/server/whois/mod.rs` is the ~40-line reference), or add an entry\n\
         to NO_PEER_HANDLE_BASELINE in {} with a reason. Adding a line is not how you pass this\n\
         test unless the protocol genuinely cannot carry an injected action.",
        undeclared.join("\n  "),
        file!(),
    );
}

#[test]
fn the_baseline_only_shrinks() {
    let servers = load_servers();
    let mut adopted = Vec::new();
    let mut not_a_tcp_server = Vec::new();
    let mut vanished = Vec::new();

    for (name, _) in NO_PEER_HANDLE_BASELINE {
        match servers.iter().find(|s| s.name == *name) {
            None => vanished.push(*name),
            Some(server) => {
                // **The two causes are reported separately, and that is not cosmetic.** This
                // used to be one list under the message "now register a peer handle (or no
                // longer run a TCP accept loop)". On 15 September 2026 the six USB servers
                // appeared in it because `runs_tcp_accept_loop` could not see a bare
                // `accept_bounded(` call — the second cause — and their lines were deleted
                // under a commit message saying they had "adopted a peer handle", the first.
                // None of them had. A message that offers two causes invites the reader to pick
                // the flattering one.
                if server.registers_peer_handle() {
                    adopted.push(*name);
                } else if !server.runs_tcp_accept_loop() {
                    not_a_tcp_server.push(*name);
                }
            }
        }
    }

    assert!(
        adopted.is_empty(),
        "these protocols now REGISTER A PEER HANDLE but are still listed in\n\
         NO_PEER_HANDLE_BASELINE — delete their lines:\n\n  {}",
        adopted.join("\n  "),
    );
    assert!(
        not_a_tcp_server.is_empty(),
        "these protocols are listed in NO_PEER_HANDLE_BASELINE and NO LONGER READ AS A TCP\n\
         ACCEPT LOOP. That is NOT the same as adopting a peer handle, and the difference has\n\
         already cost one wrong deletion. Check which it is before touching the baseline:\n\n  \
         {}\n\n\
         If the protocol really stopped listening on TCP, delete the line. If it only changed\n\
         HOW it accepts — a new helper, a different spelling of the call — then the detector in\n\
         `runs_tcp_accept_loop` is what needs fixing, and deleting the line would silently drop\n\
         a protocol out of this ratchet's coverage.",
        not_a_tcp_server.join("\n  "),
    );
    assert!(
        vanished.is_empty(),
        "NO_PEER_HANDLE_BASELINE names protocols that no longer exist under src/server:\n\n  {}",
        vanished.join("\n  "),
    );
}

#[test]
fn every_declared_reason_is_still_true_of_the_source() {
    let servers = load_servers();
    let mut wrong = Vec::new();

    for (name, reason) in NO_PEER_HANDLE_BASELINE {
        let Some(marker) = reason.marker() else {
            continue;
        };
        let Some(server) = servers.iter().find(|s| s.name == *name) else {
            continue; // reported by the shrink test
        };
        if !reason.holds_for(server) {
            wrong.push(format!(
                "{name}: declared {reason:?}, but its framing source marker `{marker}` is gone"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "a baselined reason has stopped being true of the code it describes. That is the failure\n\
         mode a plain comment has and this table exists to avoid: re-read the protocol and either\n\
         adopt the peer handle or give it the reason that is now correct.\n\n  {}",
        wrong.join("\n  "),
    );
}

#[test]
fn grouped_hyper_connection_marker_requires_the_hyper_import_path() {
    let matches = |body: &str| {
        ServerSource {
            name: "fixture".into(),
            body: strip_comments(body),
            contract: String::new(),
        }
        .has_hyper_connection_marker()
    };
    assert!(matches("use hyper::server::conn::http1;"));
    assert!(matches(
        "use hyper::{body::Incoming, header::{HeaderValue, ALLOW},\n server::conn::http1, Method};"
    ));
    assert!(matches("use hyper::{body::Incoming, server::conn};"));
    assert!(!matches("use unrelated::{server::conn::http1};"));
    assert!(!matches(
        "use hyper::{body::Incoming}; use unrelated::server::conn::http1;"
    ));
    assert!(!matches("use hyper::{header::{server::conn::http1}};"));
    assert!(!matches("// use hyper::{server::conn::http1};"));
}

/// The count this pass left behind, so a regression is visible as a number and not only as a
/// named protocol.
///
/// Both figures may only move in one direction: more servers with a handle, fewer without.
#[test]
fn peer_handle_coverage_does_not_regress() {
    let servers = load_servers();
    let tcp: Vec<&ServerSource> = servers
        .iter()
        .filter(|s| s.runs_tcp_accept_loop())
        .collect();
    let with_handle = tcp.iter().filter(|s| s.registers_peer_handle()).count();

    // 92 TCP accept-loop servers, 40 of them with a peer handle after the September 2026
    // adoption pass — 32 before it. The floor is what matters; the total is printed for
    // context and is allowed to grow as protocols are added.
    const MIN_WITH_HANDLE: usize = 40;
    assert!(
        with_handle >= MIN_WITH_HANDLE,
        "peer-handle coverage went backwards: {with_handle} of {} TCP accept-loop servers \
         register one, and {MIN_WITH_HANDLE} did at the last measurement. A protocol lost its \
         handle, or the detection stopped seeing it.",
        tcp.len(),
    );
}

#[test]
fn exchange_only_contract_requires_a_declaration_and_no_raw_output() {
    let source = |contract: &str| ServerSource {
        name: "fixture".into(),
        body: "TcpListener::bind(addr);".into(),
        contract: strip_comments(contract),
    };
    assert!(!source("// .request_only(\"comment\")").declares_exchange_only());
    assert!(!source("ActionResult::Custom { name, data }").declares_exchange_only());
    assert!(source(
        "builder.request_only(\"correlated replies\"); ActionResult::Custom { name, data }"
    )
    .declares_exchange_only());
    assert!(source("request_only: Some(\"no unsolicited messages\")").declares_exchange_only());
    assert!(
        !source("builder.request_only(\"incorrect\"); ActionResult::Output(bytes)")
            .declares_exchange_only()
    );
}

#[test]
fn hyper_framing_reason_recognizes_both_library_import_forms() {
    for body in [
        "hyper::server::conn::http1::Builder::new()",
        "use hyper::{server::conn::http1}; http1::Builder::new()",
        "use hyper_util::server::conn::auto; auto::Builder::new()",
    ] {
        let source = ServerSource {
            name: "fixture".into(),
            body: strip_comments(body),
            contract: String::new(),
        };
        assert!(Reason::HyperOwnsSocket.holds_for(&source), "{body}");
    }
    let source = ServerSource {
        name: "fixture".into(),
        body: strip_comments("// hyper_util::server::conn::auto"),
        contract: String::new(),
    };
    assert!(!Reason::HyperOwnsSocket.holds_for(&source));
}
