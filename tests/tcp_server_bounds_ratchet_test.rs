//! Ratchet: every TCP accept-loop server declares a read deadline and a connection cap.
//!
//! This reads the **source tree**, not the registry, so it holds at any feature set — including
//! the six-protocol CI gate, where a registry-walking test only ever sees what that build
//! compiled. Every protocol directory under `src/server` whose `mod.rs` opens a TCP accept loop
//! must name a timeout constant *and* go through `crate::server::accept_bounded`, somewhere in
//! that directory (nfs declares both in `guard.rs`, which is the right place for it).
//!
//! # This test could not see two thirds of the tree, and that is the part worth reading
//!
//! Until 16 September 2026 the derivation was `mod_src.contains("TcpListener")`. Most servers
//! here do not write that: they call `crate::server::socket_helpers::create_reusable_tcp_listener`,
//! whose *return type* is a `TcpListener` but whose call site never names one. So this ratchet
//! walked **32** servers while **92** open a TCP accept loop, and the 60 it could not see
//! included `http`, `tcp`, `telnet`, `ssh`, `ldap`, `imap`, `grpc`, `modbus`, `git` and
//! `kubernetes`.
//!
//! **47 of those 60 had neither bound** — no cap and no deadline. A peer that connects and says
//! nothing holds a socket, a task and an `AppState` entry forever, pre-authentication, on a
//! server that will happily accept a hundred more; that is the free denial of service this test
//! exists to prevent, and it was sitting behind the test's own blind spot.
//!
//! The lesson is the recurring one in this repository: **the test counted a token, not the
//! thing.** A source-reading check must match every way the thing is actually written, and a
//! green result over an unmeasured population is worse than no check, because it is trusted.
//!
//! # The baselines are large on purpose
//!
//! Both are **shrink-only**, and they now record real, measured debt rather than an artefact of
//! what the derivation happened to match. Adding a protocol to either is not a fix; it is a
//! statement, with a reason, that the bound cannot be expressed there — and the reason has to be
//! good enough to survive review. Removing one is the work.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test tcp_server_bounds_ratchet_test -- --test-threads=100

#[path = "helpers/fork_source.rs"]
mod fork_source;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Protocols that open a TCP accept loop without naming a read deadline.
///
/// Measured 16 September 2026 across all 92, once the derivation stopped missing the servers
/// that bind through `create_reusable_tcp_listener`. The previous value of this list was empty,
/// which was true of the 32 it could see and false of the tree.
///
/// Entries are **leaf names** (`serial`, not `usb/serial`) — see `leaf()`.
///
/// Nothing here makes a deadline impossible. This is work left.
///
/// **Empty as of 22 September 2026, and it may only stay that way.** Every one of the 92 TCP
/// accept loops now names a read deadline. The last five were `nfc`, `ollama`, `openai`, `rtsp`
/// and `xmpp`; the two hyper servers among them (`ollama`, `openai`) took the `peek` +
/// `ConnectionActivity` shape `etcd` and `s3` established rather than a deadline inside hyper's
/// own reads, because hyper keeps polling a connection while a request is being answered and
/// such a deadline fires in the middle of a model round-trip.
///
/// That "every one of the 92" was true of the population this test measured and false of the
/// tree: when the population was widened on 26 September 2026 (see [`tcp_servers`]) it grew to
/// 95, and the three it had missed — `http2`, `socket_file`, `ssh_agent` — had no deadline at
/// all. They were fixed rather than baselined, so the list is still empty.
const TIMEOUT_BASELINE: &[&str] = &[];

/// Protocols that open a TCP accept loop without a connection cap.
///
/// Measured 16 September 2026 across all 92. The list held 14 then — the ones the old
/// derivation could see — and reached 25 once the derivation stopped missing two thirds of the
/// tree.
///
/// **Empty as of 22 September 2026, and it may only stay that way.** Every one of the 92 TCP
/// accept loops now goes through `crate::server::accept_bounded`. The last ten were `amqp`,
/// `bgp`, `doh`, `dot`, `llmnr`, `mongodb`, `socks5`, `webrtc`, `webrtc_signaling` and
/// `websocket`; five of them answer in a protocol vocabulary of their own (SOCKS5's
/// `NO ACCEPTABLE METHODS`, AMQP's `Connection.Close` 320, BGP's Cease/Out-of-Resources
/// NOTIFICATION, and an HTTP 503 for the two WebSocket-carried ones), and five refuse with a
/// plain close because every message they could send would have to echo something the refused
/// peer never sent — or, for `doh` and `dot`, would be a malformed TLS record rather than a
/// refusal at all.
///
/// The widened population of 26 September 2026 found three more with no cap — `http2`,
/// `socket_file` and `ssh_agent` — and all three now go through `accept_bounded` or its Unix
/// twin `accept_bounded_unix`.
///
/// Nothing here makes a cap impossible. This is work left.
const CAP_BASELINE: &[&str] = &[];

/// Ways a read is actually bounded in time — **mechanisms, not names**.
///
/// This list used to include `READ_TIMEOUT`, `IDLE_` and `_TIMEOUT`, which match a *constant's
/// name* rather than anything that enforces a deadline. `_TIMEOUT` over-matched badly:
/// `snowflake` was absent from `TIMEOUT_BASELINE` while having no read bound at all, because it
/// declares `CODE_REQUEST_TIMEOUT = "000629"` — a Snowflake error *code*, a string. The protocol
/// was silently exempted by its own error table.
///
/// **A loose list fails in the dangerous direction.** A protocol that has no bound but happens
/// to contain a matching word passes and nobody looks again; a protocol that has one but spells
/// it unusually gets flagged, which costs a reader five minutes. Prefer the second. Re-measured
/// across all 92 when this was tightened: it flags nothing that is not already on the baseline,
/// so the loose version was buying no coverage at all — only the snowflake-shaped hole.
///
/// `timeout(` is bare rather than `tokio::time::timeout(` because most of the tree imports it.
/// `Instant::now() +` catches the hand-rolled deadline loop that `hls`, `ipp` and the
/// `accept_bounded` helpers use.
const TIMEOUT_TOKENS: &[&str] = &[
    "timeout(",
    "IdleTimeoutReader",
    "watch_idle",
    "Instant::now() +",
    "sleep_until",
    "set_read_timeout",
];

fn server_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server")
}

/// Every protocol directory under `src/server` that opens a stream accept loop — TCP or Unix
/// domain — with the whole directory's Rust source concatenated, because a protocol may put its
/// bounds in a sibling module, and `nfs` does exactly that.
///
/// **The listener is looked for in every `.rs` file of the directory, not only `mod.rs`.**
/// Until 26 September 2026 only `mod.rs` was read for it, and three servers were invisible:
/// `http2` binds in `h2_server.rs`, while `socket_file` and `ssh_agent` bind a `UnixListener`,
/// which was not counted as a listener at all. All three had neither a connection cap nor a read
/// deadline — the "counted a token, not the thing" blind spot the module comment describes, one
/// file over. Widening the population added exactly those three directories and no other, so it
/// costs no false positives; the run on the unfixed tree flagged all three in both checks.
fn tcp_servers() -> Vec<(String, String)> {
    let root = server_root();
    let mut found = Vec::new();

    for entry in walk_dirs(&root) {
        let mut own_source = rust_sources(&entry);
        if own_source.contains("ics_support::spawn") {
            // These codecs delegate their socket ownership, cap and read deadlines.
            own_source.push_str(
                &std::fs::read_to_string(root.join("ics_support.rs")).expect("ICS transport owner"),
            );
        }
        // Every way a server here opens a stream accept loop, looked for in every file of the
        // directory. Matching only `TcpListener` is what hid 60 of 92 protocols from this test:
        // `create_reusable_tcp_listener` returns a `TcpListener` without its caller ever
        // writing the type. `UnixListener` is the same accept-loop shape over a filesystem
        // socket, with the same exposure to a peer that connects and says nothing.
        if !LISTENER_TOKENS
            .iter()
            .any(|token| own_source.contains(token))
        {
            continue;
        }
        let name = entry
            .strip_prefix(&root)
            .expect("under src/server")
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");

        // A protocol's own directory, plus — for one that nests a level deeper — its family
        // directory. `nfs` declares both its bounds in `nfs/guard.rs`, a sibling module, and
        // this walk has always picked that up because it is in the same directory. The USB
        // family is the same arrangement one level out: all six protocols hand their socket to
        // `usb/guard.rs`, which is the only thing in the process that reads from it, so
        // `usb/keyboard` declaring the bound in its own `mod.rs` would mean six copies of one
        // number. Without this, the check measured a token's *location* rather than whether a
        // read is bounded — the same class of blind spot as the `TcpListener` one above.
        let mut combined = own_source;
        if let Some(family) = family_dir(&root, &entry) {
            combined.push_str(&rust_sources(family));
        }
        found.push((name, combined));
    }

    found.sort();
    found
}

/// How a server opens a stream accept loop. See [`tcp_servers`].
const LISTENER_TOKENS: &[&str] = &[
    "TcpListener",
    "create_reusable_tcp_listener",
    "UnixListener",
];

/// Every `.rs` file directly in `dir`, concatenated. Nested directories are protocols of their
/// own in [`walk_dirs`], so they are not folded in here.
fn rust_sources(dir: &Path) -> String {
    let mut combined = String::new();
    for file in std::fs::read_dir(dir).expect("read protocol dir").flatten() {
        let path = file.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                combined.push_str(&text);
            }
        }
    }
    combined
}

/// The family directory of a protocol that nests one level deeper (`src/server/usb` for
/// `src/server/usb/keyboard`), or `None` for a top-level protocol.
///
/// Only the family's own `.rs` files are read, never a sibling protocol's, so `usb/keyboard`
/// cannot be exempted by something `usb/msc` declares.
fn family_dir<'a>(root: &Path, entry: &'a Path) -> Option<&'a Path> {
    let parent = entry.parent()?;
    (parent != root).then_some(parent)
}

/// `src/server/<p>` and `src/server/<family>/<p>` — the USB and Bluetooth families nest one
/// level deeper.
fn walk_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(root).expect("read src/server").flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        dirs.push(path.clone());
        for nested in std::fs::read_dir(&path).expect("read nested").flatten() {
            let nested = nested.path();
            if nested.is_dir() {
                dirs.push(nested);
            }
        }
    }
    dirs
}

/// The protocol name a baseline entry uses: the last path segment, so `usb/serial` is `serial`
/// and a top-level `redis` is `redis`.
fn leaf(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

#[test]
fn every_tcp_accept_loop_declares_a_read_deadline() {
    let allowed: BTreeSet<&str> = TIMEOUT_BASELINE.iter().copied().collect();
    let mut missing = Vec::new();

    for (name, source) in tcp_servers() {
        if allowed.contains(leaf(&name)) {
            continue;
        }
        if !bounds_a_read_in_time(&source) {
            missing.push(name);
        }
    }

    assert!(
        missing.is_empty(),
        "these TCP servers bind a listener and never bound a read in time, so a peer that \
         connects and says nothing holds a socket, a task and an AppState entry forever:\n  \
         {}\n\nGive each the pair `src/server/whois/mod.rs` established — one bound on the \
         silence of a peer that has produced nothing, a longer one on a peer already in a \
         session — with the value argued per protocol in the comment beside it. Wrap the \
         read() and nothing else, so a model round-trip and a `manual` rule parking an event \
         for a human sit outside the deadline by construction.",
        missing.join("\n  ")
    );
}

#[test]
fn every_tcp_accept_loop_goes_through_the_shared_connection_cap() {
    let allowed: BTreeSet<&str> = CAP_BASELINE.iter().copied().collect();
    let mut seen_allowed = BTreeSet::new();
    let mut missing = Vec::new();

    for (name, source) in tcp_servers() {
        let has_cap = source.contains("accept_bounded")
            || (name == "opcua" && source.contains("server.run_with(listener)") && {
                // The external stack owns its accept loop. Verify the real bounded loop in
                // NetGet's fork (netget-async-opcua-server), rather than exempting this protocol
                // from the connection-cap ratchet.
                let adapter =
                    fork_source::read_fork("netget-async-opcua-server", "src/server.rs");
                adapter.contains("self.connections.len() < 256")
                    && adapter.contains("if accepting =>")
            });
        if allowed.contains(leaf(&name)) {
            if has_cap {
                // It grew a cap: the baseline entry is stale and must go.
                seen_allowed.insert(leaf(&name).to_string());
            }
            continue;
        }
        if !has_cap {
            missing.push(name);
        }
    }

    assert!(
        missing.is_empty(),
        "these TCP servers accept without limit, so a read deadline alone still lets an \
         attacker hold `deadline x rate` connections at once:\n  {}\n\nCall \
         `crate::server::accept_bounded::accept_bounded` in place of `listener.accept()`, \
         declare a MAX_CONNECTIONS and a CONNECTION_CAP_REFUSAL in the protocol's own mod.rs, \
         and move the returned permit into the connection task.",
        missing.join("\n  ")
    );

    assert!(
        seen_allowed.is_empty(),
        "these protocols are on CAP_BASELINE but now do call accept_bounded — remove them from \
         the list, which may only shrink: {:?}",
        seen_allowed
    );
}

#[test]
fn the_protocols_these_sweeps_covered_have_both_bounds() {
    // Named explicitly rather than derived, because the point of the list is that each entry
    // was measured by hand and has a wire-driven test of its own.
    //
    // The first eighteen are the original sweep: the 18 of 32 that referenced no read or idle
    // timeout at all. The twenty after them are the two connection-cap batches of
    // September 2026 — each has a `tests/server/<p>/connection_bounds_test.rs` that fills the
    // cap from the wire, asserts how the next peer is refused, and asserts that closing one
    // admitted connection frees exactly one slot.
    //
    // A protocol belongs here only when **both** bounds are real, which is why this list is
    // shorter than "everything that has been touched": the assertions below are the pin, so an
    // entry that has a cap and no deadline would fail rather than record a gap. Both batches
    // were checked against these three conditions before being added.
    const SWEPT: &[&str] = &[
        "cassandra",
        "db2",
        "etcd",
        "kafka",
        "m3ua",
        "mcp",
        "memcached",
        "mssql",
        "mysql",
        "nfs",
        "postgresql",
        "redis",
        "smb",
        "svn",
        "tls",
        "tor_relay",
        "torrent_peer",
        "zookeeper",
        // Connection-cap batch one (September 2026).
        "finger",
        "gopher",
        "hls",
        "ident",
        "ipp",
        "mqtt",
        "proxy",
        "smtp",
        "torrent_tracker",
        "whois",
        // Connection-cap batch two, which emptied CAP_BASELINE.
        "amqp",
        "bgp",
        "doh",
        "dot",
        "llmnr",
        "mongodb",
        "socks5",
        "webrtc",
        "webrtc_signaling",
        "websocket",
        // The three the widened population found (26 September 2026). Each has a
        // `connection_bounds_test.rs` that fills the cap from the wire and drives both read
        // bounds from the peer's side.
        "http2",
        "socket_file",
        "ssh_agent",
        // New protocols, born with both bounds (Programme 4).
        "dict",
        "gemini",
        "bolt",
        "nostr",
        // Programme 4 new HTTP-layered servers, each with a connection_bounds_test.rs driving
        // the shared tests/helpers/http_bounds.rs checks.
        "prometheus",
        "docker",
        "vault",
        "beanstalkd",
        "zabbix",
        "gearman",
        "nsq",
        "otlp",
    ];

    let servers = tcp_servers();
    for protocol in SWEPT {
        let (_, source) = servers
            .iter()
            .find(|(name, _)| leaf(name) == *protocol)
            .unwrap_or_else(|| panic!("{protocol} no longer opens a listener in its directory"));

        assert!(
            TIMEOUT_TOKENS.iter().any(|token| source.contains(token)),
            "{protocol} lost its read deadline"
        );
        assert!(
            source.contains("accept_bounded"),
            "{protocol} lost its connection cap"
        );
        assert!(
            source.contains("MAX_CONNECTIONS") || source.contains("MAX_CONCURRENT_CONNECTIONS"),
            "{protocol} must declare its own cap constant, so the number is documented where \
             the protocol is rather than inherited invisibly"
        );
    }
}

/// Does this protocol's source actually bound a read in time?
///
/// A direct mechanism from [`TIMEOUT_TOKENS`], **or** the `select!`-arm idiom: a
/// `tokio::time::sleep` racing the read, with a timeout or deadline binding to sleep for.
///
/// That second form is why this is a function rather than a flat list. `nats` writes
///
/// ```ignore
/// let read_deadline = if spoke_once { IDLE_BETWEEN_FRAMES_TIMEOUT } else { FIRST_FRAME_READ_TIMEOUT };
/// tokio::select! {
///     n = read_half.read(&mut buf) => n?,
///     _ = tokio::time::sleep(read_deadline) => { /* close */ }
/// }
/// ```
///
/// which is a real deadline on a real read and matches none of the direct tokens. Flagging it
/// was a false positive — in the safe direction, but still wrong.
///
/// **The conjunct is what keeps this from sliding back into name-matching.** `time::sleep(`
/// alone would pass any protocol with a retry backoff or a keepalive timer; a `_TIMEOUT`
/// identifier alone is what silently exempted `snowflake`, whose only match was
/// `CODE_REQUEST_TIMEOUT = "000629"` — a Snowflake error code, a string, with no timing code
/// anywhere in the directory. Requiring **both** a real sleep call and a deadline to sleep for
/// still catches that: a protocol that bounds nothing has no `sleep` to pair with the name.
fn bounds_a_read_in_time(source: &str) -> bool {
    if TIMEOUT_TOKENS.iter().any(|token| source.contains(token)) {
        return true;
    }
    let sleeps = source.contains("time::sleep(");
    let has_deadline = source.contains("_TIMEOUT") || source.contains("_deadline");
    sleeps && has_deadline
}

// ---------------------------------------------------------------------------------------------
// A deadline that only covers the handshake
// ---------------------------------------------------------------------------------------------

/// Every accept loop's deadlines must reach past its handshake.
///
/// [`every_tcp_accept_loop_declares_a_read_deadline`] asks whether a directory bounds *a* read in
/// time, and a `timeout(` anywhere satisfies it. Six servers satisfied it with a deadline that
/// covered nothing a peer does once connected: `doh`, `socks5`, `websocket`, `webrtc` and
/// `webrtc_signaling` bounded only their handshake — TLS, the SOCKS5 greeting, the HTTP upgrade
/// head — and `mqtt`'s one `timeout(` waited on its own writer task at exit. After the handshake
/// each read loop awaited the peer with nothing racing it, so a peer that went quiet, or vanished
/// without a FIN, held its slot forever. All six are fixed (September 2026) and this test keeps
/// the shape from coming back.
///
/// # The rule, and why it is this narrow
///
/// A directory is flagged when **every** `timeout(` call in its code is one of:
///
/// * **a handshake bound** — the call's arguments mention `handshake` (`TLS_HANDSHAKE_TIMEOUT`,
///   `HANDSHAKE_TIMEOUT_SECS`, `SIGNALLING_HANDSHAKE_TIMEOUT`), or
/// * **a join on its own task** — the awaited expression is a bare identifier naming a handle or
///   a writer (`timeout(d, writer_handle)`), which bounds how long *we* wait for *ourselves*,
///
/// **and** it has no other deadline mechanism: none of [`POST_HANDSHAKE_MECHANISMS`], and no
/// `time::sleep(` whose argument names a read, an idle bound or a deadline (the `select!` idiom
/// `nats` uses — its accept-error backoff `sleep(from_millis(50))` is not one, which is why the
/// argument is inspected rather than the call counted).
///
/// Measured on the tree before the six were fixed (`1e1ad6c0`), across all 95 stream servers,
/// it flagged **exactly those six and nothing else**; on the fixed tree it flags nothing. A
/// server whose only deadline is on its handshake but *named* differently is not caught — the
/// rule reads names, and a loose name list is what exempted `snowflake` from the check above for
/// months. It errs toward missing a case rather than training people to edit a baseline, and
/// the miss is the direction the module comment warns about, so it is said here: a handshake
/// deadline spelled `CONNECT_WAIT` would pass.
///
/// What it deliberately does not try to do is prove that a *post*-handshake bound covers the
/// right read. That needs dataflow, not text: `mqtt`'s fixed read deadline and a hypothetical
/// deadline on some unrelated helper look the same to a scan. The per-protocol
/// `connection_bounds_test.rs` suites, which drive an idle peer from the wire, are what answer
/// that — this test only catches the directory that has no candidate at all.
#[test]
fn no_accept_loop_bounds_only_its_handshake() {
    let mut flagged = Vec::new();
    for (name, source) in tcp_servers() {
        let code = strip_line_comments(&source);
        let calls = timeout_call_arguments(&code);
        if calls.is_empty() {
            // No `timeout(` at all: the check above decides whether something else bounds it.
            continue;
        }
        let kinds: Vec<&str> = calls.iter().map(|c| classify_timeout(c)).collect();
        let only_handshake_or_join = kinds.iter().all(|k| *k != "other");
        let has_other_mechanism = POST_HANDSHAKE_MECHANISMS
            .iter()
            .any(|token| code.contains(token))
            || sleeps_on_a_read_deadline(&code);
        if only_handshake_or_join && !has_other_mechanism {
            flagged.push(format!("{name} (timeouts: {})", kinds.join(", ")));
        }
    }

    assert!(
        flagged.is_empty(),
        "these servers' only deadlines are on a handshake or on joining their own task, so once a \
         peer is past the handshake nothing bounds how long it may sit silent:\n  {}\n\nBound the \
         post-handshake read too. Own the read loop: a `timeout` around the read and nothing \
         else (`mqtt`, `ssh_agent`). A crate owns the loop: `watch_idle` over a \
         `ConnectionActivity` the answer holds busy (`doh`, `http2`). A session the client may \
         hold open in silence: `watch_idle_with_probe` with a keepalive Ping (`websocket`, \
         `webrtc`). A relay: one clock both directions touch (`socks5`).",
        flagged.join("\n  ")
    );
}

/// Deadline mechanisms that are never handshake-specific in this tree. The mechanisms of
/// [`TIMEOUT_TOKENS`] other than `timeout(`, which this test classifies call by call instead.
const POST_HANDSHAKE_MECHANISMS: &[&str] = &[
    "IdleTimeoutReader",
    "watch_idle",
    "Instant::now() +",
    "sleep_until",
    "set_read_timeout",
];

/// `handshake`, `join`, or `other` — see [`no_accept_loop_bounds_only_its_handshake`].
fn classify_timeout(arguments: &str) -> &'static str {
    if arguments.to_ascii_lowercase().contains("handshake") {
        return "handshake";
    }
    let awaited = arguments.rsplit(',').next().unwrap_or("").trim();
    let awaited = awaited
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    let is_identifier = !awaited.is_empty()
        && awaited
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if is_identifier && (awaited.contains("handle") || awaited.contains("writer")) {
        return "join";
    }
    "other"
}

/// The argument text of every `timeout(` call in `code`, parentheses balanced.
fn timeout_call_arguments(code: &str) -> Vec<String> {
    let bytes = code.as_bytes();
    let mut calls = Vec::new();
    let mut from = 0;
    while let Some(found) = code[from..].find("timeout(") {
        let start = from + found;
        // `timeout(` must be the whole identifier: `read_timeout(` is a different function.
        let preceded_by_ident =
            start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let open = start + "timeout(".len();
        from = open;
        if preceded_by_ident {
            continue;
        }
        let mut depth = 1usize;
        let mut end = open;
        while end < bytes.len() && depth > 0 {
            match bytes[end] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            end += 1;
        }
        calls.push(code[open..end.saturating_sub(1)].to_string());
    }
    calls
}

/// A `time::sleep(` whose argument names a read, an idle bound or a deadline — the `select!`
/// read-deadline idiom — as opposed to a retry backoff.
fn sleeps_on_a_read_deadline(code: &str) -> bool {
    let mut from = 0;
    while let Some(found) = code[from..].find("time::sleep(") {
        let open = from + found + "time::sleep(".len();
        let close = code[open..]
            .find(')')
            .map(|i| open + i)
            .unwrap_or(code.len());
        let argument = code[open..close].to_ascii_lowercase();
        if ["idle", "read", "deadline"]
            .iter()
            .any(|word| argument.contains(word))
        {
            return true;
        }
        from = open;
    }
    false
}

/// `code` with `//` comments removed, so a doc comment quoting `timeout(` is not read as a call.
/// Quote-aware, so `"http://..."` in a string is kept.
fn strip_line_comments(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    for line in code.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut cut = line.len();
        let chars: Vec<(usize, char)> = line.char_indices().collect();
        for (i, &(at, c)) in chars.iter().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '"' {
                in_string = true;
            } else if c == '/' && chars.get(i + 1).map(|&(_, n)| n) == Some('/') {
                cut = at;
                break;
            }
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}
