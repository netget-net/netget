//! Every declared `max_inbound_bytes` bound, driven from a socket: send bound+1, and the
//! model must never see it.
//!
//! `ProtocolMetadataV2::max_inbound_bytes`' own doc comment sets the standard — "every
//! declaration should have a test that sends this many bytes plus one and asserts the refusal
//! happens *before* any model call. A bound nobody tested is a comment." Each bound that landed
//! has such a test, written by hand for that protocol. This is the generic one: it reads the
//! number off the registry and probes every protocol that declares it, so a bound added
//! tomorrow is probed the day it is added rather than when somebody remembers.
//!
//! # What this proves, and what it deliberately does not
//!
//! **It proves the DoS property**, which is the one that is the same in every protocol: bytes
//! past the bound do not reach the model and do not leave the connection parked holding them.
//! A server that buffered `bound + 1` bytes and handed them to an LLM would be charging a
//! stranger's oversized message to the model backend, and the mock counts that directly.
//!
//! **It does not prove that the declared number is the number that fired.** For a line-oriented
//! protocol it is: `bound + 1` bytes with no newline is exactly an over-long line. For a
//! length-prefixed one the first bytes are read as a header, so what refuses may be the length
//! check rather than the byte bound, and the two are not distinguishable from outside. That is
//! the job of the per-protocol tests, which construct a legal-looking message that declares
//! `bound + 1` in the protocol's own vocabulary — and it is why this file is an addition to
//! them rather than a replacement.
//!
//! # Refusal, defined so that it means something in every protocol at once
//!
//! A protocol's refusal vocabulary is its own: a `connection.close` frame, a 413, an RESP
//! error, a plain hang-up. What they share is that the server **decides** — so the assertion is
//!
//! > within the deadline the server either closed the connection or wrote something back,
//! > **and** the model was called zero times.
//!
//! Failing that means the server silently swallowed an over-bound message and is sitting on it,
//! which is the shape of every defect this metadata field exists to make visible. The
//! "wrote something back" arm is what lets a protocol that answers an error and keeps the
//! connection alive (HTTP with keep-alive, most obviously) pass honestly rather than being
//! written off as unbounded.
//!
//! # Coverage is asserted, not assumed
//!
//! A probe that quietly covers half the tree is worse than none — this repository has shipped
//! that mistake three times, most recently in a ratchet that walked the registry and so went
//! green on a six-protocol build for reasons unrelated to what it checked. So:
//!
//! * every protocol compiled into this build that declares `max_inbound_bytes` is either
//!   **probed** or skipped for a reason that is either derived (not a TCP stream, needs
//!   privilege beyond a privileged port, bound past [`MAX_PROBE_BYTES`]) or written down in
//!   [`NOT_PROBED`];
//! * a declaring protocol that is in neither fails the test by name — including one that will
//!   not *start* here, because a server this file cannot start is coverage it does not have;
//! * the three real findings from its first run are in [`KNOWN_FINDINGS`], shrink-only, with
//!   what the probe saw. They are reported rather than exempted, and a baselined protocol that
//!   starts passing fails the test so the entry gets deleted;
//! * the full probed/skipped split prints on every run, so coverage is readable rather than
//!   inferred.
//!
//! Because it walks the **registry** it only sees what this build compiled, which is the
//! inescapable cost of a behavioural test — you cannot start a server that is not there. Run it
//! at `--all-features` to see the whole tree; `registry-audit` is the job that does.
//!
//! # The traps this file is built around
//!
//! **Wait for the listener.** A connection racing the bind is refused at connect, and that
//! reads exactly like "the bound closed my connection" — a false pass, in the direction that
//! matters. `connect_when_listening` retries the connect itself rather than trusting that
//! `local_addr` being set means `accept` is running.
//!
//! **Count from a baseline, not from zero.** Several protocols speak first and what they say is
//! the model's — NNTP and SVN generate their greeting. Counting every call against the payload
//! reported five protocols as enforcing nothing, which was this probe's mistake and not theirs.
//! `settled_call_count` is taken after the connect settles and subtracted.
//!
//! **A privileged default port is not a reason to skip.** Everything here starts on port 0, so
//! `PrivilegedPort(80)` never comes into it. Treating it as a skip cost seventeen protocols
//! including `http`, `imap`, `ftp`, `smtp`, `ssh`, `telnet` and `whois`.
//!
//! **The registry's name is the display form.** `"Bitcoin P2P"`, `"XML-RPC"`, `"SSH Agent"` —
//! not the source directory. Every table here is keyed case-insensitively on that name, because
//! the first version keyed on the directory and its entries matched nothing at all.
//!
//! **The instruction must be non-empty.** `ServerForm::create` substitutes a default
//! instruction for `None`, and any non-empty instruction makes `operator_wants_dynamic` true —
//! which is the condition under which the model *would* be consulted. A probe built with
//! `..Default::default()` and no instruction, or with an `event_handlers` rule, would measure
//! nothing: the zero would be the routing table's, not the bound's.
//!
//! Run with:
//!   ./cargo-isolated.sh test --all-features --test max_inbound_bytes_bound_plus_one_test -- --test-threads=100

mod helpers;

use std::collections::BTreeMap;
use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::protocol::metadata::PrivilegeRequirement;
use netget::protocol::server_registry;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The largest bound this file will actually put on a socket.
///
/// Writing this to loopback costs milliseconds; a protocol whose bound is larger is listed in
/// [`NOT_PROBED`] rather than being probed slowly. The cap is a property of the test, not of
/// the protocol — raising it costs only time.
const MAX_PROBE_BYTES: usize = 8 * 1024 * 1024;

/// How long the server has to decide about `bound + 1` bytes.
///
/// Generous against `--test-threads=100`: the assertion is that it decides *at all*, and a
/// server that has decided answers or hangs up immediately. What this must not do is expire
/// while a correct server is still reading the bytes we are writing.
const DECISION_DEADLINE: Duration = Duration::from_secs(20);

/// Protocols whose declared number bounds an **accumulation queue**, not one message.
///
/// These are exempted from the zero-model-calls half of the assertion and from it alone: they
/// are still started, still sent `bound + 1` bytes, and still required to decide about the
/// connection.
///
/// The distinction is real and it is the reason this file cannot be the only bound test. `tcp`
/// hands each *read* to the model as it arrives and `MAX_QUEUED_BYTES` bounds what piles up
/// behind an LLM call that is already in flight — so one model call for an 8 MiB message is the
/// design working, not the bound failing. A protocol that frames messages or lines has no such
/// call to make, because no complete unit ever arrives.
///
/// Reaching for this list is a claim about the protocol, so it needs the same scrutiny as a
/// `NOT_PROBED` entry: if a bound really does govern one message, an entry here hides a defect.
/// Keys are matched against the registry's protocol name, case-insensitively — that name is
/// the display form (`"Bitcoin P2P"`, `"XML-RPC"`, `"SSH Agent"`), not the source directory.
/// A first version keyed these tables on the directory name and every entry silently missed.
const STREAMING_BOUND: &[(&str, &str)] = &[
    (
        "tcp",
        "MAX_QUEUED_BYTES bounds data queued behind an in-flight LLM call, not one message; TCP \
         answers each read by design",
    ),
    (
        "echo",
        "READ_CHUNK bounds one read, not one message; RFC 862 echo answers each read by design, \
         so the handler sees every chunk of an over-bound send",
    ),
];

/// Protocols that are probed and **do not** pass, each with what the probe found.
///
/// **Shrink-only.** Removing an entry is the work; adding one is not an option. These are real
/// findings from the first run of this file, left visible rather than exempted away — the same
/// choice `max_inbound_bytes_declaration_test`'s baseline makes for its "unbounded, reported"
/// kind. They were outside the boundary of the pass that wrote this test, so they are reported
/// rather than fixed.
///
/// A baseline entry still runs the probe: what is suppressed is only the failure, so an entry
/// whose protocol starts passing is caught by the stale check at the end of the sweep.
const KNOWN_FINDINGS: &[(&str, &str)] = &[
    (
        "bitcoin p2p",
        "a decode error leaves the peer connected with nothing written. \
         `try_parse_bitcoin_message` correctly returns Err for bad magic — and its own doc \
         comment says the caller 'drops the connection instead of buffering forever' — but the \
         Err arm in the read loop logs, sets ConnectionState::Idle and returns, so the socket \
         stays open and the peer waits out its own timeout. 4 MB of junk is neither answered \
         nor refused.",
    ),
    (
        "proxy",
        "one model call lands after an over-bound request head. `read_request_head` does bail \
         at MAX_REQUEST_BYTES and the error propagates, so the bound itself fires; what is not \
         settled from outside is whether that call is the connection's own arriving late or \
         one provoked by the refused head. Read src/server/proxy/mod.rs before removing this.",
    ),
    (
        "xmpp",
        "one 256 KiB write buys ~50 model calls, and the amplification is by design in the \
         source: the read loop's own comment says 'for simplicity, we'll pass the entire buffer \
         to LLM for parsing', so every read raises xmpp_data_received carrying the whole \
         accumulated buffer, whose prompt grows toward 256 KiB. MAX_XMPP_BUFFER_BYTES does \
         eventually fire and close the connection — after all of those round trips. The bound \
         caps memory and not the model bill, which is the half the declaration implies it has. \
         The probe reports this two ways depending on which limit it hits first (a model-call \
         count, or the connection sitting on the bytes past the decision deadline while those \
         calls are still going); both are the same defect.",
    ),
];

/// Protocols that declare a bound this file does not probe, each with the reason.
///
/// Four kinds, and the difference matters:
///
/// 1. **Not a TCP stream** — UDP, raw IP and link-level servers are not reachable with
///    `TcpStream::connect`, and a datagram protocol's bound is its receive buffer, which a
///    single `send_to` cannot exceed from userspace anyway. The transport is read from
///    `stack_name()`, so this kind is detected rather than listed; entries here are the ones a
///    stack name does not settle.
/// 2. **Not on a socket at all** — USB/IP and NFC read from a device transport.
/// 3. **The bound is past [`MAX_PROBE_BYTES`]** — affordability, not correctness.
/// 4. **Raw bytes cannot reach the bound** — the declared number governs a payload that sits
///    behind a parser that refuses junk first, so probing it would assert the parser. The HTTP
///    family is the large case and is handled by the `HttpBody` shape instead; what is listed
///    here is the residue that neither shape reaches.
///
/// Every entry is a claim that can go stale. Deleting one is the work.
const NOT_PROBED: &[(&str, &str)] = &[
    (
        "grpc",
        "will not start without a `proto_schema` startup parameter — the model supplies the \
         protobuf definition, and there is no default one to invent here. Its MAX_REQUEST_BYTES is \
         therefore unprobed by this file; `tests/server/grpc/` is where it has to be checked.",
    ),
    (
        "grpc-web",
        "requires proto_schema and a binary gRPC-Web request to a declared RPC; this probe's \
         POST /netget-bound-probe with application/octet-stream would test media admission, not the framed bound. \
         tests/server/grpc_web/e2e_test.rs::incoming_request_limits_plain_and_gzip_independent_peer \
         accepts the exact 4 MiB protobuf limit (plus its 5-byte frame) and refuses +1 with \
         RESOURCE_EXHAUSTED through the independent Connect-ES peer, for plain and gzip input. \
         over_cap_upload_closes_without_waiting_for_declared_eof separately proves an unfinished \
         over-cap upload closes without an unlimited drain.",
    ),
    (
        "ConnectRPC",
        "will not start without a `proto_schema` startup parameter, like grpc. \
         tests/server/connect_rpc/e2e_test.rs::incoming_request_limits_plain_and_gzip_independent_peer \
         accepts the exact MAX_MESSAGE_BYTES message and refuses one byte more, plain and gzip, \
         through an independent peer.",
    ),
    (
        "Cap'n Proto RPC",
        "will not start without `schema` and `interface` startup parameters, and there is no \
         default interface to invent here. tests/server/capnp_rpc/wire_test.rs::\
         bounds_close_the_connection refuses a segment table announcing MAX_MESSAGE_BYTES + 1 \
         (and more than 64 segments) before allocating anything, with no reply.",
    ),
];
// The first version also listed the USB family and `nfc` here. Every one of those entries was
// dead, because `stack_name()` already settles them ("USB>HID>Keyboard" is not a TCP stream) and
// the transport check runs first — a reason nothing reaches is exactly the stale-baseline
// problem this file's header is about, so they are gone rather than kept for reassurance.

/// How this test speaks to a protocol in order to reach its declared bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `bound + 1` raw bytes straight onto the socket. Exactly right for a line- or
    /// frame-oriented protocol; for a length-prefixed one it still proves the DoS property.
    Raw,
    /// A well-formed HTTP request whose `Content-Length` declares `bound + 1`, then that many
    /// bytes. The ~25 protocols whose declared number is `MAX_REQUEST_BODY_BYTES` would refuse
    /// raw junk at the request line, long before the body bound — which would pass while
    /// asserting the HTTP parser.
    HttpBody,
}

fn shape_for(stack: &str) -> Shape {
    if stack.contains(">HTTP") {
        Shape::HttpBody
    } else {
        Shape::Raw
    }
}

/// Whether this protocol listens on TCP, read from its declared stack.
fn is_tcp(stack: &str) -> bool {
    stack.contains(">TCP>") || stack.ends_with(">TCP")
}

/// What happened to one protocol.
#[derive(Debug)]
enum Outcome {
    Probed { bytes: usize, note: &'static str },
    Skipped(String),
    Failed(String),
}

async fn wait_for_port(state: &AppState, id: ServerId) -> Option<u16> {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return Some(addr.port());
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    None
}

/// Connect, retrying until the accept loop is actually running.
///
/// `local_addr` is recorded once the socket is bound, which is not the same instant as the
/// accept loop being ready, and on some protocols the gap is real. A connect refused in that
/// gap looks exactly like the refusal this test is trying to observe — a false pass — so the
/// retry is load-bearing rather than defensive.
async fn connect_when_listening(port: u16) -> Option<TcpStream> {
    for _ in 0..200 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => return Some(s),
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    None
}

/// Write the over-bound message, then watch what the server does about it.
///
/// A write that fails part-way is **not** a failure of the probe: a server that refuses as soon
/// as it has read past the bound closes while we are still writing, and that is the behaviour
/// being asked for. What matters is only what comes back afterwards.
async fn probe(mut stream: TcpStream, payload: Vec<u8>) -> Result<&'static str, String> {
    let writer = tokio::spawn(async move {
        // Chunked so a mid-write refusal is observed rather than buffered away by one large
        // syscall.
        let mut wrote_all = true;
        for chunk in payload.chunks(64 * 1024) {
            if stream.write_all(chunk).await.is_err() {
                wrote_all = false;
                break;
            }
        }
        let _ = stream.flush().await;

        let mut sink = vec![0u8; 8192];
        let mut total_read = 0usize;
        let mut saw_eof = false;
        // One read is enough: either the server answered, or it hung up, or neither happens
        // and the timeout expires — which is the failure this test exists to name.
        match tokio::time::timeout(DECISION_DEADLINE, stream.read(&mut sink)).await {
            Ok(Ok(0)) => saw_eof = true,
            Ok(Ok(n)) => total_read = n,
            // A reset is a hang-up with worse manners, and several servers produce one by
            // closing a socket that still has our unread bytes queued.
            Ok(Err(_)) => saw_eof = true,
            Err(_) => {}
        }
        (wrote_all, saw_eof, total_read)
    });

    let (wrote_all, saw_eof, total_read) = writer
        .await
        .map_err(|e| format!("probe task panicked: {e}"))?;

    if saw_eof {
        Ok("closed the connection")
    } else if total_read > 0 {
        Ok("answered, connection kept")
    } else if !wrote_all {
        // The write was refused and nothing came back and no EOF was seen — the peer is gone
        // in every practical sense.
        Ok("refused the write")
    } else {
        Err(format!(
            "took the whole over-bound message and then neither answered nor closed within \
             {DECISION_DEADLINE:?}. An over-bound message must be decided about, not buffered \
             and forgotten"
        ))
    }
}

fn http_body_payload(bound: usize) -> Vec<u8> {
    let declared = bound + 1;
    let mut out = format!(
        "POST /netget-bound-probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: \
         application/octet-stream\r\nContent-Length: {declared}\r\n\r\n"
    )
    .into_bytes();
    out.resize(out.len() + declared, b'A');
    out
}

/// How many model calls this connection has provoked *before* the over-bound message.
///
/// Several protocols speak first, and what they say is the model's: NNTP and SVN generate their
/// greeting, and others raise a connect event. Counting from zero attributed that call to the
/// payload and reported five protocols as enforcing nothing, which was the probe's mistake and
/// not theirs — the exact false-positive class this repository has shipped three times.
///
/// Waiting for the count to *settle* rather than sleeping a fixed interval matters in the other
/// direction too: a greeting call still in flight when the baseline is taken would be counted
/// against the payload instead.
async fn settled_call_count(mock: &MockOllamaServer) -> usize {
    let ceiling = std::time::Instant::now() + Duration::from_secs(8);
    let mut last = mock.call_count().await;
    let mut stable_since = std::time::Instant::now();
    while std::time::Instant::now() < ceiling {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = mock.call_count().await;
        if now != last {
            last = now;
            stable_since = std::time::Instant::now();
            continue;
        }
        if stable_since.elapsed() >= Duration::from_millis(800) {
            break;
        }
    }
    last
}

/// One protocol, start to stop.
async fn probe_protocol(name: &str, bound: usize, stack: &'static str, streaming: bool) -> Outcome {
    // A streaming bound governs what accumulates behind the model, so the model has to let it
    // accumulate: `wait_for_more` on every read. Answering with nothing let TCP take each read
    // as a complete exchange and stay open — a legitimate answer on raw TCP — so the probe
    // passed only when one read happened to be large enough to fail at the mock, which depends
    // on how the kernel chunks the reads (it failed the PFCP pair job on #196 that way).
    //
    // What decides now is still not TCP's own `MAX_QUEUED_BYTES`: the accumulated prompt
    // passes the mock's 2 MB request limit first, the call fails, and TCP fails closed. That is
    // a decision every time, which is what this probe asks. The 8 MiB queue bound itself has
    // no test of its own yet (tests/server/tcp/AGENTS.md, "Queue bound").
    let answer = if streaming {
        serde_json::json!([{"type": "wait_for_more"}])
    } else {
        serde_json::json!([])
    };
    let mock = match MockOllamaServer::start(
        MockLlmBuilder::new()
            // Unconstrained, so anything that reaches the model is *recorded* rather than
            // 500-ing into an error path that could be mistaken for silence.
            .on_any()
            .respond_with_actions(answer)
            .expect_at_least(0)
            .build(),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return Outcome::Skipped(format!("mock ollama would not start: {e}")),
    };

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let form = ServerForm {
        protocol: name.to_string(),
        port: Some(0),
        // Non-empty and with no `event_handlers`: the model is the only thing that could
        // answer, so a zero count is the bound's doing and nothing else's.
        instruction: Some("Answer whatever arrives.".to_string()),
        // Diameter requires a local identity and TACACS+ a shared secret. Both enable their
        // explicit model opt-in so zero calls here measure parser refusal rather than
        // default denial.
        startup_params: if name.eq_ignore_ascii_case("diameter") {
            Some(serde_json::json!({
                "origin_host": "bounds.example",
                "origin_realm": "example",
                "llm_fallback": true
            }))
        } else if name.eq_ignore_ascii_case("tacacs") {
            Some(serde_json::json!({
                "shared_secret": "bound-probe-secret",
                "llm_fallback": true
            }))
        } else {
            None
        },
        ..Default::default()
    };
    let server_id = match form.create(&state, tx).await {
        Ok(id) => id,
        Err(e) => return Outcome::Skipped(format!("will not start with default parameters: {e}")),
    };

    let result = async {
        let port = wait_for_port(&state, server_id)
            .await
            .ok_or_else(|| "never bound a port".to_string())?;
        let stream = connect_when_listening(port)
            .await
            .ok_or_else(|| format!("never accepted a connection on port {port}"))?;

        // Whatever merely connecting costs, charged to connecting and not to the payload.
        let baseline = settled_call_count(&mock).await;

        let payload = match shape_for(stack) {
            Shape::Raw => vec![b'A'; bound + 1],
            Shape::HttpBody => http_body_payload(bound),
        };
        let note = probe(stream, payload).await?;

        let calls = settled_call_count(&mock).await.saturating_sub(baseline);
        if calls != 0 && !streaming {
            return Err(format!(
                "{calls} model call(s) for a message of {} bytes against a declared bound of \
                 {bound} (the connection itself cost {baseline}, which is not counted here). \
                 The bound must be enforced before the model is consulted — otherwise a \
                 stranger's oversized message is billed to the LLM backend, which is the \
                 amplification the bound exists to stop. If this bound governs an accumulation \
                 queue rather than one message, say so in STREAMING_BOUND",
                bound + 1
            ));
        }
        Ok(note)
    }
    .await;

    let _ = state.remove_server(server_id).await;

    match result {
        Ok(note) => Outcome::Probed { bytes: bound, note },
        Err(e) => Outcome::Failed(e),
    }
}

/// The control.
///
/// Every assertion in the sweep below is a **zero**, and a zero is indistinguishable from a
/// mock nothing ever tried to reach. This proves the counting works in this file's own harness,
/// with this file's own `ServerForm`: the same server, spoken to *inside* its bound, must
/// consult the model.
///
/// It is gated on `tcp` because it needs one protocol whose small-input behaviour is known.
/// At a feature set without it the sweep still runs, and this is what it loses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_probe_harness_can_see_a_model_call() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("Answer whatever arrives.".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");

    let port = wait_for_port(&state, server_id)
        .await
        .expect("tcp server bound a port");
    let mut stream = connect_when_listening(port)
        .await
        .expect("tcp server accepted");
    stream.write_all(b"well inside the bound").await.unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut calls = 0;
    while std::time::Instant::now() < deadline {
        calls = mock.call_count().await;
        if calls > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let _ = state.remove_server(server_id).await;

    assert!(
        calls > 0,
        "a message well inside the bound did not reach the model, so this harness cannot \
         distinguish 'the bound refused it' from 'the mock was never reachable'. Every zero \
         asserted by the sweep is worthless until this passes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_declared_bound_refuses_bound_plus_one_without_consulting_the_model() {
    // Lowercased, because the registry's name is the display form — `"Bitcoin P2P"`,
    // `"XML-RPC"`, `"SSH Agent"` — and keying on the source directory made every entry in
    // these tables silently miss.
    let not_probed: BTreeMap<String, &str> = NOT_PROBED
        .iter()
        .map(|(k, v)| (k.to_lowercase(), *v))
        .collect();
    let streaming: BTreeMap<String, &str> = STREAMING_BOUND
        .iter()
        .map(|(k, v)| (k.to_lowercase(), *v))
        .collect();
    let known_findings: BTreeMap<String, &str> = KNOWN_FINDINGS
        .iter()
        .map(|(k, v)| (k.to_lowercase(), *v))
        .collect();
    let mut baselined: Vec<String> = Vec::new();

    let mut declaring: Vec<(String, usize, &'static str, PrivilegeRequirement)> = Vec::new();
    for (name, proto) in server_registry::registry().all_protocols() {
        let meta = proto.metadata();
        if let Some(bound) = meta.max_inbound_bytes {
            declaring.push((
                name,
                bound,
                proto.stack_name(),
                meta.privilege_requirement.clone(),
            ));
        }
    }
    declaring.sort_by(|a, b| a.0.cmp(&b.0));

    assert!(
        !declaring.is_empty(),
        "no compiled protocol declares max_inbound_bytes — this build compiled nothing this \
         test can probe, which is a harness problem rather than a pass"
    );

    let mut probed: Vec<(String, usize, &'static str)> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();

    for (name, bound, stack, privilege) in declaring {
        // Reasons a stack name or the metadata settles by itself, so they need no table entry.
        if !is_tcp(stack) {
            skipped.push((name, format!("not a TCP stream ({stack})")));
            continue;
        }
        // `PrivilegedPort` is not a reason to skip: every server here is started on port 0, so
        // its privileged *default* port never comes into it. Treating it as one cost seventeen
        // protocols including `http`, `imap`, `ftp`, `smtp`, `ssh`, `telnet` and `whois` — the
        // kind of quiet under-coverage this file's own header is about.
        if !matches!(
            privilege,
            PrivilegeRequirement::None | PrivilegeRequirement::PrivilegedPort(_)
        ) {
            skipped.push((name, format!("needs privilege ({privilege:?})")));
            continue;
        }
        if bound > MAX_PROBE_BYTES {
            skipped.push((
                name,
                format!("bound is {bound} bytes, past this test's {MAX_PROBE_BYTES}-byte cap"),
            ));
            continue;
        }
        let key = name.to_lowercase();
        if let Some(reason) = not_probed.get(&key) {
            skipped.push((name, (*reason).to_string()));
            continue;
        }

        let is_streaming = streaming.contains_key(&key);
        match probe_protocol(&name, bound, stack, is_streaming).await {
            Outcome::Probed { bytes, note } => {
                if known_findings.contains_key(&key) {
                    // A baselined protocol that has started passing: the entry is stale and
                    // the assertion below says so, rather than letting a fix go unnoticed.
                    baselined.push(format!("{name} (now passes)"));
                }
                probed.push((
                    name,
                    bytes,
                    if is_streaming {
                        "decided (accumulation bound: model calls not counted)"
                    } else {
                        note
                    },
                ))
            }
            Outcome::Skipped(reason) => {
                // A protocol that will not start here is a real gap in coverage, not a pass.
                // It is recorded as a skip *and* named, so it cannot vanish quietly.
                unclassified.push(format!("{name}: {reason}"));
                skipped.push((name, reason));
            }
            Outcome::Failed(reason) => {
                if known_findings.contains_key(&key) {
                    baselined.push(format!("{name}: {reason}"));
                } else {
                    failures.push(format!("{name}: {reason}"));
                }
            }
        }
    }

    println!(
        "\n=== bound+1 probe: {} probed, {} skipped ===",
        probed.len(),
        skipped.len()
    );
    println!("\n-- probed --");
    for (name, bound, note) in &probed {
        println!("  {name:<20} bound {bound:>10}  → {note}");
    }
    println!("\n-- skipped --");
    for (name, reason) in &skipped {
        println!("  {name:<20} {reason}");
    }
    if !baselined.is_empty() {
        println!("-- known findings (KNOWN_FINDINGS, shrink-only) --");
        for entry in &baselined {
            println!("  {entry}");
        }
        println!();
    }

    assert!(
        failures.is_empty(),
        "{} protocol(s) did not refuse bound+1 cleanly:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    // Shrink-only in the other direction: a baselined protocol that now passes means the entry
    // is stale, and a stale exemption is how a fix becomes invisible and a regression becomes
    // silent. Delete the entry.
    let fixed: Vec<&String> = baselined
        .iter()
        .filter(|e| e.ends_with("(now passes)"))
        .collect();
    assert!(
        fixed.is_empty(),
        "{} protocol(s) in KNOWN_FINDINGS now refuse bound+1 cleanly. Delete their entries — \
         a baseline may only shrink, and one that outlives its defect stops the next regression \
         from failing anything:\n  {:?}",
        fixed.len(),
        fixed
    );

    assert!(
        unclassified.is_empty(),
        "{} protocol(s) declare a bound and could not be probed for a reason no human has \
         written down. Each is coverage this file silently does not have — give it an entry in \
         NOT_PROBED saying so, or make it startable:\n  {}",
        unclassified.len(),
        unclassified.join("\n  ")
    );

    // A NOT_PROBED entry that no longer names a compiled protocol is either a protocol that was
    // renamed or one that stopped declaring a bound. Either way the reason is stale.
    // Case-insensitive, for the same reason the tables above are: the registry's name is the
    // display form. A stale check that never matches anything is worth less than no check.
    let compiled: Vec<(String, Option<usize>)> = server_registry::registry()
        .all_protocols()
        .into_iter()
        .map(|(n, p)| (n.to_lowercase(), p.metadata().max_inbound_bytes))
        .collect();
    let stale: Vec<&str> = NOT_PROBED
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| {
            compiled
                .iter()
                .any(|(c, bound)| c == &n.to_lowercase() && bound.is_none())
        })
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_PROBED names {} compiled protocol(s) that no longer declare a bound, so the reason \
         is stale: {stale:?}",
        stale.len()
    );
}
