//! What NetGet's own client of a protocol does to a socket *before* anyone tells it to.
//!
//! ## Why this exists
//!
//! Several NetGet servers bound how long they will wait for a peer's **first byte**. That
//! bound is a defence — a peer that connects and says nothing holds a task, an `AppState`
//! row and one of `MAX_CONNECTIONS` slots, pre-authentication, and nothing else in the
//! process will ever close it. But the bound also has a victim: NetGet's *own* client of the
//! same protocol, created from the dashboard, is routed `*` -> manual, so it can sit
//! connected and silent for as long as a person takes to type into `[ send message ]` — a
//! window `src/state/intercepts.rs` puts at 300 seconds. `tcp`, `telnet`, `ldap`, `whois` and
//! `redis` each had a 30-second first-byte bound that dropped the operator's own client while
//! they were still looking at it, and each was raised to 300.
//!
//! Every other protocol was left alone, and the exemption rested on a throwaway measurement
//! that was never committed. This file is that measurement, made permanent.
//!
//! ## The three-way classification, and why a byte count alone is not enough
//!
//! A first-byte bound can only ever strand a peer that is **connected and silent**. So the
//! question for each protocol is: can NetGet's own client ever *be* that peer? A client that
//! puts no bytes on the wire looks identical to a client that opened no socket if you only
//! count bytes — and they are completely different answers:
//!
//! | accepts | bytes | classification | what it means for the server's first-byte bound |
//! |---|---|---|---|
//! | 0 | 0 | **lazy** — no socket until an operation is issued | irrelevant: there is no connection to strand |
//! | >= 1 | > 0 | **speaks inside `connect()`** | irrelevant: the first byte has already arrived |
//! | >= 1 | 0 | **connected and silent** | the bound is load-bearing and must outlast a human |
//!
//! Only the third row makes a short bound a defect. The first two are exemptions for
//! genuinely different reasons, and a test that collapsed them would go on passing if a lazy
//! client were made eager — which is exactly the change that would break the exemption.
//!
//! ## How it is measured
//!
//! A bare `tokio::net::TcpListener` counts **accepts** and **bytes** separately, and a client
//! is pointed at it through `ClientForm` — the same path the dashboard's `[ + <proto> client ]`
//! takes. The instruction is empty and the LLM endpoint is a dead port, so nothing the model
//! could say is what puts bytes on the wire: what arrives is the client library's own doing,
//! inside `connect()`. `ClientForm::create` is deliberately **not** awaited — a client that
//! speaks and then waits for an answer our listener will never give (postgresql, mssql,
//! cassandra) would never return — so the probe watches the counters instead of the result.
//!
//! ## The window
//!
//! [`WINDOW`] is 5 seconds, and the probe **returns the moment bytes arrive**, so only the
//! "nothing happened" verdict pays it. A library that speaks inside `connect()` does so in the
//! same task as the connect: measured here, every one of them is on the wire within **22-93ms**
//! (postgresql, mssql, cassandra and mongodb at ~22ms, couchdb at 72-93ms across runs, because
//! it builds a reqwest client first). The documented worst case for that reqwest build is
//! ~650ms under heavy process concurrency — the macOS system-proxy probe against configd, see
//! the root CLAUDE.md — so 5 seconds is ~50x the observed cost and ~7x the pathological one.
//! The whole file's wall clock is one window (~5.2s measured), because the tests run in
//! parallel and only the lazy and silent verdicts wait it out.
//!
//! ## One test per protocol, feature-gated
//!
//! Deliberately **not** one test gated on every feature at once: that would compile in no
//! ordinary build and would only ever run under the non-blocking `registry-audit` job.
//! Whatever feature set you compile runs exactly the relevant subset.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis,tcp,telnet \
//!       --test silent_peer_probe_test -- --test-threads=100

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use netget::cli::management::ClientForm;
use netget::llm::OllamaClient;
use netget::state::app_state::AppState;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// How long the probe will wait for a client that has done nothing yet.
///
/// See the module docs: the probe short-circuits as soon as bytes arrive, so this is only
/// paid by a client that never connects or never speaks. Being generous here is the safe
/// direction — too short and a slow speaker is misread as silent, which is a flake in the
/// exempt tests and a false alarm about a server bound.
const WINDOW: Duration = Duration::from_secs(5);

/// How often the counters are sampled. Small enough that the recorded time-to-first-byte is
/// meaningful, large enough not to spin.
const POLL: Duration = Duration::from_millis(20);

/// What a client did to a socket it was pointed at, before anyone asked it for anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// No TCP connection at all: the client opens one when an operation is issued.
    Lazy,
    /// Connected and put bytes on the wire from inside `connect()`.
    SpeaksInConnect,
    /// Connected and said nothing. The state a first-byte bound can strand.
    ConnectedAndSilent,
}

impl Reach {
    fn describe(self) -> &'static str {
        match self {
            Reach::Lazy => "lazy (no socket until an operation is issued)",
            Reach::SpeaksInConnect => "speaks inside connect() (first byte already on the wire)",
            Reach::ConnectedAndSilent => "connected and silent (a first-byte bound can strand it)",
        }
    }
}

/// The result of one probe, with the numbers behind it so a failure message can be specific.
struct Observation {
    reach: Reach,
    accepts: usize,
    bytes: usize,
    /// Time from "client creation started" to the first byte, when there was one.
    first_byte_after: Option<Duration>,
    /// What `ClientForm::create` returned, when it returned at all inside the window.
    ///
    /// Only interesting for the **lazy** verdict, and there it is essential: "opened no
    /// socket" and "refused the address and never tried" are indistinguishable by counting,
    /// and only the first is an exemption. A `create` that errored is reported in the failure
    /// text so nobody reads a rejected address as laziness.
    creation: CreationOutcome,
}

/// Whether `ClientForm::create` finished inside the probe, and how.
#[derive(Debug, Clone)]
enum CreationOutcome {
    /// Still running when the probe decided — the normal case for a client that speaks and
    /// then waits for a reply the counting peer never sends.
    Pending,
    /// Returned a client id.
    Ok,
    /// Returned an error, which for a lazy verdict is the thing to read before believing it.
    Failed(String),
}

impl CreationOutcome {
    fn describe(&self) -> String {
        match self {
            CreationOutcome::Pending => "ClientForm::create had not returned".to_string(),
            CreationOutcome::Ok => "ClientForm::create succeeded".to_string(),
            CreationOutcome::Failed(e) => format!("ClientForm::create FAILED: {e}"),
        }
    }
}

/// A listener that counts accepts and bytes separately and answers nothing.
///
/// Answering nothing is the point: the peer NetGet's server presents to a silent client is
/// one that also says nothing first, so a client that waits for a greeting waits here too.
struct CountingPeer {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

impl CountingPeer {
    async fn bind() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the counting peer");
        let addr = listener.local_addr().expect("local_addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));

        let accepts_t = accepts.clone();
        let bytes_t = bytes.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                accepts_t.fetch_add(1, Ordering::SeqCst);
                let bytes_c = bytes_t.clone();
                // The socket is held for the life of this task rather than dropped, so the
                // client never sees an EOF it could mistake for a refusal and retry around.
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                bytes_c.fetch_add(n, Ordering::SeqCst);
                            }
                        }
                    }
                });
            }
        });

        CountingPeer {
            addr,
            accepts,
            bytes,
        }
    }
}

/// Point NetGet's client of `protocol` at a counting peer and classify what it does.
///
/// The client is built exactly as the dashboard builds one, with two deliberate choices:
/// an **empty instruction** and an LLM endpoint on a dead port, so that no model turn can be
/// the thing that produces bytes. Anything observed is the client library speaking for itself.
async fn probe(protocol: &str, startup_params: Option<serde_json::Value>) -> Observation {
    let peer = CountingPeer::bind().await;
    let remote_addr = format!("127.0.0.1:{}", peer.addr.port());

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let llm = OllamaClient::new("http://127.0.0.1:1".to_string());
    state.set_llm_client(llm.clone()).await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let form = ClientForm {
        protocol: protocol.to_string(),
        remote_addr: Some(remote_addr.clone()),
        // Empty, not None: `ClientForm::create` substitutes a default instruction for `None`.
        instruction: Some(String::new()),
        startup_params,
        ..Default::default()
    };

    let started = Instant::now();
    // Not awaited: a client that speaks and then waits for a reply our peer never sends
    // (postgresql's StartupMessage, mssql's PRELOGIN, cassandra's OPTIONS) never returns here.
    let mut creation = tokio::spawn(async move { form.create(&state, llm, tx).await });

    let mut first_byte_after = None;
    loop {
        let bytes = peer.bytes.load(Ordering::SeqCst);
        if bytes > 0 {
            first_byte_after = Some(started.elapsed());
            break;
        }
        if started.elapsed() >= WINDOW {
            break;
        }
        tokio::time::sleep(POLL).await;
    }

    let accepts = peer.accepts.load(Ordering::SeqCst);
    let bytes = peer.bytes.load(Ordering::SeqCst);

    // Give creation a moment to land its result, then stop it either way. This is what makes
    // a "lazy" verdict readable: a client that refused the address never connected either.
    let outcome = match tokio::time::timeout(Duration::from_millis(250), &mut creation).await {
        Ok(Ok(Ok(_))) => CreationOutcome::Ok,
        Ok(Ok(Err(e))) => CreationOutcome::Failed(format!("{e:#}")),
        Ok(Err(e)) => CreationOutcome::Failed(format!("creation task died: {e}")),
        Err(_) => CreationOutcome::Pending,
    };
    creation.abort();

    let reach = match (accepts, bytes) {
        (0, _) => Reach::Lazy,
        (_, 0) => Reach::ConnectedAndSilent,
        _ => Reach::SpeaksInConnect,
    };

    Observation {
        reach,
        accepts,
        bytes,
        first_byte_after,
        creation: outcome,
    }
}

/// Assert a protocol's claimed classification, explaining what a change implies.
///
/// The failure text is the whole value of this file: whoever breaks an exemption needs to be
/// told what the new state is and what it means for that protocol's server-side bound, not
/// just that a number moved.
fn assert_reach(protocol: &str, expected: Reach, obs: &Observation, why: &str) {
    if obs.reach == expected {
        eprintln!(
            "[silent-peer-probe] {protocol}: {} ({} accepts, {} bytes{})",
            obs.reach.describe(),
            obs.accepts,
            obs.bytes,
            match obs.first_byte_after {
                Some(d) => format!(", first byte after {}ms", d.as_millis()),
                None => format!("; {}", obs.creation.describe()),
            }
        );
        return;
    }

    let implication = match obs.reach {
        Reach::ConnectedAndSilent => format!(
            "NetGet's {protocol} client now connects and says nothing, which is the one state a \
             first-byte read bound can strand. A dashboard-created client is routed `*` -> manual \
             and waits for a person at `[ send message ]` — up to the 300 seconds \
             src/state/intercepts.rs gives them. So src/server/{protocol}/mod.rs must not drop a \
             silent peer before then: raise its first-byte bound to 300s, declare \
             `first_byte_timeout_secs` and `idle_timeout_secs` as startup parameters, and add a \
             wire-driven bounds test. Copy src/server/redis/{{mod,actions}}.rs and \
             tests/server/redis/connection_bounds_test.rs, which is exactly this repair."
        ),
        Reach::SpeaksInConnect => format!(
            "NetGet's {protocol} client now puts bytes on the wire from inside connect(), so it \
             can no longer be stranded by a first-byte bound — the first byte has already \
             arrived. If this file previously claimed it was lazy, the exemption is still sound \
             but for a different reason; update the claim here rather than the assertion."
        ),
        Reach::Lazy => format!(
            "NetGet's {protocol} client no longer opens a socket at all until an operation is \
             issued, so there is nothing for a first-byte bound to strand. The exemption is still \
             sound, but for a different reason than this file claimed; update the claim."
        ),
    };

    panic!(
        "{protocol}: expected {}, measured {} ({} accepts, {} bytes in {}s; {}).\n\
         Claimed here because: {why}\n\
         What the new state implies: {implication}",
        expected.describe(),
        obs.reach.describe(),
        obs.accepts,
        obs.bytes,
        WINDOW.as_secs(),
        obs.creation.describe(),
    );
}

// ===========================================================================================
// Connected and silent — the protocols whose server-side first-byte bound had to be raised.
//
// These are the positive cases. Without them this file would assert only exemptions and would
// go on passing on a tree where every client had become silent.
// ===========================================================================================

#[tokio::test]
async fn tcp_client_is_connected_and_silent() {
    let obs = probe("tcp", None).await;
    assert_reach(
        "tcp",
        Reach::ConnectedAndSilent,
        &obs,
        "a bare TcpStream::connect that sends nothing until an action says to — the peer whose \
         30-second first-byte bound in src/server/tcp/mod.rs was the original defect",
    );
}

#[tokio::test]
async fn telnet_client_is_connected_and_silent() {
    let obs = probe("telnet", None).await;
    assert_reach(
        "telnet",
        Reach::ConnectedAndSilent,
        &obs,
        "the client waits for the server's option negotiation rather than opening with its own",
    );
}

#[tokio::test]
async fn redis_client_is_connected_and_silent() {
    let obs = probe("redis", None).await;
    assert_reach(
        "redis",
        Reach::ConnectedAndSilent,
        &obs,
        "no HELLO, no AUTH, no PING: the connection is opened and the first command comes from \
         the operator or the model. This is the measurement that found the redis defect",
    );
}

#[tokio::test]
async fn ftp_client_is_connected_and_silent() {
    let obs = probe("ftp", None).await;
    assert_reach(
        "ftp",
        Reach::ConnectedAndSilent,
        &obs,
        "the client connects and reads the server's 220 greeting in its read loop; it writes          nothing of its own, so \"FTP is server-speaks-first\" is not an exemption — the          greeting is ours, and sending it says nothing about whether the peer will answer it.          That was the wrong test, and it is why src/server/ftp/mod.rs kept a 60-second          first-byte bound through the first pass of this sweep",
    );
}

#[tokio::test]
async fn nntp_client_is_connected_and_silent() {
    let obs = probe("nntp", None).await;
    assert_reach(
        "nntp",
        Reach::ConnectedAndSilent,
        &obs,
        "the client reads the welcome line in its read loop and answers it only when an action          says to — no CAPABILITIES, no MODE READER of its own. Server-speaks-first again, and          again not an exemption",
    );
}

#[tokio::test]
async fn pop3_client_is_connected_and_silent() {
    let obs = probe("pop3", None).await;
    assert_reach(
        "pop3",
        Reach::ConnectedAndSilent,
        &obs,
        "the client reads the +OK greeting in its read loop and sends no CAPA or USER of its          own. Its server's 60-second bound was Dovecot's login_timeout, which is right for          Dovecot: Dovecot has no client that parks on a human",
    );
}

#[tokio::test]
async fn torrent_peer_client_is_connected_and_silent() {
    let obs = probe("torrent_peer", None).await;
    assert_reach(
        "torrent_peer",
        Reach::ConnectedAndSilent,
        &obs,
        "the sharpest case in this file: the client's read loop opens with read_exact on the          OTHER peer's 68-byte handshake, and sends its own only when the send_handshake action          says to — so both ends wait, and whichever has the shorter bound gives up first. BEP 3          says the initiator speaks immediately, which is true of every mainline client and false          of this one",
    );
}

// ===========================================================================================
// Speaks inside connect() — exempt because the first byte arrives before anyone is waited on.
// ===========================================================================================

#[tokio::test]
async fn postgresql_client_speaks_inside_connect() {
    let obs = probe("postgresql", None).await;
    assert_reach(
        "postgresql",
        Reach::SpeaksInConnect,
        &obs,
        "tokio-postgres sends the StartupMessage as the first thing it does on the socket",
    );
}

#[tokio::test]
async fn mssql_client_speaks_inside_connect() {
    let obs = probe("mssql", None).await;
    assert_reach(
        "mssql",
        Reach::SpeaksInConnect,
        &obs,
        "tiberius opens with a TDS PRELOGIN packet",
    );
}

#[tokio::test]
async fn cassandra_client_speaks_inside_connect() {
    let obs = probe("cassandra", None).await;
    assert_reach(
        "cassandra",
        Reach::SpeaksInConnect,
        &obs,
        "scylla's session builder opens with an OPTIONS frame and waits for SUPPORTED",
    );
}

#[tokio::test]
async fn mongodb_client_speaks_inside_connect() {
    let obs = probe("mongodb", None).await;
    assert_reach(
        "mongodb",
        Reach::SpeaksInConnect,
        &obs,
        "the official driver starts SDAM monitoring on construction, which sends `hello`",
    );
}

#[tokio::test]
async fn tls_client_speaks_inside_connect_but_only_the_handshake() {
    let obs = probe("tls", None).await;
    assert_reach(
        "tls",
        Reach::SpeaksInConnect,
        &obs,
        "tokio_rustls puts the ClientHello on the wire from inside connect(), before any model          turn or keystroke — which exempts the server's HANDSHAKE_READ_TIMEOUT and nothing          else. **This is the one protocol where a byte count cannot answer the question by          itself.** Those bytes are a handshake; after it completes the same client writes no          application bytes at all until an action or [ send message ] says to, so against the          server's wait for the first application RECORD it is connected-and-silent. A bare          TcpListener cannot see that distinction, which is exactly why src/server/tls/mod.rs          now has two constants where it had one: a bound that covers two waits is only correct          if both waits face the same peer",
    );
}

#[tokio::test]
async fn couchdb_client_speaks_inside_connect() {
    let obs = probe("couchdb", None).await;
    assert_reach(
        "couchdb",
        Reach::SpeaksInConnect,
        &obs,
        "connect() calls check_status(), which is a real HTTP GET",
    );
}

// ===========================================================================================
// Lazy — exempt because no socket exists until an operation is issued.
// ===========================================================================================

#[tokio::test]
async fn elasticsearch_client_is_lazy() {
    let obs = probe("elasticsearch", None).await;
    assert_reach(
        "elasticsearch",
        Reach::Lazy,
        &obs,
        "connect() builds a reqwest client and issues no request; the first socket belongs to \
         the first search",
    );
}

#[tokio::test]
async fn s3_client_is_lazy() {
    let obs = probe("s3", None).await;
    assert_reach(
        "s3",
        Reach::Lazy,
        &obs,
        "the AWS SDK client is built from a config and connects only when an operation is called",
    );
}

#[tokio::test]
async fn sqs_client_is_lazy() {
    let obs = probe(
        "sqs",
        Some(serde_json::json!({
            "queue_url": "http://127.0.0.1:1/000000000000/probe",
            "region": "us-east-1",
        })),
    )
    .await;
    assert_reach(
        "sqs",
        Reach::Lazy,
        &obs,
        "the AWS SDK client is built from a config and connects only when an operation is called. \
         `queue_url` is required at construction, so it is supplied — pointed at a dead port, \
         because a client that did reach out must fail rather than quietly succeed elsewhere",
    );
}

#[cfg(all(unix, feature = "libsmbclient"))]
#[tokio::test]
async fn smb_client_is_lazy() {
    let obs = probe("smb", None).await;
    assert_reach(
        "smb",
        Reach::Lazy,
        &obs,
        "pavao's SmbClient::new builds a libsmbclient context and touches no socket; every \
         operation connects for itself",
    );
}

#[tokio::test]
async fn etcd_client_is_lazy() {
    let obs = probe("etcd", None).await;
    assert_reach(
        "etcd",
        Reach::Lazy,
        &obs,
        "etcd_client::Client::connect returns a connected client having opened no TCP connection \
         at all — the tonic channel underneath it is lazy, and the first socket belongs to the \
         first RPC. Measured, against the opposite expectation: tonic's eager `connect()` would \
         have put the HTTP/2 preface on the wire from inside connect(), and nothing here does",
    );
}
