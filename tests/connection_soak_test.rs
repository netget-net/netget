//! Ten thousand short connections, and what must not grow.
//!
//! `PROTOCOL_QUALITY.md` Tier 2: *"A soak test per protocol family. Ten thousand short
//! connections against a running server; assert `AppState` connection count returns to zero and
//! RSS is flat."*
//!
//! # Why this exists now
//!
//! 145 `tokio::spawn` sites across 113 protocols were converted to `AppState::spawn_server_task`
//! on 15 September 2026, so that `stop_server` can abort a per-connection task. That registration
//! is `tasks.retain(|h| !h.is_finished()); tasks.push(handle)` — it prunes **on the next
//! registration**, which means the steady state is one entry per *live* connection however many
//! have come and gone. That is a claim about the tenth thousandth connection, and nothing in the
//! tree tested past the thirty-first (`per_connection_registration_does_not_accumulate_handles`).
//!
//! The opposite — a server that accumulates a `JoinHandle`, a `ConnectionState` or a peer handle
//! for every connection it has *ever* accepted — is invisible until a long-running server falls
//! over, because every individual test opens a handful of connections and stops.
//!
//! # What is asserted, and why each one is here
//!
//! | assertion | the leak it catches |
//! |---|---|
//! | the tracked-connection map does not grow with connections served | a server that never forgets a closed peer — state grows forever and the dashboard paints peers that are gone. A leaking server grows this at 1.0 entries per connection; the budget is 0.2 |
//! | `server_task_count` never exceeds a bound set by live connections | the `retain`-on-register pruning in `register_server_task` not actually pruning |
//! | RSS is flat across the run | everything the two counters above cannot see — buffers, peer handles, access-log rows, channel backlog |
//! | active connection count returns to **zero** once traffic stops | a close path that marks some connections and misses others |
//! | `connections` is empty after `cleanup_closed_connections` | `Closed` entries that are marked and never drained |
//! | `recent_connections` stays at its declared cap | the "recently connected" ring growing without bound |
//! | the listening port is free after stop, and rebinds | a stopped server holding its socket |
//!
//! # The reaper is part of the system under test
//!
//! `AppState` does not delete a closed connection; it marks it `Closed` and leaves it for the
//! cleanup tick, which the TUI event loop and the MCP reaper each drive every few seconds with a
//! ten-second retention. Nothing drives one inside a test process.
//!
//! A first version of this file left it that way, and all three stream protocols grew the
//! connection map at **exactly 1.0 entries per connection served** and RSS by about **1.4 KB per
//! connection** — 34 MiB to 48 MiB over ten thousand HTTP connections. That is not a leak. It is
//! the retention window with nothing reaping it, and calling it a leak would have been the
//! `ospf` mistake in a new place: a test measuring a configuration NetGet never ships.
//!
//! So the harness runs the reaper at the production values ([`CONNECTION_RETENTION_SECS`]) and
//! the soak is paced to outlast it, which turns the question into the one worth asking — does the
//! map reach a **steady state**, or does it track the total ever served? Measured: a steady
//! ~4 120 entries, which is [`TARGET_CONNECTIONS_PER_SEC`] × [`CONNECTION_RETENTION_SECS`], flat
//! from the first sweep to the ten thousandth connection.
//!
//! **The finding worth keeping is that the unreaped number is 1.0.** Between two cleanup ticks a
//! busy server holds one entry for every connection in that window, and every one of those
//! entries is under the single global `AppState` `RwLock`. Nothing bounds it but the tick.
//!
//! # Honesty about RSS
//!
//! Allocators do not return freed pages promptly, and a process that has just started has not
//! finished growing its arenas, so **start-vs-end is not a measurement** — it reports growth that
//! would have happened with no traffic at all. This compares a *late* window against an *earlier*
//! one, both taken after a warm-up of [`RSS_WARMUP`] connections, and states the growth as
//! **bytes per connection** rather than as a percentage. A percentage is the wrong unit: 5% of a
//! 200 MiB process is 10 MiB, which is a 1 KB-per-connection leak waved through.
//!
//! RSS also steps rather than sloping, so a rate alone is not enough either — see
//! [`MIN_RSS_GROWTH_BYTES`], which documents both the second half of the rule and the real
//! sensitivity it buys. In short: the two counters are the sharp instruments and RSS is the
//! backstop for what they cannot count.
//!
//! Every sample is printed on failure, so a red run says *where* the curve bent rather than only
//! that it did.
//!
//! # Why these four protocols
//!
//! One per shape, not one per protocol — the leak is in the shared lifecycle, and the shapes
//! differ in who owns the socket:
//!
//! * **`tcp`** — a plain stream server whose reader NetGet wrote itself. The reference
//!   implementation every other stream protocol was copied from.
//! * **`http`** — hyper's `serve_connection` owns the connection, so NetGet's tracking and the
//!   library's lifetime have to agree. `CLAUDE.md` records this as the shape ~30 protocols share.
//! * **`dns`** — datagram, and declared `.connectionless()`. It adds a **new** connection entry
//!   per *datagram*, with no close path at all, so its entire defence against unbounded growth is
//!   the 10-second idle sweep. That sweep is the thing under test here, and it is the one
//!   protocol family where "returns to zero" is a statement about the reaper rather than about
//!   the close path.
//! * **`redis`** — a session protocol with its own framing and per-connection state machine.
//!
//! # Not in the normal suite, and why
//!
//! Every test here is `#[ignore]`d with a reason. Each takes ~25 seconds by construction — it has
//! to outlast the retention window — and the four together run in about 100 seconds, which is
//! several times the whole rest of the suite.
//!
//! The part that would make them actively harmful as a default is the ephemeral port range. Each
//! clean close leaves the side that sent `FIN` first — the test — in `TIME_WAIT` for 2·MSL, and
//! macOS reports 16 384 ephemeral ports against a 15-second MSL. Two of these running
//! concurrently under `--test-threads=100` exhaust the range and report `EADDRNOTAVAIL`, which is
//! a kernel bookkeeping limit wearing a leak's clothes. They must run **serially**, which is what
//! `.github/workflows/nightly-soak.yml` does.
//!
//! Run them by hand with:
//!
//! ```text
//! CARGO_TARGET_DIR=/tmp/vsoak ./cargo-isolated.sh test \
//!     --no-default-features --features tcp,http,dns,redis \
//!     --test connection_soak_test -- --ignored --test-threads=1 --nocapture
//! ```


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::{ConnectionStatus, RECENT_CONNECTION_CAPACITY};
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// The soak size the roadmap item names.
const SOAK_CONNECTIONS: usize = 10_000;

/// How many connections are open at once.
///
/// Not a throughput knob — a safety one. `ulimit -n` is 256 by default on macOS, and the whole
/// point of a soak test is that it must not fail for a reason that is not a leak. Sixteen leaves
/// room for the server's own accepted ends, the test binary's other file descriptors and
/// whatever else the runner is doing.
const IN_FLIGHT: usize = 16;

/// Connections opened per second.
///
/// Paced, and the pacing is load-bearing twice over.
///
/// **Ephemeral ports.** A clean close leaves the side that sent `FIN` first — here the test — in
/// `TIME_WAIT` for 2·MSL. macOS reports `net.inet.ip.portrange` 49152..65535 and
/// `net.inet.tcp.msl` 15000 ms, so the sustainable rate is 16 384 ÷ 30 s ≈ 546 connections per
/// second. Unpaced, this test opens ten thousand in about three seconds and the *next* test in
/// the file fails with `EADDRNOTAVAIL` — a red run that is a kernel bookkeeping limit rather
/// than a leak, which is the single most effective way to get a soak test deleted.
///
/// **The reaper.** `AppState` holds a closed connection until the cleanup tick reaps it
/// ([`CONNECTION_RETENTION_SECS`]). A soak that finishes before the first tick measures the
/// ramp instead of the steady state, and reports the retention window as a leak. At this rate
/// the run lasts ~25 s and the map settles.
const TARGET_CONNECTIONS_PER_SEC: usize = 400;

/// Connections to serve before a sample counts toward the verdict.
///
/// Two things have to have finished. The allocator has to have stopped growing its arenas — a
/// process that has just started grows regardless of traffic, and measuring from zero reports
/// that growth as a leak. And the connection map has to have reached its steady state, which
/// takes one full [`CONNECTION_RETENTION_SECS`] plus a tick: at
/// [`TARGET_CONNECTIONS_PER_SEC`] that is the first ~4 000 connections.
const RSS_WARMUP: usize = 4_000;

/// Connections per sample.
///
/// Sampling is on the *crossing* of a multiple, not on `served % SAMPLE_EVERY == 0`: `served`
/// advances in [`IN_FLIGHT`]-sized batches, so an exact-modulus test silently samples at
/// `lcm(IN_FLIGHT, SAMPLE_EVERY)` instead. That bug gave two samples per window where it should
/// have given twelve, and a mean over two samples is a reading, not a measurement.
const SAMPLE_EVERY: usize = 250;

/// How long `AppState` keeps a closed connection, and an idle connectionless one, before the
/// cleanup tick reaps it.
///
/// Both `src/tui/event_loop.rs` and `src/mcp_stdio/tools.rs` declare 10 seconds. The soak runs
/// its own reaper at these values rather than leaving the map unreaped, because an unreaped map
/// is not a configuration NetGet ever ships — the TUI ticks one and MCP mode spawns one — and a
/// test that fails on designed behaviour teaches nothing.
const CONNECTION_RETENTION_SECS: u64 = 10;

/// How often the soak's reaper ticks. Production uses 5 s; this is a polling frequency rather
/// than a semantic, and a shorter one only makes the steady state cleaner to measure.
const REAPER_INTERVAL: Duration = Duration::from_millis(500);

/// The RSS tolerance, as bytes of growth per connection served.
///
/// A percentage would be the wrong unit: 5% of a 200 MiB process is 10 MiB, which waves through
/// a 1 KB-per-connection leak. The smallest leak shape that actually exists here is one retained
/// `ConnectionState` — several `String`s, measured on this tree at roughly 1.4 KB of RSS per
/// connection when the map is left unreaped. 128 B/conn sits an order of magnitude below that.
///
/// Measured across three full runs: 0.0–31.7 B/conn for the three stream protocols, and
/// 72.8–356.4 B/conn for `dns` — which is *not* a leak and is the whole reason
/// [`MIN_RSS_GROWTH_BYTES`] exists. The dns figure is one allocator step of about 1 MiB divided
/// by the 3 000 connections between the windows; its connection map is flat to three decimal
/// places across the same samples. A rate budget alone would have failed `dns` on every run.
const MAX_RSS_BYTES_PER_CONNECTION: f64 = 128.0;

/// RSS growth below this is never called a leak, whatever the per-connection rate works out to.
///
/// **This is the floor that decides what the RSS assertion can actually see, and it is worth
/// being plain about.** RSS does not grow smoothly. It steps, in page-table-sized jumps, as the
/// allocator takes a new arena — a single step of ~0.9 MiB was measured here between two adjacent
/// samples with the map perfectly flat on either side. Spread across the ~3 000 connections
/// between the two measurement windows that one step reads as ~300 B/conn, which is above the
/// rate budget and is not a leak.
///
/// So the verdict needs *both*: a rate above [`MAX_RSS_BYTES_PER_CONNECTION`] **and** an absolute
/// growth above this. That makes the real sensitivity of the RSS check about 3 MiB over 3 000
/// connections — roughly 1 KB per connection — against a retained-`ConnectionState` leak of about
/// 1.4 KB per connection. That is a margin of well under two, and it is the honest limit of what
/// a resident-set reading can resolve at this scale.
///
/// **The counters are the sharp instruments; RSS is the backstop.** The map slope separates the
/// defect from the steady state by a factor of five, and the task ceiling catches a leaked
/// `JoinHandle` that is far too small to move RSS at all. RSS earns its place by covering what
/// neither counts — a buffer, a peer handle, an access-log row, a channel backlog — not by being
/// the most precise of the three.
const MIN_RSS_GROWTH_BYTES: f64 = 3.0 * 1024.0 * 1024.0;

/// The tolerance on the *connection map* itself, as entries of growth per connection served.
///
/// This is the sharp instrument; RSS is the backstop. A server that never forgets a closed peer
/// grows this at 1.0 — one entry for every connection it has ever accepted — which is exactly
/// what the map does with no reaper running. A server at its steady state grows it at ~0.
/// 0.2 is far below the defect and far above the jitter of where a tick lands.
const MAX_CONNECTION_ENTRIES_PER_CONNECTION: f64 = 0.2;

/// The ceiling on registered background tasks at any point in the soak.
///
/// The contract is not a specific number, it is that the number **does not depend on how many
/// connections have been served**. It is expressed in terms of [`IN_FLIGHT`] for that reason: the
/// accept loop, up to one reader and one writer per live connection, and generous headroom for
/// handles whose tasks have finished but whose pruning is waiting on the next registration.
const MAX_REGISTERED_TASKS: usize = IN_FLIGHT * 4 + 16;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Resident set size of this process, in bytes.
///
/// `ps -o rss=` prints kibibytes on both macOS and Linux and needs no new dependency, which
/// matters: a soak test that drags in a process-info crate is a soak test nobody merges.
fn rss_bytes() -> u64 {
    let pid = std::process::id().to_string();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .expect("`ps` must be on PATH to measure RSS; without it this test measures nothing");
    let text = String::from_utf8_lossy(&out.stdout);
    let kib: u64 = text
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("`ps -o rss=` printed {text:?}, which is not a kibibyte count"));
    kib * 1024
}

/// Start a server through the same path the dashboard and the MCP surface use, with **no model
/// behind it**.
///
/// Two independent guards, because a soak test that accidentally makes ten thousand LLM calls
/// measures the rate limiter rather than the connection lifecycle:
///
/// * `instruction: Some(String::new())` — `ServerForm::create` substitutes a default instruction
///   for `None`, and any non-empty instruction makes `operator_wants_dynamic` true. `CLAUDE.md`
///   names this as the trap two `peer_inject` tests fell into while documenting the opposite.
/// * a `*` → static rule with no actions, which `tests/empty_static_handler_test.rs` measured as
///   suppressing the call outright.
///
/// The endpoint is `127.0.0.1:1` as a third guard: if both of the above were wrong, the call
/// fails instantly and visibly rather than reaching whatever model is running on this machine.
async fn start_model_free(protocol: &str) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // Drain it. The status channel is unbounded, and ten thousand connections' worth of
    // `__UPDATE_UI__` would otherwise be counted as this test's own leak.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let id = ServerForm {
        protocol: protocol.to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("create a {protocol} server: {e}"));

    let port = wait_for_port(&state, id).await;
    spawn_reaper(&state);
    (state, id, port)
}

/// The cleanup tick, as the TUI event loop and the MCP reaper run it.
///
/// Without this the soak measures a configuration NetGet never ships. `AppState` marks a closed
/// connection `Closed` and leaves it there; draining is the reaper's job, and nothing in a test
/// process drives one. Measured with no reaper, all three stream protocols grew the map at
/// exactly 1.0 entries per connection served and RSS by ~1.4 KB per connection — which is the
/// retention window doing its job, not a leak, and a test that called it one would be deleted
/// the first time someone read it.
///
/// Running it here means the soak asserts the thing that actually matters: that with the
/// production reaper in place the map and the process reach a **steady state** rather than
/// tracking the total ever served.
fn spawn_reaper(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REAPER_INTERVAL);
        loop {
            tick.tick().await;
            state
                .cleanup_closed_connections(CONNECTION_RETENTION_SECS)
                .await;
            state
                .cleanup_old_connections(CONNECTION_RETENTION_SECS)
                .await;
        }
    });
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Poll a condition to a deadline. `CLAUDE.md` is explicit that a fixed sleep is where this
/// repository's load-flakiness came from.
async fn wait_until<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if f().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn active_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| c.status == ConnectionStatus::Active)
                .count()
        })
        .unwrap_or(0)
}

async fn tracked_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0)
}

/// One sample of everything that must not grow.
#[derive(Clone, Copy)]
struct Sample {
    served: usize,
    rss: u64,
    tasks: usize,
    tracked: usize,
}

/// Renders the whole series. A soak failure that says only "it grew" costs another soak run to
/// diagnose; this says where the curve bent.
fn series(samples: &[Sample]) -> String {
    let mut s = String::from("\n  served |      RSS |  tasks | tracked conns\n");
    for p in samples {
        s.push_str(&format!(
            "  {:>6} | {:>6} KiB | {:>6} | {:>6}\n",
            p.served,
            p.rss / 1024,
            p.tasks,
            p.tracked
        ));
    }
    s
}

/// The two measurement windows, as `(low, high]` bounds on `served`.
///
/// Both sit after [`RSS_WARMUP`] and they are adjacent and equal, so the distance between their
/// midpoints — the denominator of every slope below — is simply the width of one window.
fn windows() -> (usize, usize, usize, usize, f64) {
    let width = (SOAK_CONNECTIONS - RSS_WARMUP) / 2;
    (
        RSS_WARMUP,
        RSS_WARMUP + width,
        RSS_WARMUP + width,
        SOAK_CONNECTIONS,
        width as f64,
    )
}

/// Mean of `value` over the samples whose `served` falls in `(lo, hi]`.
fn mean_over(
    samples: &[Sample],
    lo: usize,
    hi: usize,
    value: impl Fn(&Sample) -> f64,
) -> (f64, usize) {
    let window: Vec<&Sample> = samples
        .iter()
        .filter(|p| p.served > lo && p.served <= hi)
        .collect();
    assert!(
        !window.is_empty(),
        "no samples in ({lo}, {hi}] — SAMPLE_EVERY, RSS_WARMUP and SOAK_CONNECTIONS disagree"
    );
    let sum: f64 = window.iter().map(|p| value(p)).sum();
    (sum / window.len() as f64, window.len())
}

/// The shared verdict: the connection-map slope, the RSS slope, the task ceiling, and the full
/// series on any failure.
///
/// The three are ordered deliberately. The map slope is the sharp instrument and names the
/// defect directly; RSS is the backstop for everything the counters cannot see; the task ceiling
/// is the one assertion about the `spawn_server_task` sweep specifically. A failure in the first
/// usually explains a failure in the second, so reporting the map first makes a red run
/// diagnosable in one read.
fn assert_flat(protocol: &str, samples: &[Sample]) {
    let (e_lo, e_hi, l_lo, l_hi, span) = windows();

    let (map_early, n_early) = mean_over(samples, e_lo, e_hi, |s| s.tracked as f64);
    let (map_late, n_late) = mean_over(samples, l_lo, l_hi, |s| s.tracked as f64);
    let map_slope = (map_late - map_early) / span;

    let (rss_early, _) = mean_over(samples, e_lo, e_hi, |s| s.rss as f64);
    let (rss_late, _) = mean_over(samples, l_lo, l_hi, |s| s.rss as f64);
    let rss_slope = (rss_late - rss_early) / span;

    let peak_tasks = samples.iter().map(|p| p.tasks).max().unwrap_or(0);

    println!(
        "[soak] {protocol}: {SOAK_CONNECTIONS} connections; windows ({e_lo}, {e_hi}] and \
         ({l_lo}, {l_hi}] with {n_early} and {n_late} samples. Connection map \
         {map_early:.0} -> {map_late:.0} entries ({map_slope:.3} per connection); RSS \
         {:.1} -> {:.1} MiB ({rss_slope:.1} B/conn); peak registered tasks {peak_tasks}.",
        rss_early / 1048576.0,
        rss_late / 1048576.0,
    );

    assert!(
        map_slope < MAX_CONNECTION_ENTRIES_PER_CONNECTION,
        "{protocol}: the tracked-connection map grew {map_slope:.3} entries per connection \
         served ({map_early:.0} entries in ({e_lo}, {e_hi}] against {map_late:.0} in \
         ({l_lo}, {l_hi}]). A slope near 1.0 means the server keeps one entry for every \
         connection it has ever accepted — state that grows forever and a dashboard that paints \
         peers who are gone. The budget is {MAX_CONNECTION_ENTRIES_PER_CONNECTION}.{}",
        series(samples)
    );

    // Both conditions, never either: see MIN_RSS_GROWTH_BYTES. A single allocator arena step
    // clears the rate budget on its own and is not a leak.
    let rss_growth = rss_late - rss_early;
    assert!(
        rss_slope < MAX_RSS_BYTES_PER_CONNECTION || rss_growth < MIN_RSS_GROWTH_BYTES,
        "{protocol}: RSS grew {:.1} MiB — {rss_slope:.1} bytes per connection — between the two \
         measurement windows (mean {:.0} KiB in ({e_lo}, {e_hi}] against {:.0} KiB in \
         ({l_lo}, {l_hi}]). That is above both the {MAX_RSS_BYTES_PER_CONNECTION:.0} B/conn rate \
         budget and the {:.0} MiB absolute floor, so it is not an allocator arena step. If the \
         map slope above passed, the growth is in something the counters cannot see — a buffer, \
         a peer handle, an access-log row, a channel backlog.{}",
        rss_growth / 1048576.0,
        rss_early / 1024.0,
        rss_late / 1024.0,
        MIN_RSS_GROWTH_BYTES / 1048576.0,
        series(samples)
    );

    assert!(
        peak_tasks <= MAX_REGISTERED_TASKS,
        "{protocol}: the registered-task count reached {peak_tasks} while never more than \
         {IN_FLIGHT} connections were open at once. `register_server_task` prunes finished \
         handles on each new registration, so the steady state must be a function of live \
         connections, not of the {SOAK_CONNECTIONS} served.{}",
        series(samples)
    );
}

/// Everything that must be true once the traffic stops.
async fn assert_drained(state: &AppState, id: ServerId, protocol: &str, samples: &[Sample]) {
    let drained = wait_until(Duration::from_secs(60), || async {
        active_connections(state, id).await == 0
    })
    .await;
    assert!(
        drained,
        "{protocol}: {} connections were still marked Active 60s after every peer closed. A \
         server that never forgets a closed connection leaks one entry per connection served and \
         paints peers that are gone.{}",
        active_connections(state, id).await,
        series(samples)
    );

    // `close_connection_on_server` only flips the status to `Closed`; removing the entry is the
    // reaper's job. The harness reaper is running, but at the production ten-second retention, so
    // this sweeps at age zero rather than waiting it out. Retried to a deadline for the reason
    // the DNS sweep is: an entry that lands just after one pass is a straggler, and a straggler
    // converges. An entry the sweep can never reach does not.
    let emptied = wait_until(Duration::from_secs(30), || async {
        state.cleanup_closed_connections(0).await;
        tracked_connections(state, id).await == 0
    })
    .await;
    assert!(
        emptied,
        "{protocol}: {} connection entries survived repeated cleanup_closed_connections after \
         {SOAK_CONNECTIONS} connections.{}",
        tracked_connections(state, id).await,
        series(samples)
    );

    let recent = state.get_recent_connections(id).await.len();
    assert!(
        recent <= RECENT_CONNECTION_CAPACITY,
        "{protocol}: the recently-closed ring holds {recent} entries after {SOAK_CONNECTIONS} \
         connections; its declared cap is {RECENT_CONNECTION_CAPACITY}. An uncapped ring is a \
         leak that looks like a feature."
    );
}

/// Stop the server and prove the port is genuinely free, by binding it again.
async fn assert_stops_and_releases(state: &AppState, id: ServerId, port: u16, protocol: &str) {
    state.remove_server(id).await;
    assert!(
        state.get_server(id).await.is_none(),
        "{protocol}: the server survived remove_server"
    );

    let freed = wait_until(Duration::from_secs(10), || async {
        tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
    })
    .await;
    assert!(
        freed,
        "{protocol}: port {port} was still bound 10s after the server stopped. After \
         {SOAK_CONNECTIONS} connections the accept loop is the one task that has to end, and the \
         listener is the operator-visible proof that it did."
    );
}

// ---------------------------------------------------------------------------------------------
// The stream soak
// ---------------------------------------------------------------------------------------------

/// Open `SOAK_CONNECTIONS` short TCP connections, `IN_FLIGHT` at a time, sampling as it goes.
///
/// Each connection writes `payload` (empty means connect-and-close) and then closes cleanly, so
/// the server sees the ordinary EOF path rather than a reset. A reset would be a different and
/// also worth-testing path; it is not this one, because the clean close is what the tracking code
/// was written against.
async fn stream_soak(protocol: &str, payload: &'static [u8]) {
    let (state, id, port) = start_model_free(protocol).await;

    // Vacuity guard. If the server never tracked a connection, every "returns to zero" assertion
    // below is trivially true and this file proves nothing — the exact failure mode `CLAUDE.md`
    // records for tests that pass because the thing under test never ran.
    let mut ever_tracked = 0usize;
    let mut samples: Vec<Sample> = Vec::new();
    let mut served = 0usize;
    let started = std::time::Instant::now();

    while served < SOAK_CONNECTIONS {
        let batch = IN_FLIGHT.min(SOAK_CONNECTIONS - served);
        let mut set = Vec::with_capacity(batch);
        for _ in 0..batch {
            set.push(tokio::spawn(async move {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                if !payload.is_empty() {
                    s.write_all(payload)
                        .await
                        .map_err(|e| format!("write: {e}"))?;
                }
                // A *full* graceful close, not just a drop. Half-close the write side so the
                // server reads EOF, then drain until the server closes its half. Dropping a
                // socket that still has unread inbound data makes the kernel send RST instead
                // of FIN, which the server logs as a read error on a connection the peer
                // closed politely — a test artefact that looks exactly like a defect.
                let _ = s.shutdown().await;
                let mut sink = [0u8; 1024];
                loop {
                    match s.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => continue,
                    }
                }
                drop(s);
                Ok::<(), String>(())
            }));
        }
        for h in set {
            if let Ok(Err(e)) = h.await {
                panic!(
                    "{protocol}: connection {served} of {SOAK_CONNECTIONS} failed: {e}. \
                     At the failure the server held {} tracked connections ({} still Active) \
                     and {} registered tasks, with at most {IN_FLIGHT} peers open at once. \
                     If this is EADDRNOTAVAIL the ephemeral port range is exhausted — run \
                     this test alone, which is why it is #[ignore]d.{}",
                    tracked_connections(&state, id).await,
                    active_connections(&state, id).await,
                    state.server_task_count(id).await,
                    series(&samples)
                );
            }
        }
        let before = served;
        served += batch;

        // On the *crossing* of a multiple, not on an exact modulus: `served` advances in
        // `IN_FLIGHT`-sized steps, so `served % SAMPLE_EVERY == 0` samples at
        // `lcm(IN_FLIGHT, SAMPLE_EVERY)` instead — two samples per window where there should
        // have been twelve.
        if served / SAMPLE_EVERY > before / SAMPLE_EVERY {
            let tracked = tracked_connections(&state, id).await;
            ever_tracked = ever_tracked.max(tracked);
            samples.push(Sample {
                served,
                rss: rss_bytes(),
                tasks: state.server_task_count(id).await,
                tracked,
            });
        }

        // Hold the target rate. A deadline against the run's own start, not a fixed sleep per
        // batch: it self-corrects when a batch runs long, and it does not accumulate drift.
        let due = Duration::from_secs_f64(served as f64 / TARGET_CONNECTIONS_PER_SEC as f64);
        if let Some(wait) = due.checked_sub(started.elapsed()) {
            tokio::time::sleep(wait).await;
        }
    }

    println!(
        "[soak] {protocol}: {SOAK_CONNECTIONS} connections in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    assert!(
        ever_tracked > 0,
        "{protocol}: not one connection was ever tracked in AppState across \
         {SOAK_CONNECTIONS} connections, so every assertion in this test would pass on a server \
         that did nothing at all."
    );

    assert_flat(protocol, &samples);
    assert_drained(&state, id, protocol, &samples).await;
    assert_stops_and_releases(&state, id, port, protocol).await;
}

/// A plain stream server, and the reference implementation every other one was copied from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: ~25s, paced to outlast the 10s connection-retention window, and it fills the \
            ephemeral port range with TIME_WAIT so it cannot share a --test-threads=100 run; \
            nightly-soak.yml runs the four serially"]
async fn tcp_serves_ten_thousand_connections_without_growing() {
    stream_soak("tcp", b"soak\n").await;
}

/// hyper owns the connection here, so NetGet's tracking and the library's lifetime have to agree.
/// `CLAUDE.md` records `serve_connection` as the shape roughly thirty protocols share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: ~25s, paced to outlast the 10s connection-retention window, and it fills the \
            ephemeral port range with TIME_WAIT so it cannot share a --test-threads=100 run; \
            nightly-soak.yml runs the four serially"]
async fn http_serves_ten_thousand_connections_without_growing() {
    stream_soak(
        "http",
        b"GET /soak HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
}

/// A session protocol with its own framing and per-connection state machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: ~25s, paced to outlast the 10s connection-retention window, and it fills the \
            ephemeral port range with TIME_WAIT so it cannot share a --test-threads=100 run; \
            nightly-soak.yml runs the four serially"]
async fn redis_serves_ten_thousand_connections_without_growing() {
    stream_soak("redis", b"*1\r\n$4\r\nPING\r\n").await;
}

// ---------------------------------------------------------------------------------------------
// The datagram soak
// ---------------------------------------------------------------------------------------------

/// Ten thousand datagrams, and the sweep that is the only thing standing between them and
/// unbounded growth.
///
/// A connectionless server has no close path by construction. `src/server/dns/mod.rs` inserts a
/// **new** `ConnectionState`, with a fresh id, for **every datagram** — not per peer — so ten
/// thousand queries from one socket are ten thousand entries, and `cleanup_old_connections` is
/// the whole defence. `CLAUDE.md` is emphatic that the sweep runs only where
/// `ProtocolMetadataV2::connectionless` is declared, and that a protocol that forgets the flag
/// "leaks idle entries until its server stops". This is the test of that declaration.
///
/// It is paced at the same rate as the stream soaks, for one reason that does not apply there:
/// the run has to outlast [`CONNECTION_RETENTION_SECS`]. Unpaced, ten thousand datagrams take
/// about three seconds, the sweep never fires once, and the test would assert only that a map
/// nothing had yet tried to reap had grown — which is true of a leaking server too. At 400/s the
/// run lasts ~25 s, the sweep fires repeatedly, and the same steady-state assertions the stream
/// soaks use apply unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: 10k datagrams paced to outlast the 10s idle sweep takes ~25s, too slow for the \
            normal suite; nightly-soak.yml runs it"]
async fn dns_sweeps_ten_thousand_datagrams_back_to_zero() {
    let (state, id, port) = start_model_free("dns").await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a client socket");
    sock.connect(("127.0.0.1", port))
        .await
        .expect("connect the client socket");

    let mut samples: Vec<Sample> = Vec::new();
    let mut ever_tracked = 0usize;
    let started = std::time::Instant::now();

    for n in 1..=SOAK_CONNECTIONS {
        sock.send(&dns_query(n as u16)).await.expect("send a query");

        if n % SAMPLE_EVERY == 0 {
            let tracked = tracked_connections(&state, id).await;
            ever_tracked = ever_tracked.max(tracked);
            samples.push(Sample {
                served: n,
                rss: rss_bytes(),
                tasks: state.server_task_count(id).await,
                tracked,
            });
        }

        let due = Duration::from_secs_f64(n as f64 / TARGET_CONNECTIONS_PER_SEC as f64);
        if let Some(wait) = due.checked_sub(started.elapsed()) {
            tokio::time::sleep(wait).await;
        }
    }

    println!(
        "[soak] dns: {SOAK_CONNECTIONS} datagrams in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    // Vacuity guard: the server has to have seen the traffic, or everything below is a statement
    // about an empty map. A datagram protocol can drop, so this is a floor rather than equality —
    // but the floor is high enough that silent total loss cannot pass.
    assert!(
        ever_tracked >= SOAK_CONNECTIONS / 10,
        "dns never tracked more than {ever_tracked} entries while {SOAK_CONNECTIONS} datagrams \
         were sent, so the sweep assertions below would be statements about an empty map. Either \
         the datagrams were dropped before the server's recv loop or they were never parsed as \
         queries.{}",
        series(&samples)
    );

    assert_flat("dns", &samples);

    // The traffic has stopped, so a full sweep must return the map to empty. Retried to a
    // deadline rather than run once: a datagram still inside the server's own handler when the
    // first sweep collected its list lands afterwards, which is a straggler and not a leak. What
    // would be a leak is an entry the sweep can never reach, and that does not converge.
    let swept = wait_until(Duration::from_secs(30), || async {
        state.cleanup_old_connections(0).await;
        tracked_connections(&state, id).await == 0
    })
    .await;
    assert!(
        swept,
        "dns kept {} connection entries after repeated full idle sweeps. A connectionless server \
         has no close path, so an entry the sweep cannot reach is leaked for the life of the \
         server.{}",
        tracked_connections(&state, id).await,
        series(&samples)
    );

    let recent = state.get_recent_connections(id).await.len();
    assert!(
        recent <= RECENT_CONNECTION_CAPACITY,
        "dns: the recently-closed ring holds {recent} entries, cap is {RECENT_CONNECTION_CAPACITY}"
    );

    assert_stops_and_releases_udp(&state, id, port, "dns").await;
}

/// A minimal well-formed DNS query for `soak.example.com A IN`, with `id` as the transaction id.
///
/// Hand-built rather than taken from a crate so this test's traffic is an independent reading of
/// RFC 1035 rather than whatever NetGet's own encoder produces.
fn dns_query(id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(38);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT 1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR 0
    for label in ["soak", "example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    q
}

async fn assert_stops_and_releases_udp(state: &AppState, id: ServerId, port: u16, protocol: &str) {
    state.remove_server(id).await;
    let freed = wait_until(Duration::from_secs(10), || async {
        tokio::net::UdpSocket::bind(("127.0.0.1", port))
            .await
            .is_ok()
    })
    .await;
    assert!(
        freed,
        "{protocol}: UDP port {port} was still bound 10s after the server stopped"
    );
}
