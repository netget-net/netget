//! How much the single `AppState` lock costs a busy deterministic server.
//!
//! `AppState` keeps servers, connections, access log, history and the rest behind one tokio
//! `RwLock`, and every per-message bookkeeping call (`record_access_log`,
//! `update_connection_stats`, …) takes it for writing. The question this harness answers is
//! whether that is a ceiling at loads NetGet is used at, or only on paper.
//!
//! It drives `C` persistent connections through a real TCP server whose only event is answered
//! by a static handler (no model call: the LLM endpoint is unroutable, so reaching it would
//! show up as a failed reply). Each connection sends `PING\n`, waits for `PONG\n`, and repeats
//! for a fixed window; the harness reports requests per second and p50/p99 round-trip latency.
//! Every connection count runs four times over:
//!
//! - **no readers** — the server alone;
//! - **dash 10Hz** — `build_snapshot` every 100 ms, the dashboard's own tick;
//! - **dashboard** — one task calling the dashboard's own `build_snapshot` back to back, which
//!   is the worst a dashboard can do (it repolls on every `__UPDATE_UI__`, a 1 s stats tick and
//!   every keypress; back to back is the upper bound of all three);
//! - **mcp** — four tasks polling `get_all_servers` and `list_access_logs`, as several MCP
//!   clients calling `list_servers` / `list_access_logs` in a loop would.
//!
//! It asserts only that every request was answered with the right bytes. Timing is reported,
//! not asserted: a wall-clock bound in a shared test run is a flake, and the numbers belong in a
//! review, not in a gate. The test is `#[ignore]`d so it runs only when asked for:
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!     --test app_state_contention_test -- --ignored --nocapture
//! ```
//!
//! A debug build is what the review measured (a release build of this crate doubles the target
//! directory). Debug code holds the lock longer than release code does, so the contention it
//! shows is an upper bound.
//!
//! `NETGET_CONTENTION_SECS` sets the window per cell (default 3) and
//! `NETGET_CONTENTION_CONNS` the comma-separated connection counts (default `1,16,64,256`).

use netget::llm::ollama_client::OllamaClient;
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
use netget::server::TcpServer;
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The history depth `tcp` declares (`HistoryMode::Last(SESSION_HISTORY_ENTRIES)`), so every
/// exchange is also written into the connection's history, as it is in production.
const TCP_HISTORY_ENTRIES: u16 = 40;

#[derive(Clone, Copy, Debug)]
enum Readers {
    None,
    /// The dashboard at the cadence it really polls: its loop ticks every 100 ms.
    Dashboard10Hz,
    Dashboard,
    Mcp,
}

impl Readers {
    fn label(self) -> &'static str {
        match self {
            Readers::None => "none",
            Readers::Dashboard10Hz => "dash 10Hz",
            Readers::Dashboard => "dashboard",
            Readers::Mcp => "mcp x4",
        }
    }
}

struct Cell {
    connections: usize,
    readers: Readers,
    requests: u64,
    secs: f64,
    p50_us: u64,
    p99_us: u64,
    max_us: u64,
    reader_polls: u64,
    status_lines: u64,
}

async fn start_server() -> (Arc<AppState>, ServerId, SocketAddr, Arc<AtomicU64>) {
    let state = Arc::new(AppState::new());
    let server = ServerInstance::new(ServerId::new(0), 0, "tcp".to_string(), String::new());
    let server_id = state.add_server(server).await;
    state
        .set_server_conversation_settings(server_id, TCP_HISTORY_ENTRIES, false)
        .await;

    let mut config = EventHandlerConfig::new();
    config.add_handler(EventHandler::new(
        EventPattern::specific("tcp_data_received"),
        EventHandlerType::static_response(vec![serde_json::json!({
            "type": "send_tcp_data", "data": "PONG\n", "encoding": "utf8"
        })]),
    ));
    state
        .set_event_handler_config(server_id, Some(config))
        .await;

    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    // Drained as the dashboard would, and counted: how many status lines one exchange costs is
    // what decides whether a peer can outrun the status channel's consumer.
    let status_lines = Arc::new(AtomicU64::new(0));
    let counter = status_lines.clone();
    tokio::spawn(async move {
        while status_rx.recv().await.is_some() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });

    let addr = TcpServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx,
        false,
        server_id,
        None,
        None,
    )
    .await
    .expect("TCP server should start");
    (state, server_id, addr, status_lines)
}

fn spawn_readers(
    state: &Arc<AppState>,
    readers: Readers,
    stop: &Arc<AtomicBool>,
    polls: &Arc<AtomicU64>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let tasks = match readers {
        Readers::None => 0,
        Readers::Dashboard10Hz | Readers::Dashboard => 1,
        Readers::Mcp => 4,
    };
    (0..tasks)
        .map(|_| {
            let state = state.clone();
            let stop = stop.clone();
            let polls = polls.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    match readers {
                        Readers::Dashboard10Hz => {
                            let snapshot = netget::tui::projection::build_snapshot(&state).await;
                            std::hint::black_box(snapshot);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Readers::Dashboard => {
                            let snapshot = netget::tui::projection::build_snapshot(&state).await;
                            std::hint::black_box(snapshot);
                        }
                        Readers::Mcp => {
                            let servers = state.get_all_servers().await;
                            let logs = state.list_access_logs(None).await;
                            std::hint::black_box((servers, logs));
                        }
                        Readers::None => unreachable!(),
                    }
                    polls.fetch_add(1, Ordering::Relaxed);
                    // Yield so a reader on the same worker cannot starve the server outright;
                    // the cost being measured is the lock, not a monopolised thread.
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect()
}

async fn run_cell(connections: usize, readers: Readers, window: Duration) -> Cell {
    let (state, server_id, addr, status_lines) = start_server().await;

    // Connect everything first, so the window measures steady-state traffic, not accepts.
    let mut streams = Vec::with_capacity(connections);
    for _ in 0..connections {
        streams.push(tokio::net::TcpStream::connect(addr).await.expect("connect"));
    }
    // One warm-up exchange each: the connection is registered and its first-byte path taken.
    for stream in &mut streams {
        exchange(stream).await.expect("warm-up exchange");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicU64::new(0));
    let reader_tasks = spawn_readers(&state, readers, &stop, &polls);

    let status_before = status_lines.load(Ordering::Relaxed);
    let started = Instant::now();
    let deadline = started + window;
    let clients: Vec<_> = streams
        .into_iter()
        .map(|mut stream| {
            tokio::spawn(async move {
                let mut samples = Vec::with_capacity(4096);
                while Instant::now() < deadline {
                    let t = Instant::now();
                    exchange(&mut stream).await?;
                    samples.push(t.elapsed().as_micros() as u64);
                }
                Ok::<Vec<u64>, String>(samples)
            })
        })
        .collect();

    let mut all = Vec::new();
    for client in clients {
        all.extend(
            client
                .await
                .expect("client task")
                .expect("every request answered"),
        );
    }
    let secs = started.elapsed().as_secs_f64();
    let status = status_lines.load(Ordering::Relaxed) - status_before;
    stop.store(true, Ordering::Relaxed);
    for task in reader_tasks {
        let _ = task.await;
    }
    state.remove_server(server_id).await;

    all.sort_unstable();
    let pct = |p: f64| all[((all.len() as f64 * p) as usize).min(all.len() - 1)];
    Cell {
        connections,
        readers,
        requests: all.len() as u64,
        secs,
        p50_us: pct(0.50),
        p99_us: pct(0.99),
        max_us: *all.last().unwrap(),
        reader_polls: polls.load(Ordering::Relaxed),
        status_lines: status,
    }
}

/// One request/response round trip: `PING\n` out, exactly `PONG\n` back.
async fn exchange(stream: &mut tokio::net::TcpStream) -> Result<(), String> {
    stream
        .write_all(b"PING\n")
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .map_err(|_| "timed out waiting for PONG".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    if &buf != b"PONG\n" {
        return Err(format!(
            "unexpected reply {:?}",
            String::from_utf8_lossy(&buf)
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark: run with --ignored --nocapture"]
async fn app_state_lock_contention_under_static_tcp_load() {
    let window = Duration::from_secs(
        std::env::var("NETGET_CONTENTION_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3),
    );
    let conns: Vec<usize> = std::env::var("NETGET_CONTENTION_CONNS")
        .ok()
        .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 16, 64, 256]);

    let mut cells = Vec::new();
    for &c in &conns {
        for readers in [
            Readers::None,
            Readers::Dashboard10Hz,
            Readers::Dashboard,
            Readers::Mcp,
        ] {
            cells.push(run_cell(c, readers, window).await);
        }
    }

    println!();
    println!(
        "{:>5}  {:<10} {:>10} {:>9} {:>9} {:>9} {:>14} {:>12}",
        "conns", "readers", "req/s", "p50 us", "p99 us", "max us", "reader polls/s", "status/req"
    );
    for cell in &cells {
        assert!(cell.requests > 0, "no request completed in {} s", cell.secs);
        println!(
            "{:>5}  {:<10} {:>10.0} {:>9} {:>9} {:>9} {:>14.0} {:>12.2}",
            cell.connections,
            cell.readers.label(),
            cell.requests as f64 / cell.secs,
            cell.p50_us,
            cell.p99_us,
            cell.max_us,
            cell.reader_polls as f64 / cell.secs,
            cell.status_lines as f64 / cell.requests as f64,
        );
    }
}
