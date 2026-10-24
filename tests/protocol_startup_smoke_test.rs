//! Integration smoke test: every registered server protocol must start HONESTLY.
//!
//! The per-protocol E2E suites exercise one protocol in isolation against a mocked
//! LLM. This test does the opposite: it walks the *whole* server registry and drives
//! each protocol through the real startup path (`cli::server_startup::
//! start_server_from_action`), the same one the TUI, the `open_server` action and the
//! MCP `start_server` tool use. It asserts nothing about protocol behaviour — only
//! that starting, reporting and stopping tell the truth.
//!
//! ## What counts as a failure
//!
//! * **`LiedAboutListening`** — the single most important case. `spawn()` returned a
//!   concrete `SocketAddr`, `server_startup` recorded `ServerStatus::Running` and set
//!   `local_addr`, and yet the port is free: nothing is bound. This exact bug has been
//!   found four separate times in this repo (`arp`, `datalink`, `icmp`, `isis`, all of
//!   which used fire-and-forget `spawn_blocking` and never awaited readiness).
//! * **`Hang`** — `spawn()` did not return within `START_TIMEOUT`. A start that never
//!   comes back is a defect regardless of what it was waiting for.
//! * **`Panicked`** — `spawn()` unwound. Startup params, missing devices and absent
//!   privileges must all produce `Err`, never a panic.
//! * **`PortLeak`** — after `remove_server()` the socket is still held. Almost always a
//!   missing `AppState::register_server_task()` in `spawn()`: dropping a Tokio
//!   `JoinHandle` merely detaches the task, so the accept loop keeps the port until
//!   process exit.
//! * **`ExternalHostDefault`** — the protocol's `default_binding()` names a host that
//!   is not loopback or a wildcard. Such a protocol is not started at all: a smoke test
//!   must never touch the network.
//!
//! ## What does not count as a failure
//!
//! * **`RefusedCleanly`** — `Err` with a message, promptly. This is the correct outcome
//!   for a protocol needing raw sockets, packet capture, a TUN device or a hardware
//!   device this machine lacks, and for one whose default interface does not exist
//!   here (`lo` is Linux; macOS calls it `lo0`). Refusing is not skipping — the reason
//!   is recorded in the report and can be reviewed.
//! * **`RunningNoSocket`** — `Running` with no bound socket. Legitimate for genuinely
//!   socketless protocols (WebRTC is peer-to-peer; Bluetooth, USB and NFC speak to a
//!   device), and `server_startup::is_bound_addr` already declines to advertise an
//!   endpoint for them. It is reported as a distinct bucket rather than a pass,
//!   because it is the one bucket this test cannot verify.
//! * **`RunningUnverifiable`** — `Running` with an address that is not a local
//!   endpoint and so cannot be probed. Probing such an address says nothing about
//!   NetGet — on a machine where anything else has joined the same multicast group (a
//!   stray `zeroconf` process is enough) it reads as held whether or not NetGet is
//!   running, which would produce both false passes and false port-leak reports.
//!   **No protocol lands here any more.** mDNS did: it reported the `224.0.0.251:5353`
//!   multicast *group* it announces on as though it were its endpoint. It now returns
//!   the `0.0.0.0:0` "no listening socket" placeholder like every other socketless
//!   protocol and shows up as `RunningNoSocket`, with the group reported on the status
//!   stream where it belongs (`src/server/mdns/mod.rs`). The bucket stays because the
//!   distinction is real and the next protocol to make that mistake should be named,
//!   not silently passed.
//!
//! ## Isolation
//!
//! * The LLM client points at `http://127.0.0.1:1` — connection-refused on the first
//!   packet. No model is contacted, and no external endpoint of any kind is.
//! * Port `0` is requested for every port-based protocol, so each start gets an
//!   ephemeral loopback port.
//! * Protocols run one at a time, each torn down before the next starts, so a protocol
//!   that ignores the requested port and binds a fixed one cannot collide with another.
//!
//! ## Running it
//!
//! ```bash
//! ./cargo-isolated.sh test --all-features --test protocol_startup_smoke_test \
//!     -- --test-threads=100 --nocapture
//! ```
//!
//! `--all-features` is the point: with fewer features the registry is smaller and the
//! sweep says correspondingly less. Set `NETGET_SMOKE_REPORT=<path>` to also write the
//! full table to a file. Set `NETGET_SMOKE_ONLY=<name>[,<name>...]` to sweep a subset
//! while debugging one protocol.

use netget::protocol::metadata::{DevelopmentState, PortTransport, PrivilegeRequirement};
use netget::state::app_state::AppState;
use netget::state::server::ServerStatus;
use netget::state::ServerId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a single `spawn()` may take before it is called a hang.
///
/// Generous on purpose: some protocols generate a TLS keypair or a host key on first
/// start. Anything past this is not slow, it is stuck.
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to wait for the socket to disappear after `remove_server()`.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the whole server sweep may take before it stops and fails.
///
/// The sweep takes seconds. Without a bound of its own, a start that wedges something every
/// later start needs turns each of the ~300 remaining protocols into a `START_TIMEOUT` hang,
/// and the job is killed at its limit with nothing printed: on 24 October 2026 one sweep ran
/// from 03:51 until the 60-minute job limit, and since libtest captures a test's output the log
/// could not say which protocol it was on. Past this the sweep fails with every protocol's
/// verdict and timing so far, and the ones it did not reach.
const SWEEP_DEADLINE: Duration = Duration::from_secs(300);

/// How long past its own deadline the sweep may be silent before the watchdog thread speaks.
///
/// The per-protocol `START_TIMEOUT` and the sweep deadline are both tokio timers, which fire
/// only while the runtime can run. A start that blocks every worker thread stops both of them,
/// so a plain OS thread watches from outside the runtime.
const WATCHDOG_GRACE: Duration = Duration::from_secs(15);

/// How long the shared `AppState` may take to answer after a protocol hung.
///
/// A hung start that is still holding the state's lock makes every later start wait on it, and
/// each would then be reported as a hang of its own.
const STATE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A start taking at least this long is printed outside libtest's capture as it happens.
const SLOW_START_MS: u128 = 5_000;

/// Hosts a protocol may legitimately default to. Anything else means the smoke test
/// would put packets on a network it does not own.
const LOCAL_HOSTS: &[&str] = &["127.0.0.1", "0.0.0.0", "::1", "::", "localhost", "[::1]"];

/// Client protocols this sweep refuses to run, and why.
///
/// This is an explicit, reported exclusion, not a silent skip: the reason is printed in
/// the report next to the protocol, so it reads as "not tested, here is why" rather than
/// as a pass. Nothing belongs here except a protocol that cannot be exercised without
/// leaving the machine.
/// Empty, and worth keeping that way.
///
/// `Tor` was the one entry: `connect()` called arti's `TorClient::create_bootstrapped()`,
/// which bootstraps against the real Tor directory authorities before it ever looks at the
/// requested address, so running it here would have put a smoke test on the public internet.
/// That was fixed at the source rather than skipped — the client now refuses to bootstrap
/// unless the caller passes `directory_server` or `allow_public_tor_network: true`
/// (`src/client/tor/mod.rs::bootstrap_target`) — so it is swept like everything else and shows
/// up as `refused cleanly`. Fixing the protocol is always available; excluding it is the last
/// resort, and an exclusion here is a standing admission that one protocol is untested.
const CLIENT_SKIPS: &[(&str, &str)] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Running, socket bound, and the kernel completes a TCP handshake on it.
    Listening,
    /// Running and the port is held, but by a datagram socket — there is no handshake
    /// to complete, so "held" is as far as verification goes.
    ListeningDatagram,
    /// Running and the port is held by an **SCTP** socket. Same reasoning as the datagram
    /// case: this probe cannot complete an SCTP association, so "held" is as far as it goes.
    ListeningSctp,
    /// Running but `spawn()` reported no endpoint. Cannot be verified here.
    RunningNoSocket,
    /// Running with an address that is not a probeable local endpoint (a multicast
    /// group). Reported, not verified — see the module docs.
    RunningUnverifiable,
    /// Running, an endpoint was advertised, and the port is free. **Defect.**
    LiedAboutListening,
    /// Clean `Err` from the startup path, with a reason.
    RefusedCleanly(String),
    /// `spawn()` never returned. **Defect.**
    Hang,
    /// `spawn()` unwound. **Defect.**
    Panicked(String),
    /// `default_binding()` names a non-local host, so it was never started. **Defect.**
    ExternalHostDefault(String),
}

impl Verdict {
    fn is_failure(&self) -> bool {
        matches!(
            self,
            Verdict::LiedAboutListening
                | Verdict::Hang
                | Verdict::Panicked(_)
                | Verdict::ExternalHostDefault(_)
        )
    }

    fn label(&self) -> &'static str {
        match self {
            Verdict::Listening => "LISTENING",
            Verdict::ListeningDatagram => "LISTENING-udp",
            Verdict::ListeningSctp => "LISTENING-sctp",
            Verdict::RunningNoSocket => "no-socket",
            Verdict::RunningUnverifiable => "unverifiable",
            Verdict::LiedAboutListening => "LIED",
            Verdict::RefusedCleanly(_) => "refused",
            Verdict::Hang => "HANG",
            Verdict::Panicked(_) => "PANIC",
            Verdict::ExternalHostDefault(_) => "EXTERNAL-HOST",
        }
    }

    fn detail(&self) -> String {
        match self {
            Verdict::RefusedCleanly(m) | Verdict::Panicked(m) | Verdict::ExternalHostDefault(m) => {
                one_line(m)
            }
            _ => String::new(),
        }
    }
}

struct Row {
    protocol: String,
    dev_state: DevelopmentState,
    privilege: PrivilegeRequirement,
    verdict: Verdict,
    ready_ms: u128,
    /// Number of `JoinHandle`s the protocol registered via `register_server_task()`.
    tasks: usize,
    /// Set when the port survived `remove_server()`.
    port_leaked: bool,
    addr: Option<SocketAddr>,
    /// The last [`STATUS_LINES_KEPT`] status messages the server itself emitted. Printed under
    /// any row that fails the honesty check or leaks its port, so an intermittent verdict says
    /// what the server reported rather than only what the probe saw (IMPROVEMENTS item 82).
    status_log: Vec<String>,
}

/// How many of a server's own status messages a row keeps for its failure report.
const STATUS_LINES_KEPT: usize = 40;

/// Collapse a multi-line error into something a table cell can hold.
fn one_line(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = flat.chars().take(140).collect();
    if flat.chars().count() > 140 {
        out.push('…');
    }
    out
}

/// Can this address be probed at all?
///
/// A multicast group is not an endpoint anyone owns: joining it is not binding it, and
/// any other process on the machine that has joined makes it look occupied. Treating
/// one as evidence produces false passes *and* false port-leak reports, so addresses
/// like these are excluded from probing rather than mis-measured.
fn is_probeable(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast(),
        std::net::IpAddr::V6(v6) => !v6.is_multicast(),
    }
}

/// What, if anything, is holding `addr`.
///
/// Check only the protocol's declared transport. A TCP socket or TIME_WAIT at the
/// same numeric port does not belong to a UDP server, and must not mask its listener
/// or read as its leak after stop. The transports have independent port namespaces.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Held {
    /// The declared transport is free.
    Nothing,
    /// The TCP half is taken.
    Tcp,
    /// The UDP half is taken.
    Udp,
    /// An **SCTP** socket holds the port.
    ///
    /// SCTP is IP protocol 132 and has its own port namespace, so a listening SCTP socket
    /// leaves both `TcpListener::bind` and `UdpSocket::bind` free. Without this arm the
    /// probe reads a correctly listening SCTP server as an empty port and calls it a liar —
    /// which is what it did to `m3ua`, the one protocol here whose transport RFC 4666
    /// section 1.4.1 defines as SCTP.
    Sctp,
}

/// Is `addr` held by a listening SCTP socket?
///
/// `None` when the question cannot be asked: a host with no SCTP stack (macOS ships neither
/// kernel support nor headers; a Linux kernel without the `sctp` module behaves the same)
/// fails at `socket(2)`, and on such a host `m3ua` refuses to start in the first place, so
/// the probe never reaches here for it.
fn sctp_holds(addr: SocketAddr) -> Option<bool> {
    use socket2::{Domain, Protocol, Socket, Type};
    /// IANA protocol number for SCTP, as `src/server/m3ua/mod.rs` names it.
    const IPPROTO_SCTP: i32 = 132;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP))).ok()?;
    // No SO_REUSEADDR: the point is to find out whether the address is taken.
    Some(socket.bind(&addr.into()).is_err())
}

fn probe_port(addr: SocketAddr, transport: PortTransport) -> Held {
    match transport {
        PortTransport::Tcp if std::net::TcpListener::bind(addr).is_err() => Held::Tcp,
        PortTransport::Udp if std::net::UdpSocket::bind(addr).is_err() => Held::Udp,
        PortTransport::Sctp if sctp_holds(addr) == Some(true) => Held::Sctp,
        _ => Held::Nothing,
    }
}

/// Does the kernel complete a TCP handshake on `addr`?
///
/// This is the difference between "a socket is bound" and "a server is listening": a
/// socket that was bound but never `listen()`ed refuses the connection. It does *not*
/// require the protocol to have called `accept()` yet — the kernel completes the
/// handshake from the backlog — which is exactly right for a smoke test that must not
/// depend on the protocol's own timing.
fn tcp_accepts(addr: SocketAddr) -> bool {
    // Connect to loopback rather than to a wildcard address, which is not a
    // destination.
    let target = if addr.ip().is_unspecified() {
        match addr.ip() {
            std::net::IpAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], addr.port())),
            std::net::IpAddr::V6(_) => {
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()))
            }
        }
    } else {
        addr
    };
    std::net::TcpStream::connect_timeout(&target, Duration::from_secs(2)).is_ok()
}

async fn wait_until_released(addr: SocketAddr, transport: PortTransport) -> bool {
    let deadline = Instant::now() + RELEASE_TIMEOUT;
    while Instant::now() < deadline {
        if probe_port(addr, transport) == Held::Nothing {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    probe_port(addr, transport) == Held::Nothing
}

#[tokio::test]
async fn udp_listener_and_release_ignore_a_tcp_socket_at_the_same_port() {
    // This bound, non-listening TCP socket reproduces the old LIED verdict:
    // its bind fails and its handshake is refused, while UDP is listening correctly.
    let tcp = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    tcp.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let addr = tcp.local_addr().unwrap().as_socket().unwrap();
    let udp = std::net::UdpSocket::bind(addr).unwrap();
    assert_eq!(probe_port(addr, PortTransport::Udp), Held::Udp);
    assert!(!tcp_accepts(addr));
    drop(udp);
    assert!(wait_until_released(addr, PortTransport::Udp).await);
    assert_eq!(probe_port(addr, PortTransport::Tcp), Held::Tcp);
    drop(tcp);
}

#[test]
fn tcp_probe_does_not_count_an_unrelated_udp_socket_as_listening() {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    assert_eq!(probe_port(addr, PortTransport::Udp), Held::Udp);
    assert_eq!(probe_port(addr, PortTransport::Tcp), Held::Nothing);
}

/// Drive one protocol through start → verify → stop.
async fn probe_protocol(
    state: &Arc<AppState>,
    name: &str,
    proto: &Arc<dyn netget::llm::actions::Server>,
) -> Row {
    let metadata = proto.metadata();
    let binding = proto.default_binding();

    // Refuse to start anything whose default host is not local. Reporting this is the
    // whole point; starting it would defeat it.
    if let Some(host) = binding.as_ref().and_then(|b| b.host.clone()) {
        if !LOCAL_HOSTS.contains(&host.as_str()) {
            return Row {
                protocol: name.to_string(),
                dev_state: metadata.state,
                privilege: metadata.privilege_requirement,
                verdict: Verdict::ExternalHostDefault(format!(
                    "default_binding().host = {host:?}, which is not loopback or a wildcard"
                )),
                ready_ms: 0,
                tasks: 0,
                port_leaked: false,
                addr: None,
                status_log: Vec::new(),
            };
        }
    }

    // Ask for an ephemeral port only where a port is meaningful. Interface-based
    // protocols declare `port: None`; forcing a port on them would exercise a path no
    // real caller uses.
    let port = match &binding {
        Some(b) => b.port.map(|_| 0u16),
        // Unmigrated protocols have no `default_binding()` and `start_server_from_action`
        // requires an explicit port from them.
        None => Some(0u16),
    };

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    // Drain, so the unbounded channel does not grow and nothing blocks on a full queue, keeping
    // the most recent messages for the failure report.
    let status_log = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let drain = {
        let status_log = Arc::clone(&status_log);
        tokio::spawn(async move {
            let mut rx = status_rx;
            while let Some(line) = rx.recv().await {
                let mut log = status_log.lock().expect("status log");
                if log.len() == STATUS_LINES_KEPT {
                    log.pop_front();
                }
                log.push_back(line);
            }
        })
    };

    let started = Instant::now();

    // Run the start in its own task. A panic then arrives as a `JoinError` naming the
    // protocol instead of taking the whole sweep down, and a hang can be timed out and
    // attributed rather than stalling every protocol after it.
    let start_state = state.clone();
    let start_name = name.to_string();
    let handle = tokio::spawn(async move {
        netget::cli::server_startup::start_server_from_action(
            &start_state,
            None, // mac_address
            None, // interface — use the protocol's declared default
            None, // host — use the protocol's declared default
            port,
            &start_name,
            false, // send_first: a connect-time banner needs an LLM we deliberately do not have
            None,  // initial_memory
            "smoke test: verify this protocol starts, listens and stops".to_string(),
            None,               // startup_params — exercise the protocol's own defaults
            None,               // event_handlers
            None,               // scheduled_tasks
            None,               // feedback_instructions
            Default::default(), // history / batching overrides
            status_tx,
        )
        .await
    });

    let mut handle = handle;
    let outcome = tokio::time::timeout(START_TIMEOUT, &mut handle).await;
    let ready_ms = started.elapsed().as_millis();

    let mut row = Row {
        protocol: name.to_string(),
        dev_state: metadata.state,
        privilege: metadata.privilege_requirement,
        verdict: Verdict::Hang,
        ready_ms,
        tasks: 0,
        port_leaked: false,
        addr: None,
        status_log: Vec::new(),
    };

    let server_id: Option<ServerId> = match outcome {
        Err(_elapsed) => {
            // Timed out. Abort so the sweep is not slowly poisoned by stuck tasks —
            // abort cannot rescue a genuinely blocking call, but it releases the
            // cooperative ones. Dropping the handle would not: a dropped `JoinHandle`
            // detaches its task and leaves it running, holding whatever it holds.
            handle.abort();
            row.verdict = Verdict::Hang;
            None
        }
        Ok(Err(join_err)) => {
            let msg = if join_err.is_panic() {
                match join_err.into_panic().downcast::<String>() {
                    Ok(s) => *s,
                    Err(other) => match other.downcast::<&'static str>() {
                        Ok(s) => s.to_string(),
                        Err(_) => "non-string panic payload".to_string(),
                    },
                }
            } else {
                "task cancelled".to_string()
            };
            row.verdict = Verdict::Panicked(msg);
            None
        }
        Ok(Ok(Err(e))) => {
            row.verdict = Verdict::RefusedCleanly(e.to_string());
            None
        }
        Ok(Ok(Ok(id))) => Some(id),
    };

    if let Some(id) = server_id {
        let server = state.get_server(id).await;
        row.tasks = state.server_task_count(id).await;

        let status = server.as_ref().map(|s| s.status.clone());
        let addr = server.as_ref().and_then(|s| s.local_addr);
        row.addr = addr;

        row.verdict = match (status, addr) {
            (Some(ServerStatus::Running), Some(a)) if !is_probeable(&a) => {
                Verdict::RunningUnverifiable
            }
            (Some(ServerStatus::Running), Some(a)) => {
                match probe_port(a, metadata.well_known_transport) {
                    Held::Nothing => Verdict::LiedAboutListening,
                    Held::Udp => Verdict::ListeningDatagram,
                    Held::Sctp => Verdict::ListeningSctp,
                    Held::Tcp => {
                        if tcp_accepts(a) {
                            Verdict::Listening
                        } else {
                            // The port is taken but refuses a connection: bound without
                            // `listen()`, or held by a socket in some other state. Either
                            // way `Running` promised an endpoint that does not answer.
                            Verdict::LiedAboutListening
                        }
                    }
                }
            }
            (Some(ServerStatus::Running), None) => Verdict::RunningNoSocket,
            (Some(ServerStatus::Error(e)), _) => Verdict::RefusedCleanly(e),
            // `start_server_from_action` returned `Ok(server_id)`, so the caller was
            // told the start succeeded. Any other recorded status — or no server at
            // all — contradicts that.
            (None, _) => Verdict::LiedAboutListening,
            (Some(s), _) => Verdict::Panicked(format!(
                "start returned Ok but the recorded status is {s:?}, not Running"
            )),
        };

        // Stop it and check the socket really goes away. Only meaningful for an
        // address this test actually owns — see `is_probeable`.
        state.remove_server(id).await;
        if let Some(a) = addr {
            if is_probeable(&a) && !wait_until_released(a, metadata.well_known_transport).await {
                row.port_leaked = true;
            }
        }
    }

    drain.abort();
    row.status_log = status_log
        .lock()
        .expect("status log")
        .iter()
        .cloned()
        .collect();
    row
}

fn dev_state_str(s: &DevelopmentState) -> &'static str {
    match s {
        DevelopmentState::Incomplete => "Incomplete",
        DevelopmentState::Experimental => "Experimental",
        DevelopmentState::Beta => "Beta",
        DevelopmentState::Stable => "Stable",
    }
}

fn priv_str(p: &PrivilegeRequirement) -> String {
    match p {
        PrivilegeRequirement::None => "None".to_string(),
        PrivilegeRequirement::PrivilegedPort(port) => format!("PrivilegedPort({port})"),
        PrivilegeRequirement::RawSockets => "RawSockets".to_string(),
        PrivilegeRequirement::PacketCapture => "PacketCapture".to_string(),
        PrivilegeRequirement::DeviceAccess(c) => format!("DeviceAccess({})", c.as_str()),
        PrivilegeRequirement::Root => "Root".to_string(),
    }
}

fn render_report(rows: &[Row]) -> String {
    let mut out = String::new();
    out.push_str("\n=== NetGet server protocol startup smoke test ===\n\n");
    out.push_str(&format!(
        "{:<26} {:<13} {:<22} {:<14} {:>7} {:>5}  {}\n",
        "PROTOCOL", "STATE", "PRIVILEGE", "VERDICT", "ms", "tasks", "DETAIL"
    ));
    out.push_str(&"-".repeat(150));
    out.push('\n');

    for r in rows {
        let mut detail = r.verdict.detail();
        if r.port_leaked {
            detail = format!("PORT LEAK after stop ({}); {detail}", r.addr.unwrap());
        }
        out.push_str(&format!(
            "{:<26} {:<13} {:<22} {:<14} {:>7} {:>5}  {}\n",
            r.protocol,
            dev_state_str(&r.dev_state),
            priv_str(&r.privilege),
            r.verdict.label(),
            r.ready_ms,
            r.tasks,
            detail
        ));
    }

    for r in rows
        .iter()
        .filter(|r| r.verdict.is_failure() || r.port_leaked)
    {
        out.push_str(&format!(
            "\n--- {}: the server's own last {} status message(s) ---\n",
            r.protocol,
            r.status_log.len()
        ));
        for line in &r.status_log {
            out.push_str(&format!("  {}\n", one_line(line)));
        }
    }

    let count = |f: &dyn Fn(&Row) -> bool| rows.iter().filter(|r| f(r)).count();
    let total = rows.len();
    let tcp = count(&|r| r.verdict == Verdict::Listening);
    let udp = count(&|r| r.verdict == Verdict::ListeningDatagram);
    let no_socket = count(&|r| r.verdict == Verdict::RunningNoSocket);
    let unverifiable = count(&|r| r.verdict == Verdict::RunningUnverifiable);
    let refused = count(&|r| matches!(r.verdict, Verdict::RefusedCleanly(_)));
    let failures = count(&|r| r.verdict.is_failure());
    let leaks = count(&|r| r.port_leaked);

    out.push_str(&format!(
        "\n{total} registered · {} LISTENING ({tcp} accept a TCP connection, {udp} datagram) · \
         {no_socket} running-without-socket · {unverifiable} running-unverifiable-address · \
         {refused} refused cleanly · {failures} defects · {leaks} port leaks\n",
        tcp + udp
    ));
    out
}

/// Write straight to the process's stderr.
///
/// libtest captures `print!`/`eprint!` output and shows it only for a test that *finishes*
/// failing, so a test killed at the job's time limit leaves none of it in the log. A direct
/// write to the stream is not captured.
fn write_uncaptured(text: &str) {
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
    let _ = err.flush();
}

/// Where the server sweep is, shared with the watchdog thread.
struct SweepProgress {
    started: Instant,
    /// The protocol being started now, and since when.
    current: Option<(String, Instant)>,
    /// One line per protocol finished, in order.
    finished: Vec<String>,
}

impl Default for SweepProgress {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            current: None,
            finished: Vec::new(),
        }
    }
}

impl SweepProgress {
    fn begin(&mut self, name: &str) {
        self.current = Some((name.to_string(), Instant::now()));
    }

    fn finish(&mut self, line: String) {
        self.current = None;
        self.finished.push(line);
    }

    fn report(&self, why: &str) -> String {
        let mut out = format!(
            "\n=== protocol_startup_smoke_test watchdog: {why} ===\nsweep running for {:.1}s\n",
            self.started.elapsed().as_secs_f64()
        );
        match &self.current {
            Some((name, since)) => out.push_str(&format!(
                "IN PROGRESS: {name}, started {:.1}s ago\n",
                since.elapsed().as_secs_f64()
            )),
            None => out.push_str("no protocol in progress\n"),
        }
        out.push_str(&format!("finished so far ({}):\n", self.finished.len()));
        for line in &self.finished {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&thread_states());
        out
    }
}

/// What every thread of this process is blocked in, from the kernel's side.
///
/// A start that blocks a worker thread shows up here as a thread sitting in a syscall other
/// than the runtime's own parking (`epoll_wait`, `futex`).
fn thread_states() -> String {
    #[cfg(target_os = "linux")]
    {
        let mut out = String::from("threads (tid name state wchan | syscall number):\n");
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return out;
        };
        for task in tasks.flatten() {
            let dir = task.path();
            let read = |file: &str| {
                std::fs::read_to_string(dir.join(file))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "?".to_string())
            };
            let stat = read("stat");
            // `pid (comm) S ...`: the state letter follows the last `)`.
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .unwrap_or("?")
                .to_string();
            let syscall = read("syscall");
            let syscall = syscall.split_whitespace().next().unwrap_or("?");
            out.push_str(&format!(
                "  {} {} {} {} | {}\n",
                task.file_name().to_string_lossy(),
                read("comm"),
                state,
                read("wchan"),
                syscall
            ));
        }
        out
    }
    #[cfg(not(target_os = "linux"))]
    {
        String::from("(per-thread kernel state is read from /proc, so only on Linux)\n")
    }
}

/// An OS thread watching the sweep from outside the tokio runtime.
///
/// It reports, uncaptured, any protocol still starting `WATCHDOG_GRACE` after its own
/// `START_TIMEOUT` — the timer that should have ended it could not fire — and exits the process
/// with a failure if the sweep is still running `WATCHDOG_GRACE` past [`SWEEP_DEADLINE`], since
/// by then the sweep's own deadline check could not run either.
struct Watchdog {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(progress: Arc<std::sync::Mutex<SweepProgress>>) -> Self {
        use std::sync::atomic::Ordering;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("smoke-watchdog".to_string())
                .spawn(move || {
                    let mut reported: Option<String> = None;
                    while !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(250));
                        let Ok(progress) = progress.lock() else {
                            return;
                        };
                        if progress.started.elapsed() > SWEEP_DEADLINE + WATCHDOG_GRACE {
                            write_uncaptured(&progress.report(&format!(
                                "the sweep is {}s past its {}s deadline and cannot stop \
                                 itself; exiting",
                                WATCHDOG_GRACE.as_secs(),
                                SWEEP_DEADLINE.as_secs()
                            )));
                            std::process::exit(101);
                        }
                        if let Some((name, since)) = &progress.current {
                            if since.elapsed() > START_TIMEOUT + WATCHDOG_GRACE
                                && reported.as_deref() != Some(name.as_str())
                            {
                                write_uncaptured(&progress.report(&format!(
                                    "`{name}` has been starting for longer than its {}s \
                                     timeout, so that timeout cannot fire",
                                    START_TIMEOUT.as_secs()
                                )));
                                reported = Some(name.clone());
                            }
                        }
                    }
                })
                .expect("spawn the watchdog thread")
        };
        Self {
            stop,
            thread: Some(thread),
        }
    }

    fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_registered_server_protocol_starts_honestly() {
    let state = Arc::new(AppState::new());
    // Unreachable on purpose: nothing on this machine listens on port 1, so any LLM
    // call fails on connect instead of reaching a model or the network.
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;

    let registry = netget::protocol::server_registry::registry();
    let mut protocols = registry.all_protocols();
    protocols.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    let only: Option<Vec<String>> = std::env::var("NETGET_SMOKE_ONLY").ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });

    assert!(
        !protocols.is_empty(),
        "the server registry is empty — was this built with no protocol features?"
    );

    let selected: Vec<_> = protocols
        .iter()
        .filter(|(name, _)| {
            only.as_ref()
                .is_none_or(|filter| filter.contains(&name.to_lowercase()))
        })
        .collect();

    let progress = Arc::new(std::sync::Mutex::new(SweepProgress::default()));
    let watchdog = Watchdog::start(Arc::clone(&progress));

    let mut rows = Vec::new();
    for (index, (name, proto)) in selected.iter().enumerate() {
        if progress.lock().expect("progress").started.elapsed() > SWEEP_DEADLINE {
            let not_reached: Vec<&str> =
                selected[index..].iter().map(|(n, _)| n.as_str()).collect();
            watchdog.stop();
            panic!(
                "{}\nthe server sweep passed its {}s deadline after {} of {} protocols; not \
                 reached ({}): {}",
                render_report(&rows),
                SWEEP_DEADLINE.as_secs(),
                rows.len(),
                selected.len(),
                not_reached.len(),
                not_reached.join(", ")
            );
        }
        progress.lock().expect("progress").begin(name);
        let row = probe_protocol(&state, name, proto).await;
        let line = format!(
            "  {:<28} {:<14} {:>7}ms  {}",
            row.protocol,
            row.verdict.label(),
            row.ready_ms,
            row.verdict.detail()
        );
        progress.lock().expect("progress").finish(line.clone());
        // Stream as we go. The full table is only printed at the end, so without this a
        // protocol that wedges the sweep cannot be named from the output — and naming it
        // is most of the value. This line is captured unless `--nocapture`; the uncaptured
        // one below and the watchdog are what reach a CI log.
        println!("{line}");
        if row.verdict == Verdict::Hang || row.ready_ms >= SLOW_START_MS {
            write_uncaptured(&format!(
                "protocol_startup_smoke_test: slow start:\n{line}\n"
            ));
        }

        if row.verdict == Verdict::Hang {
            // Is the shared state still usable? If the hung start holds its lock, every
            // protocol after this one would wait on it and be reported as a hang of its own,
            // which is how one defect becomes an hour-long sweep. Name it and stop instead.
            //
            // A write, for a server that does not exist: tokio's RwLock queues a writer
            // behind any holder, reader or writer, so this fails if anything still holds it.
            let probe = tokio::time::timeout(
                STATE_PROBE_TIMEOUT,
                state.update_server_status(ServerId::new(u32::MAX), ServerStatus::Stopped),
            )
            .await;
            if probe.is_err() {
                rows.push(row);
                watchdog.stop();
                panic!(
                    "{}\n`{name}` hung on start, and {}s after its task was aborted the shared \
                     AppState still cannot be locked: the hung start is holding it. Every \
                     protocol after it would wait on that lock and time out, so the sweep \
                     stops here.",
                    render_report(&rows),
                    STATE_PROBE_TIMEOUT.as_secs()
                );
            }
        }
        rows.push(row);
    }
    watchdog.stop();

    let report = render_report(&rows);
    println!("{report}");
    if let Ok(path) = std::env::var("NETGET_SMOKE_REPORT") {
        let _ = std::fs::write(path, &report);
    }

    let defects: Vec<&Row> = rows
        .iter()
        .filter(|r| r.verdict.is_failure() || r.port_leaked)
        .collect();

    assert!(
        defects.is_empty(),
        "{report}\n{} protocol(s) failed the honesty check: {}",
        defects.len(),
        defects
            .iter()
            .map(|r| format!(
                "{} [{}{}] {}",
                r.protocol,
                r.verdict.label(),
                if r.port_leaked { "+PORT-LEAK" } else { "" },
                r.verdict.detail()
            ))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

/// A client has nothing to connect to here, so the only universal property worth
/// asserting is the one that matters most in practice: `connect()` against a closed
/// loopback port must come back **promptly and without unwinding**. Hanging and
/// panicking are the two failures; everything else is recorded and reported.
///
/// Deliberately *not* asserted: that `connect()` returns `Err`. About half the client
/// protocols return `Ok` here, and for most that is a legitimate design rather than a
/// lie — a datagram client (DNS, UDP, SNMP, NTP, syslog…) has no handshake to fail, and
/// several request/response clients build a lazily-connecting handle (`reqwest`, the
/// MongoDB driver) whose first real I/O happens later. `Client::connect` has no
/// documented contract that it must reach the peer, so failing the build on that would
/// be inventing one. The report prints the split so the ambiguity stays visible instead
/// of being either asserted away or silently passed.
///
/// Note the documented limitation this test cannot cover: a client's accept/read loop
/// `JoinHandle` is not stored by every protocol, so `remove_client()` does not always
/// stop the network loop. That is checked for the protocols that do register one in
/// `tests/client_stop_releases_socket_test.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_registered_client_protocol_refuses_a_closed_port_promptly() {
    use netget::state::client::ClientInstance;
    use netget::state::ClientId;

    /// Clients get less rope than servers: connecting to a closed loopback port is a
    /// single failed syscall, so anything past this is a retry loop or a hang.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

    let state = Arc::new(AppState::new());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;

    // A port nothing is on. Bind it, read the number, drop the listener: the OS will
    // not immediately hand it out again, so a connect there is refused.
    let closed_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        l.local_addr().expect("probe local_addr").port()
    };
    let remote = format!("127.0.0.1:{closed_port}");

    let registry = &netget::protocol::CLIENT_REGISTRY;
    let mut names = registry.list_protocols();
    names.sort_by_key(|n| n.to_lowercase());

    assert!(!names.is_empty(), "the client registry is empty");

    let mut hangs: Vec<String> = Vec::new();
    let mut panics: Vec<String> = Vec::new();
    let mut connected: Vec<String> = Vec::new();
    let mut refused = 0usize;
    let mut report =
        String::from("\n=== NetGet client protocol connect-refusal smoke test ===\n\n");

    let mut skipped: Vec<String> = Vec::new();

    for name in &names {
        if let Some((_, why)) = CLIENT_SKIPS.iter().find(|(n, _)| n == name) {
            report.push_str(&format!("{name:<26}       -    NOT RUN: {why}\n"));
            skipped.push(name.clone());
            continue;
        }
        let Some(client) = registry.get(name) else {
            continue;
        };

        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let drain = tokio::spawn(async move {
            let mut rx = status_rx;
            while rx.recv().await.is_some() {}
        });

        let instance = ClientInstance::new(
            ClientId::new(0),
            remote.clone(),
            name.clone(),
            "smoke test: connect to a closed port".to_string(),
        );
        let client_id = state.add_client(instance).await;

        let ctx = netget::protocol::ConnectContext::new(
            remote.clone(),
            state.get_llm_client().await.expect("llm client was set"),
            state.clone(),
            status_tx,
            client_id,
        );

        let started = Instant::now();
        let handle = tokio::spawn(async move { client.connect(ctx).await });
        let outcome = tokio::time::timeout(CONNECT_TIMEOUT, handle).await;
        let ms = started.elapsed().as_millis();

        let verdict = match outcome {
            Err(_) => {
                hangs.push(name.clone());
                "HANG".to_string()
            }
            Ok(Err(join_err)) if join_err.is_panic() => {
                panics.push(name.clone());
                "PANIC".to_string()
            }
            Ok(Err(_)) => "cancelled".to_string(),
            Ok(Ok(Err(e))) => {
                refused += 1;
                format!("refused: {}", one_line(&e.to_string()))
            }
            Ok(Ok(Ok(addr))) => {
                // Not a failure — see the doc comment. Recorded so the count is visible.
                connected.push(format!("{name} -> {addr}"));
                format!("returned Ok with no peer ({addr})")
            }
        };

        report.push_str(&format!("{name:<26} {ms:>7}ms  {verdict}\n"));

        state.remove_client(client_id).await;
        drain.abort();
    }

    report.push_str(&format!(
        "\n{} registered · {refused} refused cleanly · {} returned Ok with no peer \
         (not asserted — see the test's doc comment) · {} hung · {} panicked · \
         {} not run ({})\n",
        names.len(),
        connected.len(),
        hangs.len(),
        panics.len(),
        skipped.len(),
        if skipped.is_empty() {
            "none".to_string()
        } else {
            skipped.join(", ")
        }
    ));
    println!("{report}");
    if let Ok(path) = std::env::var("NETGET_SMOKE_CLIENT_REPORT") {
        let _ = std::fs::write(path, &report);
    }

    assert!(
        hangs.is_empty() && panics.is_empty(),
        "{report}\nhung: {hangs:?}\npanicked: {panics:?}"
    );
}

/// Set in the child process [`a_stopped_stdio_server_does_not_keep_the_process_alive`] runs.
#[cfg(unix)]
const STDIO_CHILD_ENV: &str = "NETGET_SMOKE_STDIO_CHILD";

/// Stopping a stdio server must leave nothing behind that the process waits for at exit.
///
/// The server reads the process's stdin, and a stdin read blocks and cannot be cancelled. It
/// used to read through `tokio::io::stdin()`, on tokio's blocking pool, and dropping a runtime
/// waits for every blocking-pool thread: so once a stdio server had been started and stopped on
/// a stdin that stayed open with nothing written, the runtime could never be dropped. The sweep
/// above starts and stops `stdio` like everything else, and whenever this binary's stdin was an
/// open pipe it finished its sweep, printed its report and then never returned.
///
/// The case needs a stdin of its own, so it runs in a child: this binary again, running
/// [`stdio_child_starts_and_stops_a_stdio_server`], with stdin a pipe this test holds open. The
/// child does not outlive this test even if this test is killed: the pipe's only writer is here,
/// so the child's read then sees end of file.
#[cfg(unix)]
#[test]
fn a_stopped_stdio_server_does_not_keep_the_process_alive() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    const CHILD_DEADLINE: Duration = Duration::from_secs(60);

    let mut child = Command::new(std::env::current_exe().expect("current_exe"))
        .args([
            "stdio_child_starts_and_stops_a_stdio_server",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(STDIO_CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    // One line for the server to read, so the child knows its read loop is running and the next
    // read is outstanding. Then the pipe stays open, with nothing more on it.
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin.write_all(b"hello\n").expect("write to the child");
    stdin.flush().expect("flush");

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break Some(status);
        }
        if started.elapsed() > CHILD_DEADLINE {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let mut output = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut output);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut output);
    }
    drop(stdin);

    let status = status.unwrap_or_else(|| {
        panic!(
            "the child had not exited after {}s, though it stops its stdio server at once: \
             something that server started is still waiting on stdin, and the runtime cannot \
             be dropped until it returns. Child output:\n{output}",
            CHILD_DEADLINE.as_secs()
        )
    });
    assert!(status.success(), "the child failed ({status}):\n{output}");
    assert!(
        output.contains("stdio child: runtime dropped"),
        "the child did not get as far as dropping its runtime:\n{output}"
    );
}

/// The child half of [`a_stopped_stdio_server_does_not_keep_the_process_alive`]. Does nothing
/// unless that test launched it.
#[cfg(unix)]
#[test]
fn stdio_child_starts_and_stops_a_stdio_server() {
    if std::env::var_os(STDIO_CHILD_ENV).is_none() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = Arc::new(AppState::new());
        state
            .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
            .await;
        let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let id = netget::cli::server_startup::start_server_from_action(
            &state,
            None,
            None,
            None,
            None,
            "stdio",
            false,
            None,
            "smoke test: start a stdio server and stop it".to_string(),
            None,
            None,
            None,
            None,
            Default::default(),
            status_tx,
        )
        .await
        .expect("start the stdio server");

        // The line the parent wrote reaches the model as an event, which fails (no model is
        // reachable) and says so on the status stream. By then the reader has gone back to
        // reading, and that read is the one nothing can cancel.
        tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = status_rx.recv().await {
                if line.contains("stdio_input_received") {
                    return;
                }
            }
            panic!("the status stream ended before the server read its stdin");
        })
        .await
        .expect("the stdio server never read the line on its stdin");

        state.remove_server(id).await;
    });
    // This is where it used to hang.
    drop(runtime);
    println!("stdio child: runtime dropped");
}
