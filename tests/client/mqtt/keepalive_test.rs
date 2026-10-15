//! NetGet's MQTT client keeps its connection alive while a model turn is parked.
//!
//! The peer is the real Eclipse `mosquitto` broker, which enforces MQTT 3.1.1 §3.1.2.10: a
//! client that sends nothing for 1.5 × its keep-alive is disconnected. The client connects with
//! a 2-second keep-alive, and its `mqtt_connected` turn is parked on a `manual` rule for ten
//! seconds — more than three times the 3-second window. Then the test answers the turn with a
//! publish and checks, from the broker's side, that the publish arrived (`mosquitto_sub` is
//! subscribed and waiting) and, from NetGet's side, that the client never left `Connected`.
//!
//! That only holds if PINGREQ keeps going out while the turn waits. rumqttc writes PINGREQ only
//! while its `EventLoop::poll` is being awaited, so a client that ran the model turn inside the
//! loop that polls went silent for the whole turn and the broker dropped it; the answered
//! publish then went nowhere.
//!
//! Zero LLM calls: the only event is answered by the manual rule, and the client's model URL is
//! unreachable.
//!
//! The test **fails** when `mosquitto` or `mosquitto_sub` is absent rather than skipping: a
//! skip is a silent pass wherever the suite runs without them.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mqtt --test client -- mqtt::keepalive --test-threads=100


use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::intercepts::InterceptOwner;
use netget::state::{ClientId, ClientStatus};
use tokio::sync::mpsc;

const MOSQUITTO: &str = "/opt/homebrew/sbin/mosquitto";
const MOSQUITTO_SUB: &str = "mosquitto_sub";

/// The keep-alive the client declares, in seconds. The broker's limit is 1.5 × this.
const KEEP_ALIVE_SECS: u64 = 2;
/// How long the connected turn stays parked: over three broker windows.
const PARKED_FOR: Duration = Duration::from_secs(10);

/// The real broker, killed on every exit path (Drop runs while unwinding a failed assert).
struct Mosquitto {
    child: Child,
    port: u16,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Mosquitto {
    fn start() -> Self {
        let binary = if std::path::Path::new(MOSQUITTO).exists() {
            MOSQUITTO
        } else {
            "mosquitto"
        };
        let dir = tempfile::tempdir().expect("tempdir");
        for _attempt in 0..5 {
            let port = {
                let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
                probe.local_addr().unwrap().port()
            };
            let conf = dir.path().join("mosquitto.conf");
            let log = dir.path().join("mosquitto.log");
            std::fs::write(
                &conf,
                format!(
                    "listener {port} 127.0.0.1\nallow_anonymous true\n\
                     log_dest file {}\nlog_type all\n",
                    log.display()
                ),
            )
            .unwrap();
            let mut child = Command::new(binary)
                .arg("-c")
                .arg(&conf)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|e| {
                    panic!(
                        "could not spawn the Eclipse `mosquitto` broker ({binary}): {e}. This \
                         test does not skip - a skip would pass silently wherever the broker is \
                         missing. Install it with `brew install mosquitto` or \
                         `apt-get install mosquitto mosquitto-clients`."
                    )
                });
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Self {
                        child,
                        port,
                        log,
                        _dir: dir,
                    };
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break; // the port was taken between probe and bind; try another
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("mosquitto never started listening on a loopback port");
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Mosquitto {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_status(state: &AppState, id: ClientId, want: fn(&ClientStatus) -> bool) {
    for _ in 0..500 {
        if let Some(status) = state.get_client(id).await.map(|c| c.status) {
            if want(&status) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "client #{} never reached the expected status; it is {:?}",
        id.as_u32(),
        state.get_client(id).await.map(|c| c.status)
    );
}

#[tokio::test]
async fn mqtt_client_survives_a_parked_turn_longer_than_its_keep_alive() {
    let broker = Mosquitto::start();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "mqtt".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", broker.port)),
        instruction: Some("keepalive test client".to_string()),
        startup_params: Some(serde_json::json!({
            "client_id": "netget-keepalive-probe",
            "keep_alive": KEEP_ALIVE_SECS,
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "mqtt_connected",
            "handler": { "type": "manual", "timeout_secs": 120 }
        })]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create mqtt client");

    // The subscriber that proves, from the broker's side, that the answered publish arrived.
    // Started before the turn is answered; `-C 1` exits after one message, `-W` bounds it.
    let subscriber = Command::new(MOSQUITTO_SUB)
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &broker.port.to_string(),
            "-t",
            "keepalive/marker",
            "-C",
            "1",
            "-W",
            "20",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "could not spawn `mosquitto_sub`: {e}. It ships with the broker (`brew install \
                 mosquitto`, or `apt-get install mosquitto-clients`); this test does not skip."
            )
        });

    // The connected turn parks for a human.
    let intercept = {
        let mut found = None;
        for _ in 0..500 {
            found = state.list_intercepts().await.into_iter().find(|v| {
                v.owner == InterceptOwner::Client(client_id) && v.event_type == "mqtt_connected"
            });
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("the mqtt_connected turn never parked")
    };
    wait_for_status(&state, client_id, |s| matches!(s, ClientStatus::Connected)).await;

    // The parked interval is the scenario itself, not a wait for a condition: a human who takes
    // ten seconds to answer. The broker's 3-second window passes three times over.
    tokio::time::sleep(PARKED_FOR).await;

    let status = state.get_client(client_id).await.map(|c| c.status);
    assert!(
        matches!(status, Some(ClientStatus::Connected)),
        "the client must still be connected after a {}s parked turn with a {}s keep-alive; \
         status is {status:?}. Broker log:\n{}",
        PARKED_FOR.as_secs(),
        KEEP_ALIVE_SECS,
        broker.log()
    );

    // The broker's own account, which is the peer-side verdict: it heard PINGREQ during the
    // park and never applied its keep-alive timeout.
    let log = broker.log();
    assert!(
        !log.lines()
            .any(|l| l.contains("netget-keepalive-probe") && l.contains("exceeded timeout")),
        "the broker timed the client out while its turn was parked. Broker log:\n{log}"
    );
    assert!(
        log.contains("Received PINGREQ from netget-keepalive-probe"),
        "the broker must have seen PINGREQ from the client while its turn was parked. Broker \
         log:\n{log}"
    );

    state
        .resolve_intercept(
            intercept.id,
            vec![serde_json::json!({
                "type": "publish",
                "topic": "keepalive/marker",
                "payload": "still-here"
            })],
        )
        .await
        .expect("answer the parked mqtt_connected turn");

    let output = tokio::task::spawn_blocking(move || subscriber.wait_with_output())
        .await
        .unwrap()
        .expect("mosquitto_sub output");
    let received = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && received.trim() == "still-here",
        "mosquitto_sub must receive the publish the answered turn made; exit {:?}, stdout \
         {received:?}, stderr {:?}. Client status {:?}. Broker log:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        state.get_client(client_id).await.map(|c| c.status),
        broker.log()
    );

    assert!(
        matches!(
            state.get_client(client_id).await.map(|c| c.status),
            Some(ClientStatus::Connected)
        ),
        "the client must still be connected after answering"
    );
}
