//! The bounds on Basic Notification, the one place the ONVIF device connects to an address a
//! client picked — from raw HTTP and a consumer written here (not evidence of interoperability:
//! `notify_test` is): the consumer allowlist and the address forms refused before the model is
//! asked, the push-subscription cap, the per-attempt timeout and the retry bound, redirects not
//! followed, the per-subscription queue keeping the newest, https only when configured, and a
//! failing model leaving no subscription. No LLM calls.
use super::bounds_test::{address, call, describing_only, device, subcodes};
use super::real_client_test::{events, policy, start_logged, StatusLog};
use super::services_test::raise;
use netget::server::onvif::{notify, wire};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How the test consumer answers.
#[derive(Clone)]
enum Mode {
    Ok,
    /// Read the request and never answer.
    Silent,
    /// Answer 307 to this location.
    Redirect(String),
    /// Hold the first request until the gate opens, then answer everything 200.
    Gated(Arc<tokio::sync::Notify>),
}

/// A consumer on a loopback port: every request body it read, in order.
struct Consumer {
    port: u16,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl Consumer {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/consumer", self.port)
    }
    fn count(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }
    /// Every NotificationMessage's `Value="…"` of an item named `name`, in arrival order.
    fn values(&self, name: &str) -> Vec<String> {
        let needle = format!("Name=\"{name}\" Value=\"");
        self.bodies
            .lock()
            .unwrap()
            .iter()
            .flat_map(|b| {
                b.split(&needle)
                    .skip(1)
                    .filter_map(|s| s.split('"').next().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if body.len() >= len {
                return Some(body.to_string());
            }
        }
    }
}

async fn consumer(mode: Mode) -> Consumer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies: Arc<Mutex<Vec<String>>> = Default::default();
    let record = bodies.clone();
    let held: Arc<Mutex<Vec<tokio::net::TcpStream>>> = Default::default();
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (record, mode, held, first) =
                (record.clone(), mode.clone(), held.clone(), first.clone());
            tokio::spawn(async move {
                while let Some(body) = read_request(&mut stream).await {
                    record.lock().unwrap().push(body);
                    let answer = match &mode {
                        Mode::Ok => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                        Mode::Silent => {
                            held.lock().unwrap().push(stream);
                            return;
                        }
                        Mode::Redirect(to) => format!(
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
                        ),
                        Mode::Gated(gate) => {
                            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                                gate.notified().await;
                            }
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
                        }
                    };
                    if stream.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Consumer { port, bodies }
}

async fn subscribe(port: u16, consumer: &str) -> (u16, String) {
    call(
        port,
        wire::EVENTS_PATH,
        &format!("<wsnt:Subscribe><wsnt:ConsumerReference><wsa:Address>{}</wsa:Address></wsnt:ConsumerReference><wsnt:InitialTerminationTime>PT120S</wsnt:InitialTerminationTime></wsnt:Subscribe>", wire::esc(consumer)),
    )
    .await
}

async fn wait_until<F: Fn() -> bool>(what: &str, secs: u64, f: F) {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} within {secs} s"));
}

/// The first access-log entry of `kind`, waited for.
async fn first(state: &AppState, id: ServerId, kind: &str, secs: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if let Some(e) = events(state, id, kind).await.into_iter().next() {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} within {secs} s"))
}

fn logged(log: &StatusLog, needle: &str) -> bool {
    log.lock().unwrap().iter().any(|l| l.contains(needle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumers_outside_the_allowlist_are_refused_before_the_model() {
    let (state, id, port, _) = start_logged(policy(), json!({})).await;
    let cases = [
        ("http://192.0.2.1:9/c", "not_allowlisted"),
        ("https://127.0.0.1:9/c", "https_refused"),
        ("http://localhost:9/c", "host_not_an_ip_address"),
        ("http://user@127.0.0.1:9/c", "userinfo"),
        ("ftp://127.0.0.1/c", "not_http"),
        ("http://0.0.0.0:9/c", "not_allowlisted"),
        ("http://[::ffff:192.0.2.1]:9/c", "not_allowlisted"),
        ("not a url", "malformed_address"),
        ("", "malformed_address"),
    ];
    for (consumer, _) in cases {
        let (status, body) = subscribe(port, consumer).await;
        assert_eq!(status, 400, "{consumer}: {body}");
        assert_eq!(subcodes(&body), vec!["InvalidArgVal"], "{consumer}: {body}");
        assert!(
            body.contains("SubscribeCreationFailedFault"),
            "{consumer}: {body}"
        );
    }
    let long = format!(
        "http://127.0.0.1:9/{}",
        "x".repeat(notify::MAX_CONSUMER_URL)
    );
    let (status, _) = subscribe(port, &long).await;
    assert_eq!(status, 400);
    let reasons: Vec<Value> = events(&state, id, "onvif_notify_refused")
        .await
        .iter()
        .map(|e| e["reason"].clone())
        .collect();
    let mut want: Vec<Value> = cases.iter().map(|(_, r)| json!(r)).collect();
    want.push(json!("malformed_address"));
    assert_eq!(reasons, want);
    // Nothing was asked and nothing exists to deliver.
    assert!(events(&state, id, "onvif_create_subscription")
        .await
        .is_empty());
    assert_eq!(device(&state, id).await.push_subscriptions(), 0);

    // Loopback, also written as IPv4-mapped IPv6, is what the default allows.
    let c = consumer(Mode::Ok).await;
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = subscribe(
        port,
        &format!("http://[::ffff:127.0.0.1]:{}/consumer", c.port),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(device(&state, id).await.push_subscriptions(), 2);

    // `subscriber` is the subscribing client's own address and nothing else; a CIDR is exact.
    let (state, id, port, _) =
        start_logged(policy(), json!({"notify_consumers": ["subscriber"]})).await;
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = subscribe(port, "http://127.0.0.2:9/c").await;
    assert_eq!(status, 400);
    let (state2, id2, port2, _) =
        start_logged(policy(), json!({"notify_consumers": ["127.0.0.1/32"]})).await;
    let (status, _) = subscribe(port2, "http://[::1]:9/c").await;
    assert_eq!(status, 400);
    let (status, _) = subscribe(port2, "http://127.0.0.2:9/c").await;
    assert_eq!(status, 400);
    let (status, body) = subscribe(port2, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(device(&state, id).await.push_subscriptions(), 1);
    assert_eq!(device(&state2, id2).await.push_subscriptions(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_subscriptions_are_bounded_apart_from_pull_points() {
    let (state, id, port, log) = start_logged(policy(), json!({})).await;
    let c = consumer(Mode::Ok).await;
    let mut paths = Vec::new();
    for _ in 0..notify::MAX_PUSH_SUBSCRIPTIONS {
        let (status, body) = subscribe(port, &c.url()).await;
        assert_eq!(status, 200, "{body}");
        paths.push(address(&body));
    }
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["Action"], "{body}");
    assert!(body.contains("SubscribeCreationFailedFault"), "{body}");
    assert_eq!(
        device(&state, id).await.push_subscriptions(),
        notify::MAX_PUSH_SUBSCRIPTIONS
    );
    // A pull point is counted on its own.
    let (status, body) = call(
        port,
        wire::EVENTS_PATH,
        "<tev:CreatePullPointSubscription/>",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // A push subscription is not pulled from.
    let (status, body) = call(
        port,
        &paths[0],
        "<tev:PullMessages><tev:Timeout>PT1S</tev:Timeout><tev:MessageLimit>1</tev:MessageLimit></tev:PullMessages>",
    )
    .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(subcodes(&body), vec!["ActionNotSupported"], "{body}");
    // Ending one ends its delivery task and makes room.
    let id0 = paths[0].rsplit('/').next().unwrap().to_string();
    let (status, body) = call(port, &paths[0], "<wsnt:Unsubscribe/>").await;
    assert_eq!(status, 200, "{body}");
    wait_until("the delivery task ending", 30, || {
        logged(&log, &format!("subscription {id0} to {} ended", c.url()))
    })
    .await;
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    // Every live subscription delivered what the model raised in its answer.
    wait_until("every subscription's first Notify", 30, || {
        c.count() > notify::MAX_PUSH_SUBSCRIPTIONS
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_consumer_that_never_answers_costs_bounded_attempts_then_the_batch_is_dropped() {
    let (state, id, port, log) = start_logged(
        policy(),
        json!({"notify_timeout_secs": 1, "notify_retries": 2}),
    )
    .await;
    let c = consumer(Mode::Silent).await;
    let started = Instant::now();
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    // The model's answer raised one notification: three attempts of a second each, 250 ms and
    // 500 ms apart, then dropped.
    let dropped = first(&state, id, "onvif_notify_dropped", 30).await;
    let took = started.elapsed();
    assert_eq!(dropped["attempts"], 3, "{dropped}");
    assert_eq!(dropped["messages"], 1, "{dropped}");
    assert!(
        dropped["error"]
            .as_str()
            .is_some_and(|e| e.contains("no answer within 1 s")),
        "{dropped}"
    );
    assert!(
        took >= Duration::from_millis(3600) && took < Duration::from_secs(15),
        "{took:?}"
    );
    assert_eq!(c.count(), 3);
    assert!(logged(&log, "decision=notify_dropped"));
    assert!(events(&state, id, "onvif_notify_delivered")
        .await
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redirect_is_not_followed() {
    let (state, id, port, _) = start_logged(policy(), json!({"notify_retries": 0})).await;
    let elsewhere = consumer(Mode::Ok).await;
    let c = consumer(Mode::Redirect(elsewhere.url())).await;
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    let dropped = first(&state, id, "onvif_notify_dropped", 30).await;
    assert_eq!(dropped["attempts"], 1, "{dropped}");
    assert!(
        dropped["error"]
            .as_str()
            .is_some_and(|e| e.contains("HTTP 307 (redirects are not followed)")),
        "{dropped}"
    );
    assert_eq!(c.count(), 1);
    assert_eq!(elsewhere.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_queue_keeps_the_newest_and_says_so() {
    let (state, id, port, log) = start_logged(policy(), json!({})).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    let c = consumer(Mode::Gated(gate.clone())).await;
    let (status, body) = subscribe(port, &c.url()).await;
    assert_eq!(status, 200, "{body}");
    // The first Notify (the model's motion alarm) is held at the consumer…
    wait_until("the first Notify", 30, || c.count() == 1).await;
    // …while more than the queue holds is raised.
    let over = 6;
    for i in 0..notify::MAX_PUSH_QUEUED + over {
        raise(
            &state,
            id,
            json!({"type": "onvif_raise_event", "topic": "tns1:Device/Trigger/DigitalInput",
                   "source": {"InputToken": format!("q{i}")}, "data": {"LogicalState": true}}),
        )
        .await;
    }
    gate.notify_one();
    wait_until("the queue delivered", 30, || {
        c.values("InputToken").len() >= notify::MAX_PUSH_QUEUED
    })
    .await;
    let got = c.values("InputToken");
    let want: Vec<String> = (over..notify::MAX_PUSH_QUEUED + over)
        .map(|i| format!("q{i}"))
        .collect();
    assert_eq!(got, want);
    for b in c.bodies.lock().unwrap().iter() {
        assert!(
            b.matches("<wsnt:NotificationMessage>").count() <= notify::MAX_NOTIFY_BATCH,
            "{b}"
        );
    }
    assert!(logged(
        &log,
        &format!(
            "{over} notification(s) dropped, more than {} waiting decision=notify_queue_overflow",
            notify::MAX_PUSH_QUEUED
        )
    ));
    assert!(events(&state, id, "onvif_notify_dropped").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_consumers_only_when_configured_and_a_failing_model_subscribes_nothing() {
    let (state, id, port, _) = start_logged(policy(), json!({"notify_allow_https": true})).await;
    let c = consumer(Mode::Silent).await;
    let (status, body) = subscribe(port, &format!("https://127.0.0.1:{}/consumer", c.port)).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = call(port, &address(&body), "<wsnt:Unsubscribe/>").await;
    assert_eq!(status, 200);
    assert_eq!(device(&state, id).await.push_subscriptions(), 0);

    // A model that cannot answer the subscription: refused, nothing kept, nothing sent.
    let (state, id, port, _) = start_logged(describing_only(), json!({})).await;
    let quiet = consumer(Mode::Ok).await;
    let (status, body) = subscribe(port, &quiet.url()).await;
    assert!(status == 500 || status == 503, "{status} {body}");
    assert_eq!(device(&state, id).await.push_subscriptions(), 0);
    raise(
        &state,
        id,
        json!({"type": "onvif_raise_event", "topic": "tns1:VideoSource/MotionAlarm",
               "source": {"Source": "lobby_cam"}, "data": {"State": true}}),
    )
    .await;
    assert_eq!(quiet.count(), 0);
}
