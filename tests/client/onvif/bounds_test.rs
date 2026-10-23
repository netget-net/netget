//! NetGet's ONVIF client against a canned device written here: the bounds on what a reply may
//! cost (nesting and size), the follow-up depth bound, the clock offset carried into every
//! WS-Security Created, and XAddrs followed by path on the host the client was given. This is
//! not evidence of interoperability — `real_server_test` is — only of the client's own limits.
use netget::cli::management::ClientForm;
use netget::server::onvif::wire;
use netget::state::app_state::AppState;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const PASSWORD: &str = "canned-secret";

#[derive(Default)]
struct Seen {
    /// Operation → how many requests named it.
    ops: HashMap<String, usize>,
    paths: Vec<String>,
    /// Every signed request's Created, and whether the digest verified.
    tokens: Vec<(String, bool)>,
}

type Answer = Arc<dyn Fn(&str) -> String + Send + Sync>;

fn operation(body: &str) -> String {
    let rest = body
        .split_once("<env:Body>")
        .map(|(_, r)| r)
        .unwrap_or_default();
    let tag = rest.trim_start_matches('<');
    let name: String = tag
        .chars()
        .take_while(|c| !matches!(c, ' ' | '/' | '>'))
        .collect();
    name.rsplit(':').next().unwrap_or_default().to_string()
}

/// A device that answers each request with `answer(operation)` and records what it saw.
async fn canned(answer: Answer) -> (u16, Arc<Mutex<Seen>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let answer = answer.clone();
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head, body) = loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
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
                            break (head.to_string(), body.to_string());
                        }
                    }
                };
                let op = operation(&body);
                {
                    let mut s = record.lock().unwrap();
                    *s.ops.entry(op.clone()).or_default() += 1;
                    s.paths
                        .push(head.split(' ').nth(1).unwrap_or_default().to_string());
                    if let Ok(req) = wire::parse_request(body.as_bytes()) {
                        if let Some(t) = req.token {
                            let ok = wire::verify_token(
                                Some(&t),
                                "admin",
                                PASSWORD,
                                chrono::Utc::now() + chrono::Duration::hours(2),
                                chrono::Duration::seconds(60),
                            )
                            .is_ok();
                            s.tokens.push((t.created.unwrap_or_default(), ok));
                        }
                    }
                }
                let reply = answer(&op);
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                            reply.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

/// A device two hours ahead of us whose capabilities name a different host.
fn normal(op: &str) -> String {
    wire::envelope(&match op {
        "GetSystemDateAndTime" => {
            wire::system_date_and_time(chrono::Utc::now() + chrono::Duration::hours(2))
        }
        "GetCapabilities" => wire::capabilities("http://203.0.113.9:80", &["Device", "Media"]),
        "GetProfiles" => {
            wire::profiles(&json!({"profiles": [{"token": "p1", "width": 640, "height": 480}]}))
        }
        "GetScopes" => wire::scopes(&json!({"scopes": ["onvif://www.onvif.org/name/Canned"]})),
        _ => wire::fault(wire::FaultCode::Receiver, &["ActionNotSupported"], "no"),
    })
}

async fn connect(port: u16, chain: &str) -> (AppState, anyhow::Result<netget::state::ClientId>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "onvif".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Read the camera".into()),
        startup_params: Some(json!({"username": "admin", "password": PASSWORD})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}}),
        ]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await;
    (state, id)
}

const SILENT: &str = "print('{\"actions\": []}')";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replies_past_the_depth_or_size_bound_refuse_the_connection() {
    let deep = Arc::new(|op: &str| {
        if op == "GetCapabilities" {
            let n = wire::MAX_DEPTH + 8;
            wire::envelope(&format!(
                "<tds:GetCapabilitiesResponse>{}{}</tds:GetCapabilitiesResponse>",
                "<a>".repeat(n),
                "</a>".repeat(n)
            ))
        } else {
            normal(op)
        }
    });
    let (port, _) = canned(deep).await;
    let (_state, id) = connect(port, SILENT).await;
    let err = format!("{:#}", id.expect_err("a depth bomb was accepted"));
    assert!(err.contains("nested deeper"), "{err}");

    let big = Arc::new(|op: &str| {
        if op == "GetCapabilities" {
            let reply = normal(op);
            format!(
                "{reply}{}",
                " ".repeat(wire::MAX_RESPONSE + 1 - reply.len())
            )
        } else {
            normal(op)
        }
    });
    let (port, _) = canned(big).await;
    let (_state, id) = connect(port, SILENT).await;
    assert!(id.is_err(), "a reply past MAX_RESPONSE was accepted");

    // Exactly MAX_RESPONSE is still a reply.
    let exact = Arc::new(|op: &str| {
        let reply = normal(op);
        if op == "GetCapabilities" {
            format!("{reply}{}", " ".repeat(wire::MAX_RESPONSE - reply.len()))
        } else {
            reply
        }
    });
    let (port, _) = canned(exact).await;
    let (_state, id) = connect(port, SILENT).await;
    id.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chains_stop_at_the_depth_bound_and_requests_carry_the_device_clock() {
    // Profiles on connect, then scopes in answer to every response, forever.
    let chain = r#"import json,sys
t=json.load(sys.stdin)['event_type_id']
a=[{'type':'onvif_get_profiles'}] if t=='onvif_connected' else [{'type':'onvif_get_scopes'}]
print(json.dumps({'actions':a}))"#;
    let (port, seen) = canned(Arc::new(normal)).await;
    let (_state, id) = connect(port, chain).await;
    id.unwrap();
    // connected (depth 0) -> GetProfiles (1) -> GetScopes (2) ... GetScopes (MAX), whose answer
    // is not asked about.
    let want = (netget::client::onvif::MAX_FOLLOWUP_DEPTH - 1) as usize;
    let count = || {
        seen.lock()
            .unwrap()
            .ops
            .get("GetScopes")
            .copied()
            .unwrap_or(0)
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        while count() < want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the chain never reached the bound");
    // And it stays there.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(count(), want);
    }
    let s = seen.lock().unwrap();
    assert_eq!(s.ops.get("GetProfiles"), Some(&1));
    // The media service was reached by its path on the host the client was given, not on the
    // host the capabilities named.
    assert!(
        s.paths.contains(&wire::MEDIA_PATH.to_string()),
        "{:?}",
        s.paths
    );
    // GetSystemDateAndTime went anonymously; every other request (GetCapabilities, GetServices,
    // GetProfiles and the scopes) was signed with the device's clock (two hours ahead) and
    // verifies.
    assert_eq!(s.ops.get("GetSystemDateAndTime"), Some(&1));
    assert_eq!(s.ops.get("GetServices"), Some(&1));
    assert_eq!(s.tokens.len(), 2 + 1 + want, "{:?}", s.tokens);
    for (created, ok) in &s.tokens {
        assert!(
            ok,
            "a token did not verify against the device clock: {created}"
        );
    }
}
