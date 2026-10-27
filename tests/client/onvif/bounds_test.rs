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
    /// Every request body, in order.
    bodies: Vec<String>,
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
                    s.bodies.push(body.clone());
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
        "GetCapabilities" => {
            wire::capabilities("http://203.0.113.9:80", &["Device", "Media"], false)
        }
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

/// A device with Events, Recording, Search and Replay, two hours ahead of us, whose
/// subscriptions and searches are canned answers.
fn profile_g(op: &str) -> String {
    wire::envelope(&match op {
        "GetSystemDateAndTime" => {
            wire::system_date_and_time(chrono::Utc::now() + chrono::Duration::hours(2))
        }
        "GetCapabilities" => {
            wire::capabilities("http://203.0.113.9:80", &["Device", "Events", "Media"], true)
        }
        "Subscribe" => "<wsnt:SubscribeResponse><wsnt:SubscriptionReference><wsa:Address>http://203.0.113.9/push/1</wsa:Address></wsnt:SubscriptionReference><wsnt:CurrentTime>2026-10-25T10:00:00Z</wsnt:CurrentTime><wsnt:TerminationTime>2026-10-25T10:02:00Z</wsnt:TerminationTime></wsnt:SubscribeResponse>".into(),
        "Renew" => "<wsnt:RenewResponse><wsnt:TerminationTime>2026-10-25T10:05:00Z</wsnt:TerminationTime><wsnt:CurrentTime>2026-10-25T10:00:00Z</wsnt:CurrentTime></wsnt:RenewResponse>".into(),
        "Unsubscribe" => "<wsnt:UnsubscribeResponse/>".into(),
        "GetRecordings" => "<trc:GetRecordingsResponse><trc:RecordingItem><tt:RecordingToken>rec_canned</tt:RecordingToken><tt:Configuration><tt:Source><tt:SourceId>cam</tt:SourceId><tt:Name>Canned</tt:Name><tt:Location/><tt:Description/><tt:Address/></tt:Source><tt:Content>All of it</tt:Content><tt:MaximumRetentionTime>PT0S</tt:MaximumRetentionTime></tt:Configuration><tt:Tracks><tt:Track><tt:TrackToken>V1</tt:TrackToken><tt:Configuration><tt:TrackType>Video</tt:TrackType><tt:Description/></tt:Configuration></tt:Track></tt:Tracks></trc:RecordingItem></trc:GetRecordingsResponse>".into(),
        "GetRecordingSummary" => "<tse:GetRecordingSummaryResponse><tse:Summary><tt:DataFrom>2026-10-24T00:00:00Z</tt:DataFrom><tt:DataUntil>2026-10-25T00:00:00Z</tt:DataUntil><tt:NumberRecordings>1</tt:NumberRecordings></tse:Summary></tse:GetRecordingSummaryResponse>".into(),
        "FindEvents" => "<tse:FindEventsResponse><tse:SearchToken>s1</tse:SearchToken></tse:FindEventsResponse>".into(),
        "GetEventSearchResults" => "<tse:GetEventSearchResultsResponse><tse:ResultList><tt:SearchState>Completed</tt:SearchState><tt:Result><tt:RecordingToken>rec_canned</tt:RecordingToken><tt:TrackToken>V1</tt:TrackToken><tt:Time>2026-10-24T08:15:00Z</tt:Time><tt:Event><wsnt:Topic Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet\">tns1:VideoSource/MotionAlarm</wsnt:Topic><wsnt:Message><tt:Message UtcTime=\"2026-10-24T08:15:00Z\" PropertyOperation=\"Changed\"><tt:Source><tt:SimpleItem Name=\"Source\" Value=\"cam\"/></tt:Source><tt:Data><tt:SimpleItem Name=\"State\" Value=\"true\"/></tt:Data></tt:Message></wsnt:Message></tt:Event><tt:StartStateEvent>false</tt:StartStateEvent></tt:Result></tse:ResultList></tse:GetEventSearchResultsResponse>".into(),
        "EndSearch" => "<tse:EndSearchResponse><tse:Endpoint>2026-10-25T00:00:00Z</tse:Endpoint></tse:EndSearchResponse>".into(),
        "GetReplayUri" => "<trp:GetReplayUriResponse><trp:Uri>rtsp://203.0.113.9/replay/rec_canned</trp:Uri></trp:GetReplayUriResponse>".into(),
        _ => return normal(op),
    })
}

/// The access-log entries of one kind the client recorded.
async fn logged(
    state: &AppState,
    id: netget::state::ClientId,
    kind: &str,
) -> Vec<serde_json::Value> {
    state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Client(id.as_u32())),
            None,
        )
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

async fn wait_for<F: Fn() -> bool>(what: &str, f: F) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} never happened"));
}

async fn post(url: &str, body: String) -> u16 {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(url)
        .header("Content-Type", "application/soap+xml")
        .body(body)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(0)
}

/// A Notify as a device writes it, with prefixes of its own.
fn notify(state: &str) -> String {
    format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b2=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:x=\"http://www.onvif.org/ver10/schema\"><s:Body><b2:Notify><b2:NotificationMessage><b2:SubscriptionReference><a:Address>http://203.0.113.9/push/1</a:Address></b2:SubscriptionReference><b2:Topic Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet\">tns1:VideoSource/MotionAlarm</b2:Topic><b2:Message><x:Message UtcTime=\"2026-10-25T10:00:01Z\" PropertyOperation=\"Changed\"><x:Source><x:SimpleItem Name=\"Source\" Value=\"cam\"/></x:Source><x:Data><x:SimpleItem Name=\"State\" Value=\"{state}\"/></x:Data></x:Message></b2:Message></b2:NotificationMessage></b2:Notify></s:Body></s:Envelope>")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notify_reaches_the_model_through_a_bounded_loopback_consumer() {
    // Subscribe on connect; a motion alarm arriving by Notify makes the model read the recordings.
    let chain = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; a=[]
if t=='onvif_connected': a=[{'type':'onvif_subscribe','termination_secs':120,'topic_filter':'tns1:VideoSource//.'}]
elif t=='onvif_notification' and e['topic']=='tns1:VideoSource/MotionAlarm' and e['data'].get('State')=='true': a=[{'type':'onvif_get_recordings'}]
print(json.dumps({'actions':a}))"#;
    let (port, seen) = canned(Arc::new(profile_g)).await;
    let (state, id) = connect(port, chain).await;
    let id = id.unwrap();
    wait_for("the Subscribe", || {
        seen.lock().unwrap().ops.contains_key("Subscribe")
    })
    .await;
    let body = {
        let s = seen.lock().unwrap();
        s.bodies
            .iter()
            .find(|b| operation(b) == "Subscribe")
            .cloned()
            .unwrap()
    };
    let consumer = body
        .split("<wsa:Address>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .unwrap()
        .to_string();
    // The consumer is the client's own, on loopback, at a path nobody can guess.
    assert!(consumer.starts_with("http://127.0.0.1:"), "{consumer}");
    let path = consumer.splitn(4, '/').nth(3).unwrap_or_default();
    assert!(
        path.starts_with("netget/onvif/notify/") && path.len() == "netget/onvif/notify/".len() + 32,
        "{consumer}"
    );
    assert!(body.contains("tns1:VideoSource//."), "{body}");
    let base = consumer.trim_end_matches(path).to_string();

    // A Notify at the consumer becomes an onvif_notification the model acts on.
    assert_eq!(post(&consumer, notify("true")).await, 200);
    wait_for("the model's GetRecordings", || {
        seen.lock().unwrap().ops.contains_key("GetRecordings")
    })
    .await;
    let got = logged(&state, id, "onvif_notification").await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["topic"], "tns1:VideoSource/MotionAlarm");
    assert_eq!(got[0]["data"], json!({"State": "true"}));
    assert_eq!(got[0]["source"], json!({"Source": "cam"}));
    assert_eq!(got[0]["subscription"], "http://203.0.113.9/push/1");

    // Anything else is refused and reaches nobody.
    assert_eq!(
        post(&format!("{base}somewhere/else"), notify("true")).await,
        404
    );
    let get = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(&consumer)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status().as_u16(), 405);
    let pad = " ".repeat(wire::MAX_REQUEST + 1);
    assert_eq!(
        post(&consumer, format!("{}{pad}", notify("false"))).await,
        413
    );
    assert_eq!(
        post(&consumer, wire::request_envelope(None, "<tds:GetScopes/>")).await,
        400
    );
    assert_eq!(post(&consumer, "<not xml".into()).await, 400);
    let deep = wire::MAX_DEPTH + 4;
    let bomb = format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>{}{}</s:Body></s:Envelope>",
        "<a>".repeat(deep),
        "</a>".repeat(deep)
    );
    assert_eq!(post(&consumer, bomb).await, 400);
    assert_eq!(logged(&state, id, "onvif_notification").await.len(), 1);

    // At most MAX_CONNECTIONS device connections at once: the next is answered 503 and closed.
    let addr = consumer
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let mut held = Vec::new();
    for _ in 0..netget::client::onvif::consumer::MAX_CONNECTIONS {
        held.push(tokio::net::TcpStream::connect(&addr).await.unwrap());
    }
    let mut extra = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(30), extra.read_to_string(&mut answer))
        .await
        .expect("the connection over the cap was not answered")
        .unwrap();
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    drop(held);

    // Renew and Unsubscribe go to the subscription's path on the device the client was given.
    let send = |action: serde_json::Value| {
        let state = state.clone();
        async move {
            match state
                .send_to_client(id, action, Duration::from_secs(30))
                .await
            {
                Ok(netget::state::client_handles::ClientSendOutcome::Executed { detail }) => {
                    serde_json::from_str::<serde_json::Value>(&detail).unwrap()
                }
                other => panic!("{other:?}"),
            }
        }
    };
    let r = send(json!({"type": "onvif_renew_push_subscription", "termination_secs": 300})).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(
        r["result"]["termination_time"], "2026-10-25T10:05:00Z",
        "{r}"
    );
    let r = send(json!({"type": "onvif_unsubscribe_push"})).await;
    assert_eq!(r["ok"], true, "{r}");
    let r = send(json!({"type": "onvif_renew_push_subscription"})).await;
    assert_eq!(r["ok"], false, "{r}");
    assert!(
        r["error"]
            .as_str()
            .is_some_and(|e| e.contains("no Basic Notification subscription")),
        "{r}"
    );
    let s = seen.lock().unwrap();
    assert_eq!(
        s.paths.iter().filter(|p| *p == "/push/1").count(),
        2,
        "{:?}",
        s.paths
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recording_search_and_replay_requests_carry_the_model_values_and_answers_are_read() {
    let chain = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; a=[]
if t=='onvif_connected':
  a=[{'type':'onvif_get_recordings'},{'type':'onvif_get_recording_summary'},
     {'type':'onvif_find_events','start':'2026-10-24T00:00:00Z','end':'2026-10-25T00:00:00Z','recording_tokens':['rec_canned'],'topic_filter':'tns1:VideoSource/MotionAlarm','max_matches':5,'keep_alive_secs':30},
     {'type':'onvif_get_replay_uri','recording_token':'rec_canned'}]
elif e.get('operation')=='FindEvents' and e['ok']:
  a=[{'type':'onvif_get_event_search_results','search_token':e['result']['search_token'],'max_results':10}]
elif e.get('operation')=='GetEventSearchResults' and e['ok']:
  a=[{'type':'onvif_end_search','search_token':'s1'}]
print(json.dumps({'actions':a}))"#;
    let (port, seen) = canned(Arc::new(profile_g)).await;
    let (state, id) = connect(port, chain).await;
    let id = id.unwrap();
    wait_for("EndSearch", || {
        seen.lock().unwrap().ops.contains_key("EndSearch")
    })
    .await;
    let responses = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let r = logged(&state, id, "onvif_response").await;
            if r.iter().any(|r| r["operation"] == "EndSearch") {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the EndSearch answer never reached the client's log");
    let by = |op: &str| {
        responses
            .iter()
            .find(|r| r["operation"] == op)
            .cloned()
            .unwrap_or_else(|| panic!("no {op} in {responses:?}"))
    };
    assert_eq!(
        by("GetRecordings")["result"]["recordings"][0]["token"],
        "rec_canned"
    );
    assert_eq!(
        by("GetRecordings")["result"]["recordings"][0]["tracks"][0]["type"],
        "Video"
    );
    assert_eq!(by("GetRecordingSummary")["result"]["number_recordings"], 1);
    assert_eq!(by("FindEvents")["result"]["search_token"], "s1");
    let results = by("GetEventSearchResults")["result"].clone();
    assert_eq!(results["search_state"], "Completed", "{results}");
    assert_eq!(
        results["results"][0]["topic"], "tns1:VideoSource/MotionAlarm",
        "{results}"
    );
    assert_eq!(
        results["results"][0]["data"],
        json!({"State": "true"}),
        "{results}"
    );
    assert_eq!(
        by("EndSearch")["result"]["endpoint"],
        "2026-10-25T00:00:00Z"
    );
    assert_eq!(
        by("GetReplayUri")["result"]["uri"],
        "rtsp://203.0.113.9/replay/rec_canned"
    );
    // The services were found in GetCapabilities' Extension and reached by path on our host.
    let s = seen.lock().unwrap();
    for p in [wire::RECORDING_PATH, wire::SEARCH_PATH, wire::REPLAY_PATH] {
        assert!(s.paths.contains(&p.to_string()), "{p} {:?}", s.paths);
    }
    let find = s
        .bodies
        .iter()
        .find(|b| operation(b) == "FindEvents")
        .unwrap();
    for part in [
        "<tse:StartPoint>2026-10-24T00:00:00Z</tse:StartPoint>",
        "<tse:EndPoint>2026-10-25T00:00:00Z</tse:EndPoint>",
        "<tt:IncludedRecordings>rec_canned</tt:IncludedRecordings>",
        ">tns1:VideoSource/MotionAlarm</wsnt:TopicExpression>",
        "<tse:MaxMatches>5</tse:MaxMatches>",
        "<tse:KeepAliveTime>PT30S</tse:KeepAliveTime>",
    ] {
        assert!(find.contains(part), "{part} not in {find}");
    }
    let replay = s
        .bodies
        .iter()
        .find(|b| operation(b) == "GetReplayUri")
        .unwrap();
    assert!(
        replay.contains("<trp:RecordingToken>rec_canned</trp:RecordingToken>"),
        "{replay}"
    );
}
