//! NetGet's ONVIF device from raw HTTP: the anonymous clock, every way a UsernameToken is
//! refused (and that a refusal never reaches the model), the faults for unknown and malformed
//! requests, the size and depth bounds, and a model that fails or answers wrongly failing
//! closed. The policy is `real_client_test::POLICY`; no LLM calls.
use super::real_client_test::{credentials, events, policy, start, PASSWORD, USER};
use base64::Engine;
use netget::server::onvif::wire;
use serde_json::{json, Value};
use std::time::Duration;

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn post(port: u16, body: impl Into<String>) -> (u16, String) {
    let r = http()
        .post(format!("http://127.0.0.1:{port}{}", wire::DEVICE_PATH))
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .body(body.into())
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap_or_default())
}

fn created(offset_secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(offset_secs))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn signed(user: &str, password: &str, nonce: &[u8], created: &str, body: &str) -> String {
    wire::request_envelope(
        Some(&wire::security_header(user, password, nonce, created)),
        body,
    )
}

const INFO: &str = "<tds:GetDeviceInformation/>";

/// The `ter:` subcodes of a fault body, in order.
fn subcodes(body: &str) -> Vec<String> {
    body.split("<env:Value>ter:")
        .skip(1)
        .filter_map(|s| s.split('<').next())
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn the_clock_is_anonymous_and_everything_else_needs_a_fresh_digest() {
    let (state, id, port) = start(policy(), credentials()).await;

    let (status, body) = post(
        port,
        wire::request_envelope(None, "<tds:GetSystemDateAndTime/>"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let el = match wire::parse_reply(body.as_bytes()).unwrap() {
        wire::Reply::Ok(el) => el,
        wire::Reply::Fault(f) => panic!("{f}"),
    };
    let when = wire::utc_of(el.child("SystemDateAndTime").unwrap()).unwrap();
    assert!(
        (chrono::Utc::now() - when).num_seconds().abs() <= 5,
        "{body}"
    );

    // Each refusal, and the reason the log gives for it.
    let password_text = wire::request_envelope(
        Some(&format!(
            "<wsse:Security xmlns:wsse=\"{}\" xmlns:wsu=\"{}\"><wsse:UsernameToken><wsse:Username>{USER}</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">{PASSWORD}</wsse:Password><wsu:Created>{}</wsu:Created></wsse:UsernameToken></wsse:Security>",
            wire::WSSE, wire::WSU, created(0)
        )),
        INFO,
    );
    let replayed_nonce = *b"replayed-nonce!!";
    let replayed_created = created(0);
    let cases: Vec<(String, &str)> = vec![
        (wire::request_envelope(None, INFO), "no_username_token"),
        (
            signed(USER, "wrong", b"nonce-0000000001", &created(0), INFO),
            "bad_digest",
        ),
        (
            signed("root", PASSWORD, b"nonce-0000000002", &created(0), INFO),
            "unknown_user",
        ),
        (password_text, "password_not_digest"),
        (
            signed(USER, PASSWORD, b"nonce-0000000003", &created(-3600), INFO),
            "stale_created",
        ),
        (
            signed(USER, PASSWORD, b"nonce-0000000004", &created(3600), INFO),
            "stale_created",
        ),
        (
            signed(USER, PASSWORD, b"nonce-0000000005", "yesterday", INFO),
            "bad_created",
        ),
    ];
    for (request, _) in &cases {
        let (status, body) = post(port, request.clone()).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("<env:Value>env:Sender</env:Value>"), "{body}");
        assert_eq!(subcodes(&body), vec!["NotAuthorized"], "{body}");
    }
    // A good token is answered, once; the same token again is a replay.
    let good = signed(USER, PASSWORD, &replayed_nonce, &replayed_created, INFO);
    let (status, body) = post(port, good.clone()).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("<tds:Manufacturer>NetGet Optics</tds:Manufacturer>"),
        "{body}"
    );
    let (status, body) = post(port, good).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(subcodes(&body), vec!["NotAuthorized"]);

    let mut want: Vec<&str> = cases.iter().map(|(_, r)| *r).collect();
    want.push("replayed_nonce");
    let got: Vec<Value> = events(&state, id, "onvif_not_authorized")
        .await
        .iter()
        .map(|e| e["reason"].clone())
        .collect();
    assert_eq!(got, want.iter().map(|r| json!(r)).collect::<Vec<_>>());
    // Only the one good request reached the model.
    assert_eq!(
        events(&state, id, "onvif_get_device_information")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn without_credentials_configured_the_device_is_open() {
    let (state, id, port) = start(policy(), json!({})).await;
    let (status, body) = post(port, wire::request_envelope(None, INFO)).await;
    assert_eq!(status, 200, "{body}");
    let asked = events(&state, id, "onvif_get_device_information").await;
    assert_eq!(asked[0]["username"], Value::Null);
}

#[tokio::test]
async fn unknown_and_malformed_requests_are_faults() {
    let (state, id, port) = start(policy(), credentials()).await;
    let sign = |body: &str| {
        let nonce: [u8; 16] = rand::random();
        signed(USER, PASSWORD, &nonce, &created(0), body)
    };
    // Operations NetGet does not serve, authenticated or not.
    for body in [
        sign("<tds:GetUsers/>"),
        wire::request_envelope(None, "<tds:SetUser/>"),
        sign("<tptz:SetHomePosition/>"),
        sign("<trc:GetRecordings xmlns:trc=\"http://www.onvif.org/ver10/recording/wsdl\"/>"),
    ] {
        let (status, text) = post(port, body).await;
        assert_eq!(status, 500, "{text}");
        assert!(
            text.contains("<env:Value>env:Receiver</env:Value>"),
            "{text}"
        );
        assert_eq!(subcodes(&text), vec!["ActionNotSupported"], "{text}");
    }
    let (status, text) = post(
        port,
        sign("<tds:GetCapabilities><tds:Category>Analytics</tds:Category></tds:GetCapabilities>"),
    )
    .await;
    assert_eq!(status, 500, "{text}");
    assert_eq!(subcodes(&text), vec!["ActionNotSupported", "NoSuchService"]);
    // Every category the device has, at its path, and no other.
    let (status, text) = post(
        port,
        sign("<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>"),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    for path in [
        "/onvif/device_service",
        "/onvif/events_service",
        "/onvif/imaging_service",
        "/onvif/media_service",
        "/onvif/ptz_service",
    ] {
        assert_eq!(
            text.matches(&format!("{path}</tt:XAddr>")).count(),
            1,
            "{path}: {text}"
        );
    }
    assert_eq!(text.matches("<tt:XAddr>").count(), 5, "{text}");
    assert!(!text.contains("<tt:Analytics>"), "{text}");
    let (status, text) = post(port, sign("<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>")).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        text.matches("<tds:Service>").count(),
        wire::SERVICES.len(),
        "{text}"
    );
    for (ns, path) in wire::SERVICES {
        assert!(
            text.contains(&format!("<tds:Namespace>{ns}</tds:Namespace><tds:XAddr>http://127.0.0.1:{port}{path}</tds:XAddr>")),
            "{ns}: {text}"
        );
    }
    let (status, text) = post(
        port,
        sign("<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>"),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.contains("/onvif/media_service</tt:XAddr>") && !text.contains("<tt:Device>"),
        "{text}"
    );

    // Not SOAP, a DOCTYPE, nesting past MAX_DEPTH, SOAP 1.1.
    let deep = format!(
        "{}{}",
        "<a>".repeat(wire::MAX_DEPTH + 8),
        "</a>".repeat(wire::MAX_DEPTH + 8)
    );
    for body in [
        "this is not XML".to_string(),
        format!(
            "<!DOCTYPE x [<!ENTITY a \"aaaa\">]>{}",
            wire::request_envelope(None, INFO)
                .split_once('\n')
                .unwrap()
                .1
        ),
        wire::request_envelope(None, &deep),
    ] {
        let (status, text) = post(port, body).await;
        assert_eq!(status, 400, "{text}");
        assert_eq!(subcodes(&text), vec!["WellFormed"], "{text}");
    }
    let soap11 = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><GetSystemDateAndTime xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>";
    let (status, text) = post(port, soap11).await;
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("env:VersionMismatch"), "{text}");

    // One byte past MAX_REQUEST is refused before it is parsed.
    let big = format!(
        "{}{}",
        wire::request_envelope(None, INFO),
        " ".repeat(wire::MAX_REQUEST)
    );
    assert!(big.len() > wire::MAX_REQUEST);
    let (status, _) = post(port, big).await;
    assert_eq!(status, 413);
    let exactly = format!(
        "{}{}",
        wire::request_envelope(None, "<tds:GetSystemDateAndTime/>"),
        " ".repeat(
            wire::MAX_REQUEST - wire::request_envelope(None, "<tds:GetSystemDateAndTime/>").len()
        )
    );
    assert_eq!(exactly.len(), wire::MAX_REQUEST);
    let (status, text) = post(port, exactly).await;
    assert_eq!(status, 200, "{text}");

    let r = http()
        .get(format!("http://127.0.0.1:{port}{}", wire::DEVICE_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 405);
    // None of it reached the model.
    for kind in ["onvif_get_device_information", "onvif_get_profiles"] {
        assert!(events(&state, id, kind).await.is_empty());
    }
}

#[tokio::test]
async fn a_model_that_fails_or_answers_wrongly_fails_closed() {
    let nonce = || -> [u8; 16] { rand::random() };
    // No handler and no reachable model: the backend fails.
    let (_state, _id, port) = start(None, credentials()).await;
    let (status, body) = post(
        port,
        signed(USER, PASSWORD, &nonce(), &created(0), "<trt:GetProfiles/>"),
    )
    .await;
    assert!(status == 500 || status == 503, "{status} {body}");
    assert!(
        body.contains("<env:Value>env:Receiver</env:Value>"),
        "{body}"
    );
    assert!(subcodes(&body).is_empty(), "{body}");
    assert!(
        !body.contains("127.0.0.1") && !body.contains("LLM") && !body.contains("retr"),
        "the failure leaked onto the wire: {body}"
    );

    // A handler that answers a stream request with something that is not a URI, and a profiles
    // request with the wrong action: both are refused, neither is sent.
    let wrong = r#"import json,sys
t=json.load(sys.stdin)['event_type_id']
a=[{'type':'onvif_stream_uri','uri':'not a uri'}] if t=='onvif_get_stream_uri' else [{'type':'onvif_snapshot_uri','uri':'http://192.0.2.1/x.jpg'}]
print(json.dumps({'actions':a}))"#;
    let (_state, _id, port) = start(
        Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":wrong}})]),
        credentials(),
    )
    .await;
    for request in [
        "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>main</trt:ProfileToken></trt:GetStreamUri>",
        "<trt:GetProfiles/>",
    ] {
        let (status, body) = post(port, signed(USER, PASSWORD, &nonce(), &created(0), request)).await;
        assert_eq!(status, 500, "{body}");
        assert!(body.contains("<env:Value>env:Receiver</env:Value>"), "{body}");
        assert!(!body.contains("not a uri") && !body.contains("x.jpg"), "{body}");
    }
}

#[test]
fn the_digest_is_the_token_profiles() {
    // UsernameToken Profile 1.0's own example: nonce, Created and password, and the digest.
    let nonce = base64::engine::general_purpose::STANDARD
        .decode("LKqI6G/AikKCQrN0zqZFlg==")
        .unwrap();
    assert_eq!(
        wire::password_digest(&nonce, "2010-09-16T07:50:45Z", "userpassword"),
        "tuOSpGlFlIXsozq4HFNeeGeFLEI="
    );
}
