//! SSDP / UPnP discovery server tests.
//!
//! Two layers, weakest evidence first, so it is obvious what each claim rests on.
//!
//! 1. **Codec against literal UDA 1.1 message text**, with no network and no LLM. The
//!    literals are the message shapes the UPnP Device Architecture 1.1 specification prints
//!    in §1.2 and §1.3, so they are independent of this implementation.
//! 2. **End to end through the real binary**, driven by a raw UDP socket with the LLM
//!    mocked. This is where the silence is pinned: a search that does not match, and a
//!    backend that has fallen over, must both produce **no datagram at all** — not an error
//!    datagram, because SSDP has no such thing and every message it defines is a positive
//!    assertion that a device exists.
//!
//! There is deliberately **no third-party-client layer**, and that is why this protocol is
//! `Experimental` rather than `Beta`. See `tests/server/ssdp/CLAUDE.md` for what was
//! surveyed and why none of it can be pointed at a unicast loopback address.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::ssdp::actions::{RequestContext, SsdpProtocol};
use netget::server::ssdp::message::{self, NotifyMessage, SearchResponse};
use std::time::Duration;
use tokio::net::UdpSocket;

// ===========================================================================
// Layer 1 — codec against literal UDA 1.1 message text
// ===========================================================================

/// The M-SEARCH a control point sends, UDA 1.1 §1.3.2.
const UDA_MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 3\r\n\
ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
USER-AGENT: unix/5.1 UPnP/1.1 crash/1.0\r\n\
\r\n";

/// The alive announcement a device multicasts, UDA 1.1 §1.2.2.
const UDA_NOTIFY_ALIVE: &str = "NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
CACHE-CONTROL: max-age=1800\r\n\
LOCATION: http://192.168.1.20:2869/desc.xml\r\n\
NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
NTS: ssdp:alive\r\n\
SERVER: Windows/10.0 UPnP/1.1 WMPNSS/12.0\r\n\
USN: uuid:1cd1e0ac-8f2a-4bd5-9a4d-7a0d5a26f1b2::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
\r\n";

#[test]
fn parses_the_uda_msearch() {
    let m = message::parse(UDA_MSEARCH.as_bytes()).expect("the spec's own M-SEARCH must parse");

    assert_eq!(m.method.as_deref(), Some("M-SEARCH"));
    assert_eq!(m.start_line, "M-SEARCH * HTTP/1.1");
    assert_eq!(m.header("HOST"), Some("239.255.255.250:1900"));
    // The quotes are part of the value; a MAN of ssdp:discover without them is not
    // conforming, and the model has to be able to tell the difference.
    assert_eq!(m.header("MAN"), Some("\"ssdp:discover\""));
    assert_eq!(m.mx(), Some(3));
    assert_eq!(
        m.header("ST"),
        Some("urn:schemas-upnp-org:device:MediaServer:1")
    );
    assert_eq!(m.header("USER-AGENT"), Some("unix/5.1 UPnP/1.1 crash/1.0"));

    // Lookup is case-insensitive in both directions.
    assert_eq!(m.header("host"), m.header("HOST"));
}

#[test]
fn parses_the_uda_alive_notify() {
    let m = message::parse(UDA_NOTIFY_ALIVE.as_bytes()).expect("the spec's own NOTIFY must parse");

    assert_eq!(m.method.as_deref(), Some("NOTIFY"));
    assert_eq!(m.header("NTS"), Some("ssdp:alive"));
    assert_eq!(
        m.header("NT"),
        Some("urn:schemas-upnp-org:device:MediaRenderer:1")
    );
    assert_eq!(
        m.header("LOCATION"),
        Some("http://192.168.1.20:2869/desc.xml")
    );
    assert_eq!(m.header("CACHE-CONTROL"), Some("max-age=1800"));

    let headers = m.headers_json();
    assert_eq!(
        headers["SERVER"],
        serde_json::json!("Windows/10.0 UPnP/1.1 WMPNSS/12.0"),
        "headers reach the model as a map, not a pre-rendered blob"
    );
}

/// A status line is a **response** — another device answering somebody else's search, which
/// arrives constantly once joined to the group. `method` is `None` precisely so `mod.rs` can
/// drop it rather than starting a discovery loop by answering it.
#[test]
fn a_status_line_is_recognised_as_a_response_not_a_request() {
    let m = message::parse(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n")
        .expect("a 200 OK is a well-formed HTTPU message");
    assert_eq!(m.method, None);
    assert_eq!(m.start_line, "HTTP/1.1 200 OK");
}

#[test]
fn refuses_datagrams_that_are_not_ssdp() {
    use message::ParseError;

    assert_eq!(message::parse(b"").unwrap_err(), ParseError::Empty);
    assert_eq!(message::parse(b"\r\n\r\n").unwrap_err(), ParseError::Empty);
    assert_eq!(
        message::parse(&[0xff, 0xfe, 0x00, 0x01]).unwrap_err(),
        ParseError::NotUtf8
    );
    // A header line with no separator. Accepting it would let a truncated datagram parse.
    assert!(matches!(
        message::parse(b"M-SEARCH * HTTP/1.1\r\nthis is not a header\r\n\r\n").unwrap_err(),
        ParseError::MalformedHeader(_)
    ));
    // Not a request line and not a status line.
    assert!(matches!(
        message::parse(b"hello world\r\n\r\n").unwrap_err(),
        ParseError::MalformedStartLine(_)
    ));
    // A request line whose version is not HTTP.
    assert!(matches!(
        message::parse(b"M-SEARCH * SSDP/1.0\r\n\r\n").unwrap_err(),
        ParseError::MalformedStartLine(_)
    ));

    let too_long = vec![b'A'; message::MAX_MESSAGE_LEN + 1];
    assert!(matches!(
        message::parse(&too_long).unwrap_err(),
        ParseError::TooLong(_)
    ));
}

/// Real implementations are sloppy about line endings. Parsing tolerates a bare LF; nothing
/// this server *emits* ever uses one.
#[test]
fn tolerates_bare_lf_on_input() {
    let m = message::parse(b"M-SEARCH * HTTP/1.1\nST: ssdp:all\nMX: 2\n\n")
        .expect("a bare-LF M-SEARCH is still an M-SEARCH");
    assert_eq!(m.header("ST"), Some("ssdp:all"));
    assert_eq!(m.mx(), Some(2));
}

/// UDA 1.1 §1.3.2: a device must treat an MX larger than 5 as 5. Without the clamp a hostile
/// or buggy control point could park a response task for hours.
#[test]
fn mx_is_clamped_to_five_seconds() {
    let huge = message::parse(b"M-SEARCH * HTTP/1.1\r\nMX: 4000000\r\n\r\n").unwrap();
    assert_eq!(huge.mx(), Some(message::MAX_MX_SECONDS));

    let absent = message::parse(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n").unwrap();
    assert_eq!(absent.mx(), None, "absent MX is not the same as MX 0");

    let garbage = message::parse(b"M-SEARCH * HTTP/1.1\r\nMX: soon\r\n\r\n").unwrap();
    assert_eq!(garbage.mx(), None);
}

/// The mandatory header set for an M-SEARCH response, UDA 1.1 §1.3.3.
///
/// `EXT` is the one that looks like a typo and is not: it is a marker header with an empty
/// value, and a control point that does not see it treats the response as coming from a
/// device that ignored the MAN extension.
#[test]
fn renders_the_mandatory_search_response_header_set() {
    let rendered = message::render_search_response(&SearchResponse {
        st: "urn:schemas-upnp-org:device:MediaServer:1".to_string(),
        usn: "uuid:9f8d2b31::urn:schemas-upnp-org:device:MediaServer:1".to_string(),
        location: "http://192.168.1.10:8080/description.xml".to_string(),
        server: "Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0".to_string(),
        max_age: 1800,
        date: "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
        extra_headers: vec![("BOOTID.UPNP.ORG".to_string(), "1".to_string())],
    });

    assert_eq!(
        rendered,
        "HTTP/1.1 200 OK\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         DATE: Sun, 06 Nov 1994 08:49:37 GMT\r\n\
         EXT:\r\n\
         LOCATION: http://192.168.1.10:8080/description.xml\r\n\
         SERVER: Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0\r\n\
         ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
         USN: uuid:9f8d2b31::urn:schemas-upnp-org:device:MediaServer:1\r\n\
         BOOTID.UPNP.ORG: 1\r\n\
         \r\n"
    );

    // And it parses back as a response, which is what a control point does with it.
    let reparsed = message::parse(rendered.as_bytes()).expect("our own output must parse");
    assert_eq!(reparsed.method, None);
    assert_eq!(reparsed.header("EXT"), Some(""));
}

/// The `DATE` header must be an HTTP-date ending in the literal `GMT`. `chrono`'s
/// `to_rfc2822` renders `+0000` instead, which is RFC 2822 and not HTTP.
#[test]
fn the_date_header_is_an_http_date() {
    let t = chrono::DateTime::parse_from_rfc3339("1994-11-06T08:49:37Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert_eq!(message::http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
}

/// UDA 1.1 §1.2.3: a byebye carries **only** HOST, NT, NTS and USN.
///
/// Sending LOCATION and CACHE-CONTROL alongside it contradicts the announcement — it tells
/// the control point where to reach a device that has just said it is leaving, and how long
/// to keep believing in it.
#[test]
fn a_byebye_carries_only_the_four_headers_uda_allows() {
    let rendered = message::render_notify(&NotifyMessage {
        host: "239.255.255.250:1900".to_string(),
        nt: "upnp:rootdevice".to_string(),
        nts: "ssdp:byebye".to_string(),
        usn: "uuid:9f8d2b31::upnp:rootdevice".to_string(),
        location: None,
        server: None,
        max_age: None,
    });

    assert_eq!(
        rendered,
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         NT: upnp:rootdevice\r\n\
         NTS: ssdp:byebye\r\n\
         USN: uuid:9f8d2b31::upnp:rootdevice\r\n\
         \r\n"
    );
}

/// The jitter is what makes NetGet's traffic look like a device's rather than a machine
/// answering instantly. Asserted as a range over many draws rather than by timing anything,
/// which would be flaky at `--test-threads=100`.
#[test]
fn the_mx_jitter_stays_in_range_and_is_not_degenerate() {
    assert_eq!(
        message::response_delay_bound_ms(Some(3), 1000),
        1000,
        "the operator's cap wins when it is lower than MX"
    );
    assert_eq!(
        message::response_delay_bound_ms(Some(1), 5000),
        1000,
        "MX wins when it is lower than the cap"
    );
    assert_eq!(message::response_delay_bound_ms(None, 5000), 0);
    assert_eq!(
        message::response_delay_bound_ms(Some(5), 0),
        0,
        "a cap of 0 disables the jitter entirely"
    );

    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..400 {
        let d = message::response_delay_ms(Some(2), 200);
        assert!(d <= 200, "delay {d} exceeded the bound of 200ms");
        seen.insert(d);
    }
    assert!(
        seen.len() > 20,
        "the delay took only {} distinct values in 400 draws; that is not jitter, and a \
         constant would pass a bounds check alone",
        seen.len()
    );

    for _ in 0..20 {
        assert_eq!(message::response_delay_ms(Some(5), 0), 0);
    }
}

// ---------------------------------------------------------------------------
// Layer 1b — the executor, on the stateless registry instance
// ---------------------------------------------------------------------------

fn execute(action: serde_json::Value) -> anyhow::Result<ActionResult> {
    SsdpProtocol::new().execute_action(action)
}

/// CR/LF in a model-supplied header would end the message early and let one action emit a
/// second one — the HTTP response-splitting shape. Refused, not sanitised, so the model is
/// told what it did.
#[test]
fn header_injection_through_extra_headers_is_refused() {
    let err = execute(serde_json::json!({
        "type": "send_ssdp_response",
        "st": "upnp:rootdevice",
        "usn": "uuid:9f8d2b31::upnp:rootdevice",
        "location": "http://127.0.0.1:8080/d.xml",
        "extra_headers": { "X-Evil": "1\r\nLOCATION: http://attacker.example/d.xml" }
    }))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("carriage return or newline"),
        "expected the injection to be named; got {err}"
    );

    // The same check applies to the plain string fields.
    assert!(execute(serde_json::json!({
        "type": "send_ssdp_response",
        "st": "upnp:rootdevice",
        "usn": "uuid:x\r\nEXTRA: header",
        "location": "http://127.0.0.1:8080/d.xml"
    }))
    .is_err());

    // And a mandatory header cannot be set twice by going round the parameters.
    let err = execute(serde_json::json!({
        "type": "send_ssdp_response",
        "st": "upnp:rootdevice",
        "usn": "uuid:9f8d2b31::upnp:rootdevice",
        "location": "http://127.0.0.1:8080/d.xml",
        "extra_headers": { "LOCATION": "http://attacker.example/d.xml" }
    }))
    .unwrap_err()
    .to_string();
    assert!(err.contains("mandatory response headers"), "got {err}");
}

/// A LOCATION that is not an absolute http(s) URL makes the advertisement useless while
/// still looking valid on the wire — the class of failure that cannot be debugged from the
/// control point's end.
#[test]
fn a_location_that_is_not_a_fetchable_url_is_refused() {
    for bad in [
        "not a url",
        "/description.xml",
        "ftp://192.168.1.10/desc.xml",
        "192.168.1.10:8080/desc.xml",
    ] {
        assert!(
            execute(serde_json::json!({
                "type": "send_ssdp_response",
                "st": "upnp:rootdevice",
                "usn": "uuid:9f8d2b31::upnp:rootdevice",
                "location": bad
            }))
            .is_err(),
            "LOCATION {bad:?} should have been refused"
        );
    }
}

/// UDA 1.1 defines exactly three NTS values. A control point ignores anything else, so an
/// unchecked one is a silent no-op — the model would believe it announced something.
#[test]
fn an_unknown_nts_is_refused() {
    let err = execute(serde_json::json!({
        "type": "send_ssdp_notify",
        "nt": "upnp:rootdevice",
        "nts": "ssdp:hello",
        "usn": "uuid:9f8d2b31::upnp:rootdevice",
        "location": "http://127.0.0.1:8080/d.xml"
    }))
    .unwrap_err()
    .to_string();
    assert!(err.contains("ssdp:alive"), "got {err}");
}

/// A search for a concrete type has its ST echoed when the model omits it — a response whose
/// ST does not match is silently discarded by a control point, which looks exactly like the
/// server being down. A **wildcard** search cannot be echoed, because the response must name
/// the concrete type, so that case is an error rather than a guess.
#[test]
fn st_is_echoed_for_a_concrete_search_but_never_for_a_wildcard() {
    let concrete = SsdpProtocol::for_request(RequestContext::ipv4_defaults(Some(
        "urn:schemas-upnp-org:device:MediaServer:1".to_string(),
    )));
    let result = concrete
        .execute_action(serde_json::json!({
            "type": "send_ssdp_response",
            "usn": "uuid:9f8d2b31::urn:schemas-upnp-org:device:MediaServer:1",
            "location": "http://127.0.0.1:8080/d.xml"
        }))
        .expect("a concrete search target can be echoed");
    let ActionResult::Output(bytes) = result else {
        panic!("send_ssdp_response must produce output bytes");
    };
    let parsed = message::parse(&bytes).unwrap();
    assert_eq!(
        parsed.header("ST"),
        Some("urn:schemas-upnp-org:device:MediaServer:1")
    );

    for wildcard in ["ssdp:all", "upnp:rootdevice"] {
        let p =
            SsdpProtocol::for_request(RequestContext::ipv4_defaults(Some(wildcard.to_string())));
        let err = p
            .execute_action(serde_json::json!({
                "type": "send_ssdp_response",
                "usn": "uuid:9f8d2b31::upnp:rootdevice",
                "location": "http://127.0.0.1:8080/d.xml"
            }))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("wildcard"),
            "a {wildcard} search must not have an ST invented for it; got {err}"
        );
    }
}

/// `no_response` must be distinguishable from a model that returned nothing at all. If it
/// returned `ActionResult::NoAction` it would look identical to `show_message`, and the
/// whole point of the action is that a refusal is a decision the log can record.
#[test]
fn no_response_is_its_own_result_not_a_bare_no_action() {
    let result = execute(serde_json::json!({
        "type": "no_response",
        "reason": "not a printer"
    }))
    .expect("no_response must execute");
    match result {
        ActionResult::Custom { name, data } => {
            assert_eq!(name, "ssdp_no_response");
            assert_eq!(data["reason"], serde_json::json!("not a printer"));
        }
        other => panic!("no_response must be a distinguishable result, got {other:?}"),
    }

    // The reason is optional; the action itself is the decision.
    assert!(execute(serde_json::json!({ "type": "no_response" })).is_ok());
}

/// A byebye built through the executor drops LOCATION even when the model supplies one,
/// because §1.2.3 does not allow it there.
#[test]
fn the_executor_strips_location_from_a_byebye() {
    let result = execute(serde_json::json!({
        "type": "send_ssdp_notify",
        "nt": "upnp:rootdevice",
        "nts": "ssdp:byebye",
        "usn": "uuid:9f8d2b31::upnp:rootdevice",
        "location": "http://127.0.0.1:8080/d.xml"
    }))
    .expect("a byebye must execute");
    let ActionResult::Custom { name, data } = result else {
        panic!("send_ssdp_notify must be a Custom result so it can be multicast, not unicast");
    };
    assert_eq!(name, "ssdp_notify");
    let rendered = data["message"].as_str().unwrap();
    assert!(
        !rendered.contains("LOCATION"),
        "byebye must carry no LOCATION: {rendered}"
    );
    assert!(!rendered.contains("CACHE-CONTROL"));
}

// ===========================================================================
// Layer 2 — end to end through the real binary, LLM mocked
// ===========================================================================

const DEVICE_UUID: &str = "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33";
const MEDIA_SERVER: &str = "urn:schemas-upnp-org:device:MediaServer:1";
const DESCRIPTION_URL: &str = "http://192.168.1.10:8080/description.xml";

/// A unicast M-SEARCH addressed straight at the server's own port.
///
/// Unicast, not multicast, and that is the whole reason this suite is deterministic: it needs
/// no privileged port, no real link and no successful group join, so it behaves the same on a
/// laptop and on a CI runner. UDA 1.1 §1.3.2 permits a unicast search, so this is a real
/// M-SEARCH rather than a testing-only shortcut.
fn msearch(st: &str, mx: u32, port: u16) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 127.0.0.1:{port}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: {st}\r\n\
         USER-AGENT: netget-test/1.0 UPnP/1.1 e2e/1.0\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Send a datagram and wait up to `secs` for an answer. `None` means nothing came back.
async fn ask(port: u16, datagram: &[u8], secs: u64) -> E2EResult<Option<Vec<u8>>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(datagram, format!("127.0.0.1:{port}"))
        .await?;

    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_secs(secs), socket.recv_from(&mut buf)).await {
        Err(_) => Ok(None),
        Ok(Ok((n, _))) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Ok(Err(e)) => Err(format!("SSDP recv failed: {e}").into()),
    }
}

/// Wait for a log line rather than asserting on it immediately: the datagram arrives on the
/// socket before the harness has necessarily drained the child's stdout, so a bare
/// `output_contains` right after `ask()` is a race that passes on a quiet machine.
async fn wait_for_log(server: &helpers::server::NetGetServer, needle: &str) -> bool {
    for _ in 0..100 {
        if server.output_contains(needle).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A matching search is answered; a non-matching one is **silent**.
///
/// One server, one mock rule that branches on the event, two searches. The rule branches
/// rather than being two rules, because two rules on the same event with no way to tell them
/// apart is the standing mistake in this repo: the first would answer both searches and the
/// second would report zero calls.
///
/// The silence half is the important one. SSDP has no "no thanks" message — UDA 1.1 §1.3.3
/// requires a device whose type does not match the search target to say nothing — so a
/// server that answered a Printer search with *anything*, including a courteous error, would
/// be advertising a printer that does not exist.
#[tokio::test]
async fn answers_a_matching_search_and_stays_silent_for_a_mismatch() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via ssdp. You are a UPnP MediaServer; answer \
         searches for MediaServer and stay silent for anything else.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("ssdp_msearch")
            .respond_with_actions_from_event(|event| {
                // Derived from the event, so a server that handed the model the wrong ST —
                // or dropped it — turns the matching case into a refusal and fails below.
                let st = event["st"].as_str().unwrap_or("");
                if st == MEDIA_SERVER || st == "ssdp:all" {
                    serde_json::json!([{
                        "type": "send_ssdp_response",
                        "st": MEDIA_SERVER,
                        "usn": format!("{DEVICE_UUID}::{MEDIA_SERVER}"),
                        "location": DESCRIPTION_URL,
                        "server": "Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0",
                        "cache_control_max_age": 1800
                    }])
                } else {
                    serde_json::json!([{
                        "type": "no_response",
                        "reason": format!("{st} is not a media server")
                    }])
                }
            })
            .expect_calls(2)
            .and()
            .on_instruction_containing("via ssdp")
            .respond_with_actions_from_event(|_| {
                serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ssdp",
                    "startup_params": { "max_response_delay_ms": 300 },
                    "instruction": "You are a UPnP MediaServer. Answer MediaServer searches."
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- the matching search ---
    let raw = ask(server.port, &msearch(MEDIA_SERVER, 3, server.port), 15)
        .await?
        .ok_or("a matching M-SEARCH got no answer at all")?;
    let reply = message::parse(&raw).expect("the answer must be a well-formed HTTPU message");

    assert_eq!(
        reply.start_line, "HTTP/1.1 200 OK",
        "an M-SEARCH is answered with a 200 OK status line"
    );
    assert_eq!(
        reply.method, None,
        "the answer is a response, not another request"
    );
    assert_eq!(
        reply.header("ST"),
        Some(MEDIA_SERVER),
        "the response must echo the requested ST; a control point discards it otherwise"
    );
    assert_eq!(
        reply.header("USN"),
        Some(format!("{DEVICE_UUID}::{MEDIA_SERVER}").as_str())
    );
    assert_eq!(reply.header("LOCATION"), Some(DESCRIPTION_URL));
    assert_eq!(reply.header("CACHE-CONTROL"), Some("max-age=1800"));
    assert_eq!(
        reply.header("SERVER"),
        Some("Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0"),
        "the model's SERVER overrides the server_header default"
    );
    assert_eq!(
        reply.header("EXT"),
        Some(""),
        "EXT is mandatory and empty (UDA 1.1 §1.3.3)"
    );
    assert!(
        reply.header("DATE").is_some_and(|d| d.ends_with("GMT")),
        "DATE must be an HTTP-date: {:?}",
        reply.header("DATE")
    );
    assert!(
        wait_for_log(&server, "decision=model_response").await,
        "the answer must be logged as the model's. Output: {:?}",
        server.get_output().await
    );

    // --- the mismatching search: nothing at all ---
    let silence = ask(
        server.port,
        &msearch("urn:schemas-upnp-org:device:Printer:1", 1, server.port),
        6,
    )
    .await?;
    if let Some(bytes) = silence {
        panic!(
            "the server answered a search it does not match with {} bytes: {:?}. Every SSDP \
             message asserts that a device exists at a LOCATION, so there is nothing \
             harmless to send here — a non-matching device must be silent (UDA 1.1 §1.3.3).",
            bytes.len(),
            String::from_utf8_lossy(&bytes)
        );
    }

    // The silence must be recorded as the model's own decision, distinct from a failure.
    assert!(
        wait_for_log(&server, "decision=model_reject").await,
        "an explicit no_response must be logged as model_reject, not as a fail-closed \
         path. Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server.output_contains("decision=fail_closed").await,
        "nothing here failed closed; output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// **The silence-on-failure test.**
///
/// When the LLM backend falls over, an SSDP server must write nothing. It must not answer
/// with a `WireFailure` string the way `http` or `redis` do, because SSDP has no header in
/// which to carry one: the only messages it defines are a 200 OK and a NOTIFY, and both of
/// them assert that a device exists at a URL. A control point receiving one caches it for
/// `max-age` and then goes and fetches that URL.
///
/// So this asserts the pair the `udp` failure test asserts: **nothing on the wire, and a
/// loud, specific log line saying why**. A silent drop with no log would be
/// indistinguishable from the server having never received the datagram.
#[tokio::test]
async fn stays_silent_but_logs_when_the_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via ssdp. Pretend to be a UPnP root device.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("via ssdp")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "ssdp",
                "startup_params": { "max_response_delay_ms": 0 },
                "instruction": "Pretend to be a UPnP root device"
            }]))
            .expect_calls(1)
            .and()
        // No rule for `ssdp_msearch`: the mock answers 500, which is the backend outage.
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let answer = ask(server.port, &msearch("ssdp:all", 1, server.port), 6).await?;
    if let Some(bytes) = answer {
        panic!(
            "the server invented a {}-byte reply while the LLM was failing: {:?}. There is \
             no error message in SSDP — anything sent here is a well-formed advertisement \
             for a device that does not exist, which every listener will cache and then try \
             to fetch.",
            bytes.len(),
            String::from_utf8_lossy(&bytes)
        );
    }

    assert!(
        wait_for_log(&server, "decision=fail_closed_llm_error").await,
        "the silence must be explained, and labelled as the server's failure rather than \
         the model's refusal — otherwise it is indistinguishable from the silent-failure \
         defect. Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server.output_contains("decision=model_reject").await,
        "a backend outage must never be recorded as the model declining. Output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// An inbound NOTIFY reaches the model, and `send_ssdp_notify` really goes out.
///
/// The announcement is pointed at a socket this test owns (`notify_target`) rather than at
/// `239.255.255.250:1900`. That is not a testing shortcut around a broken path: loopback
/// carries no multicast route, so `sendto(239.255.255.250:1900)` from a socket bound to
/// 127.0.0.1 returns `EADDRNOTAVAIL` (measured on macOS 27), and the parameter exists
/// precisely so announcements can be observed. What is under test is everything else — that
/// the event fires with the announcer's fields, that the model's answer is rendered as a
/// real NOTIFY, and that it is addressed to the group in its HOST header whatever socket it
/// is sent to.
#[tokio::test]
async fn an_inbound_notify_reaches_the_model_and_an_announcement_goes_out() -> E2EResult<()> {
    let observer = UdpSocket::bind("127.0.0.1:0").await?;
    let observer_port = observer.local_addr()?.port();

    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via ssdp. Announce yourself when another device \
         announces itself.",
    )
    .with_log_level("debug")
    .with_mock(move |mock| {
        mock.on_event("ssdp_notify")
            .respond_with_actions_from_event(|event| {
                // Branch on the event so the test fails if the server did not decode the
                // announcement it received.
                if event["nts"].as_str() == Some("ssdp:alive") {
                    serde_json::json!([{
                        "type": "send_ssdp_notify",
                        "nt": MEDIA_SERVER,
                        "nts": "ssdp:alive",
                        "usn": format!("{DEVICE_UUID}::{MEDIA_SERVER}"),
                        "location": DESCRIPTION_URL
                    }])
                } else {
                    serde_json::json!([{ "type": "no_response", "reason": "not an alive" }])
                }
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via ssdp")
            .respond_with_actions_from_event(move |_| {
                serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ssdp",
                    "startup_params": {
                        "max_response_delay_ms": 0,
                        "notify_target": format!("127.0.0.1:{observer_port}")
                    },
                    "instruction": "Announce yourself when another device announces itself."
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let sender = UdpSocket::bind("127.0.0.1:0").await?;
    sender
        .send_to(
            UDA_NOTIFY_ALIVE.as_bytes(),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), observer.recv_from(&mut buf))
        .await
        .map_err(|_| {
            "no announcement arrived at notify_target; send_ssdp_notify produced nothing"
        })??;
    buf.truncate(n);

    let announcement = message::parse(&buf).expect("the announcement must be well formed");
    assert_eq!(announcement.method.as_deref(), Some("NOTIFY"));
    assert_eq!(announcement.start_line, "NOTIFY * HTTP/1.1");
    assert_eq!(
        announcement.header("HOST"),
        Some("239.255.255.250:1900"),
        "HOST names the multicast group even when the datagram is pointed elsewhere: it is \
         the group the announcement is *about*, not the socket it went to"
    );
    assert_eq!(announcement.header("NTS"), Some("ssdp:alive"));
    assert_eq!(announcement.header("NT"), Some(MEDIA_SERVER));
    assert_eq!(
        announcement.header("USN"),
        Some(format!("{DEVICE_UUID}::{MEDIA_SERVER}").as_str())
    );
    assert_eq!(announcement.header("LOCATION"), Some(DESCRIPTION_URL));
    assert_eq!(
        announcement.header("CACHE-CONTROL"),
        Some("max-age=1800"),
        "an alive announcement carries the default max-age when the model gives none"
    );
    assert_eq!(
        announcement.header("SERVER"),
        Some("NetGet/1.0 UPnP/1.1 NetGet-SSDP/1.0"),
        "the server_header default is used when the action names no SERVER"
    );

    assert!(
        wait_for_log(&server, "decision=model_notify").await,
        "Output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
