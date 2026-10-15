//! SSDP / UPnP discovery **client** tests.
//!
//! Three layers, weakest evidence last, so it is obvious what each claim rests on and what
//! it does not.
//!
//! 1. **The executor and the request bytes, with no network and no LLM.** What the client
//!    puts on the wire is asserted by parsing it back with the *device* half's codec
//!    (`server::ssdp::message`), and every rejection the executor makes is pinned.
//! 2. **End to end against two devices hand-written in this file.** This is what proves the
//!    one-to-many shape — that a search collects replies for its whole window, raises one
//!    event per responder rather than returning on the first datagram, and that an
//!    unsolicited NOTIFY is surfaced too. Those devices are an independent reading of UDA
//!    1.1, **not** an independent implementation of it: same class as `dhcp`'s in-test RFC
//!    2131 decoder.
//! 3. **End to end against NetGet's own SSDP server**, two processes over unicast loopback.
//!    This is **same-project evidence**: it shows the two halves of NetGet agree, not that
//!    either matches a real UPnP device. It is why the client is `Experimental` and not
//!    `Beta`; see `tests/client/ssdp/CLAUDE.md` for what would actually earn Beta.
//!
//! Everything is unicast to 127.0.0.1. That is not a shortcut around a bug: bound to
//! loopback, *sending* to 239.255.255.250 fails with `EADDRNOTAVAIL` (49) because loopback
//! carries no multicast route — measured on macOS 27, where the group *join* succeeds and
//! only the send fails. UDA 1.1 §1.3.2 permits a unicast M-SEARCH, so this is a real search
//! rather than a testing-only shortcut, and it is what `send_msearch`'s `target` parameter
//! exists for.


use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::client::ssdp::{max_age_of, render_msearch, SsdpClientProtocol};
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::server::ssdp::message;
use serde_json::json;
use std::time::Duration;
use tokio::net::UdpSocket;

const DEVICE_UUID: &str = "uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33";
const OTHER_UUID: &str = "uuid:2b7f4c10-6d3e-4a11-b0c9-5e8a3f2d7c44";
const MEDIA_SERVER: &str = "urn:schemas-upnp-org:device:MediaServer:1";
const MEDIA_RENDERER: &str = "urn:schemas-upnp-org:device:MediaRenderer:1";

// ===========================================================================
// Layer 1 — the request bytes and the executor, no network, no LLM
// ===========================================================================

/// The M-SEARCH we emit must be a message a device will accept.
///
/// Asserted by parsing it with the **device** half's codec rather than by string comparison:
/// a string comparison only says the bytes did not change, while this says a UDA 1.1 parser
/// finds the fields where the specification says they are.
#[test]
fn the_msearch_we_emit_is_a_conforming_uda_request() {
    let target = "239.255.255.250:1900".parse().unwrap();
    let rendered = render_msearch(MEDIA_SERVER, 3, target, "NetGet/1.0 UPnP/1.1 test/1.0");

    let parsed = message::parse(rendered.as_bytes()).expect("our own M-SEARCH must parse");

    assert_eq!(parsed.method.as_deref(), Some("M-SEARCH"));
    assert_eq!(parsed.start_line, "M-SEARCH * HTTP/1.1");
    assert_eq!(parsed.header("HOST"), Some("239.255.255.250:1900"));
    // The quotes are part of the value. A device that receives `MAN: ssdp:discover` without
    // them is entitled to treat the search as non-conforming and ignore it.
    assert_eq!(parsed.header("MAN"), Some("\"ssdp:discover\""));
    assert_eq!(parsed.mx(), Some(3));
    assert_eq!(parsed.header("ST"), Some(MEDIA_SERVER));
    assert_eq!(
        parsed.header("USER-AGENT"),
        Some("NetGet/1.0 UPnP/1.1 test/1.0")
    );
    assert!(
        rendered.ends_with("\r\n\r\n"),
        "the header block must end with a blank line: {rendered:?}"
    );
}

/// A unicast search names the device in `HOST`, which is what the device expects to see and
/// what NetGet's own server suite sends.
#[test]
fn a_unicast_search_addresses_the_device_in_host() {
    let rendered = render_msearch("ssdp:all", 1, "127.0.0.1:41900".parse().unwrap(), "ua/1.0");
    let parsed = message::parse(rendered.as_bytes()).unwrap();
    assert_eq!(parsed.header("HOST"), Some("127.0.0.1:41900"));
}

fn execute(action: serde_json::Value) -> anyhow::Result<ClientActionResult> {
    SsdpClientProtocol::new().execute_action(action)
}

/// A CR or LF in the search target would end the `ST` line early and let the rest of the
/// model's string become further headers of *our* request — the response-splitting shape,
/// pointed at discovery. Refused rather than sanitised, so the model is told what it did.
#[test]
fn header_injection_through_the_search_target_is_refused() {
    let err = execute(json!({
        "type": "send_msearch",
        "st": "ssdp:all\r\nMAN: \"evil\""
    }))
    .expect_err("a search target containing CRLF must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("carriage return") || msg.contains("newline"),
        "the refusal must say why: {msg}"
    );

    assert!(
        execute(json!({"type": "send_msearch", "st": "a\nb"})).is_err(),
        "a bare LF splits the message just as well as a CRLF"
    );
}

/// `st` is not optional and not allowed to be blank: a device answers only a search whose
/// target it matches, so an empty target is a search that can never succeed.
#[test]
fn a_search_must_name_a_target() {
    assert!(execute(json!({"type": "send_msearch"})).is_err());
    assert!(execute(json!({"type": "send_msearch", "st": "   "})).is_err());
}

/// MX is clamped, not rejected.
///
/// UDA 1.1 §1.3.2 requires a *device* to treat an MX above 5 as 5, so an oversized value is
/// pointless rather than wrong — refusing the search over a detail the device ignores would
/// lose a discovery for nothing. Zero becomes 1 for the same reason: MX 0 asks every device
/// on the network to answer at once.
#[test]
fn mx_defaults_and_is_clamped_to_the_uda_range() {
    let mx_of = |action: serde_json::Value| -> u64 {
        match execute(action).expect("valid search") {
            ClientActionResult::Custom { data, .. } => data["mx"].as_u64().unwrap(),
            other => panic!("send_msearch must be Custom, got {other:?}"),
        }
    };

    assert_eq!(mx_of(json!({"type": "send_msearch", "st": "ssdp:all"})), 3);
    assert_eq!(
        mx_of(json!({"type": "send_msearch", "st": "ssdp:all", "mx": 4000000})),
        u64::from(message::MAX_MX_SECONDS)
    );
    assert_eq!(
        mx_of(json!({"type": "send_msearch", "st": "ssdp:all", "mx": 0})),
        1
    );
    assert!(
        execute(json!({"type": "send_msearch", "st": "ssdp:all", "mx": "three"})).is_err(),
        "a non-numeric MX is a mistake worth reporting, not a value to guess at"
    );
}

/// A bad `target` is rejected where the model can see it, rather than becoming a search that
/// silently never goes anywhere.
#[test]
fn a_target_override_must_be_an_ip_and_port() {
    match execute(json!({
        "type": "send_msearch", "st": "ssdp:all", "target": "192.168.1.1:1900"
    }))
    .expect("a valid target is accepted")
    {
        ClientActionResult::Custom { data, .. } => {
            assert_eq!(data["target"], json!("192.168.1.1:1900"));
        }
        other => panic!("unexpected {other:?}"),
    }

    assert!(execute(json!({"type": "send_msearch", "st": "a", "target": "192.168.1.1"})).is_err());
    assert!(
        execute(json!({"type": "send_msearch", "st": "a", "target": "not an address"})).is_err()
    );

    // Omitted and empty both mean "use the address the client was opened with".
    match execute(json!({"type": "send_msearch", "st": "ssdp:all", "target": ""})).unwrap() {
        ClientActionResult::Custom { data, .. } => assert_eq!(data["target"], json!(null)),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn the_lifecycle_verbs_map_to_their_results() {
    assert!(matches!(
        execute(json!({"type": "wait_for_more"})).unwrap(),
        ClientActionResult::WaitForMore
    ));
    assert!(matches!(
        execute(json!({"type": "disconnect"})).unwrap(),
        ClientActionResult::Disconnect
    ));

    let err = execute(json!({"type": "send_ssdp_response"}))
        .expect_err("a device verb is not a control point verb")
        .to_string();
    assert!(
        err.contains("Unknown SSDP client action"),
        "the model must be told the name is wrong: {err}"
    );
}

/// `CACHE-CONTROL` reaches the model as a number as well as verbatim: asked "is this device
/// still fresh?", a model should not have to parse a header directive first.
#[test]
fn max_age_is_parsed_out_of_cache_control() {
    let with = |value: &str| {
        let raw = format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: {value}\r\n\r\n");
        max_age_of(&message::parse(raw.as_bytes()).unwrap())
    };

    assert_eq!(with("max-age=1800"), Some(1800));
    assert_eq!(with("no-cache, max-age=60"), Some(60));
    assert_eq!(with("max-age = 90"), Some(90));
    assert_eq!(with("no-cache"), None, "no directive is not zero seconds");
    assert_eq!(with("max-age=forever"), None);

    let no_header = message::parse(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n").unwrap();
    assert_eq!(max_age_of(&no_header), None);
}

// ===========================================================================
// Layer 2 & 3 — end to end
// ===========================================================================

/// A `HTTP/1.1 200 OK` in the exact shape UDA 1.1 §1.3.3 requires.
fn search_response(st: &str, usn: &str, location: &str, server: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         DATE: Thu, 04 Sep 2026 10:00:00 GMT\r\n\
         EXT:\r\n\
         LOCATION: {location}\r\n\
         SERVER: {server}\r\n\
         ST: {st}\r\n\
         USN: {usn}\r\n\
         \r\n"
    )
    .into_bytes()
}

/// An `ssdp:alive` announcement, UDA 1.1 §1.2.2.
fn notify_alive(nt: &str, usn: &str, location: &str) -> Vec<u8> {
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         LOCATION: {location}\r\n\
         NT: {nt}\r\n\
         NTS: ssdp:alive\r\n\
         SERVER: Linux/6.1 UPnP/1.1 TestDevice/1.0\r\n\
         USN: {usn}\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Wait for a log line rather than asserting on it straight away: the datagrams cross the
/// socket well before the harness has necessarily drained the child's stdout, so a bare
/// `output_contains` is a race that passes only on a quiet machine.
async fn wait_for_log(client: &helpers::client::NetGetClient, needle: &str) -> bool {
    for _ in 0..150 {
        if client.output_contains(needle).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// **The property that makes SSDP different from every other client here.**
///
/// One search, two devices answering from two different addresses, plus an unsolicited
/// announcement. A client that returned on the first datagram — which is what every other
/// client in this tree correctly does — would report one device on a network of two, and the
/// `expect_calls(2)` on `ssdp_search_response` is what catches that.
///
/// The devices are hand-written here from UDA 1.1. That is deliberate and it is also the
/// limit of what this proves: it is an independent reading of the specification, not an
/// independent implementation of it.
#[tokio::test]
async fn one_search_collects_every_responder_and_hears_an_announcement() -> E2EResult<()> {
    // Two "devices". Only the first is searched; the second answers unprompted, which is
    // exactly what happens on a real multicast network where every device sees the search.
    let device_one = UdpSocket::bind("127.0.0.1:0").await?;
    let device_two = UdpSocket::bind("127.0.0.1:0").await?;
    let device_one_addr = device_one.local_addr()?;

    let config = NetGetConfig::new(format!(
        "discover upnp devices at {device_one_addr} via ssdp and tell me what answers"
    ))
    .with_log_level("debug")
    .with_mock(move |mock| {
        mock.on_instruction_containing("via ssdp")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": device_one_addr.to_string(),
                "base_stack": "ssdp",
                "startup_params": {
                    "bind_address": "127.0.0.1",
                    // Nothing here depends on the group, and a socket bound to loopback
                    // could not send to it anyway.
                    "join_multicast": false,
                    // Long enough that both answers and the announcement land inside one
                    // window even when a hundred tests run together.
                    "response_window_ms": 6000
                },
                "instruction": "Search for every device and report what answers."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ssdp_connected")
            .respond_with_actions(json!([{"type": "send_msearch", "st": "ssdp:all", "mx": 1}]))
            .expect_calls(1)
            .and()
            // Two responders, two events. This count is the whole test.
            .on_event("ssdp_search_response")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(2)
            .and()
            .on_event("ssdp_notify_received")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            .on_event("ssdp_search_complete")
            .respond_with_actions(json!([{"type": "disconnect"}]))
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(config).await?;

    // --- device one receives the search and answers it ---
    let mut buf = vec![0u8; 4096];
    let (n, control_point) =
        tokio::time::timeout(Duration::from_secs(30), device_one.recv_from(&mut buf))
            .await
            .map_err(|_| "no M-SEARCH arrived at the device within 30s")??;

    let search =
        message::parse(&buf[..n]).expect("what the client sent must be a valid HTTPU message");
    assert_eq!(search.method.as_deref(), Some("M-SEARCH"));
    assert_eq!(search.header("MAN"), Some("\"ssdp:discover\""));
    assert_eq!(search.header("ST"), Some("ssdp:all"));
    assert_eq!(search.mx(), Some(1));
    assert_eq!(
        search.header("HOST"),
        Some(device_one_addr.to_string().as_str()),
        "a unicast search names the device it is aimed at"
    );

    device_one
        .send_to(
            &search_response(
                MEDIA_SERVER,
                &format!("{DEVICE_UUID}::{MEDIA_SERVER}"),
                "http://127.0.0.1:8080/description.xml",
                "Linux/6.1 UPnP/1.1 TestMediaServer/1.0",
            ),
            control_point,
        )
        .await?;

    // --- device two answers the same search, from a different address ---
    device_two
        .send_to(
            &search_response(
                MEDIA_RENDERER,
                &format!("{OTHER_UUID}::{MEDIA_RENDERER}"),
                "http://127.0.0.1:8081/desc.xml",
                "Linux/6.1 UPnP/1.1 TestRenderer/1.0",
            ),
            control_point,
        )
        .await?;

    // --- and announces itself unprompted ---
    device_two
        .send_to(
            &notify_alive(
                MEDIA_RENDERER,
                &format!("{OTHER_UUID}::{MEDIA_RENDERER}"),
                "http://127.0.0.1:8081/desc.xml",
            ),
            control_point,
        )
        .await?;

    assert!(
        wait_for_log(&client, "2 responder(s)").await,
        "the search must report BOTH devices, not the first one. Output: {:?}",
        client.get_output().await
    );
    assert!(
        client.output_contains(MEDIA_SERVER).await,
        "the first device's type must reach the log"
    );
    assert!(
        client.output_contains(MEDIA_RENDERER).await,
        "the second device's type must reach the log"
    );
    assert!(
        wait_for_log(&client, "ssdp:alive").await,
        "the unsolicited announcement must be surfaced too. Output: {:?}",
        client.get_output().await
    );

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

/// A repeat answer from a device already reported is one device, not two.
///
/// Real devices retransmit; a control point that counted each retransmission would report a
/// network of duplicates. The dedupe key is address **and** USN, so a device answering
/// `ssdp:all` with several distinct services still counts once per service — which is why
/// this test sends the same USN twice and a second, different USN from the same address, and
/// expects two responders rather than one or three.
#[tokio::test]
async fn a_retransmitted_answer_is_the_same_device() -> E2EResult<()> {
    let device = UdpSocket::bind("127.0.0.1:0").await?;
    let device_addr = device.local_addr()?;

    let config = NetGetConfig::new(format!(
        "discover upnp devices at {device_addr} via ssdp and tell me what answers"
    ))
    .with_log_level("debug")
    .with_mock(move |mock| {
        mock.on_instruction_containing("via ssdp")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": device_addr.to_string(),
                "base_stack": "ssdp",
                "startup_params": {
                    "bind_address": "127.0.0.1",
                    "join_multicast": false,
                    "response_window_ms": 6000
                },
                "instruction": "Search for every device and report what answers."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ssdp_connected")
            .respond_with_actions(json!([{"type": "send_msearch", "st": "ssdp:all", "mx": 1}]))
            .expect_calls(1)
            .and()
            // Three datagrams arrive; two are distinct services, so two events.
            .on_event("ssdp_search_response")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(2)
            .and()
            .on_event("ssdp_search_complete")
            .respond_with_actions(json!([{"type": "disconnect"}]))
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(config).await?;

    let mut buf = vec![0u8; 4096];
    let (_, control_point) =
        tokio::time::timeout(Duration::from_secs(30), device.recv_from(&mut buf))
            .await
            .map_err(|_| "no M-SEARCH arrived at the device within 30s")??;

    let first = search_response(
        MEDIA_SERVER,
        &format!("{DEVICE_UUID}::{MEDIA_SERVER}"),
        "http://127.0.0.1:8080/description.xml",
        "Linux/6.1 UPnP/1.1 TestMediaServer/1.0",
    );
    // Same device, same service, sent twice: one responder.
    device.send_to(&first, control_point).await?;
    device.send_to(&first, control_point).await?;
    // Same device, a different service: genuinely a second result.
    device
        .send_to(
            &search_response(
                "upnp:rootdevice",
                &format!("{DEVICE_UUID}::upnp:rootdevice"),
                "http://127.0.0.1:8080/description.xml",
                "Linux/6.1 UPnP/1.1 TestMediaServer/1.0",
            ),
            control_point,
        )
        .await?;

    assert!(
        wait_for_log(&client, "2 responder(s), 1 duplicate(s)").await,
        "the repeat must be counted as a duplicate, not as a third device. Output: {:?}",
        client.get_output().await
    );

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

/// The two halves of NetGet, talking to each other over unicast loopback.
///
/// **Read what this proves carefully.** The peer is NetGet's own SSDP server, which shares
/// this client's HTTPU codec and was written in the same pass. It is same-project evidence:
/// it shows the halves agree, and it would not catch a mistake both halves make. It is
/// exactly the circular-evidence class the root `CLAUDE.md` names, and it is why the client
/// is rated `Experimental`.
///
/// It is still worth having: it is the only test in which the thing answering is a real
/// server process making real decisions through a model, rather than a fixed string this
/// file wrote.
#[tokio::test]
async fn discovers_netgets_own_ssdp_server() -> E2EResult<()> {
    let server_config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via ssdp as a UPnP MediaServer at \
         http://127.0.0.1:8080/description.xml",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("via ssdp")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "ssdp",
                // Keep the device's MX jitter short: the client's window is what bounds the
                // test, and a faithful multi-second wait would only make it slower.
                "startup_params": {"max_response_delay_ms": 100},
                "instruction": "You are a UPnP MediaServer. Answer searches for it."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ssdp_msearch")
            .respond_with_actions(json!([{
                "type": "send_ssdp_response",
                "st": MEDIA_SERVER,
                "usn": format!("{DEVICE_UUID}::{MEDIA_SERVER}"),
                "location": "http://127.0.0.1:8080/description.xml",
                "server": "Linux/6.1 UPnP/1.1 NetGet-SSDP/1.0",
                "cache_control_max_age": 1800
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    let device_addr = format!("127.0.0.1:{}", server.port);

    let client_config = NetGetConfig::new(format!(
        "discover upnp devices at {device_addr} via ssdp and tell me what answers"
    ))
    .with_log_level("debug")
    .with_mock({
        let device_addr = device_addr.clone();
        move |mock| {
            mock.on_instruction_containing("via ssdp")
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "remote_addr": device_addr,
                    "base_stack": "ssdp",
                    "startup_params": {
                        "bind_address": "127.0.0.1",
                        "join_multicast": false,
                        "response_window_ms": 6000
                    },
                    "instruction": "Search for a MediaServer and report what answers."
                }]))
                .expect_calls(1)
                .and()
                .on_event("ssdp_connected")
                .respond_with_actions(json!([{
                    "type": "send_msearch", "st": MEDIA_SERVER, "mx": 1
                }]))
                .expect_calls(1)
                .and()
                .on_event("ssdp_search_response")
                .respond_with_actions(json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
                .on_event("ssdp_search_complete")
                .respond_with_actions(json!([{"type": "disconnect"}]))
                .expect_calls(1)
                .and()
        }
    });

    let client = helpers::start_netget_client(client_config).await?;

    assert!(
        wait_for_log(&client, &format!("{DEVICE_UUID}::{MEDIA_SERVER}")).await,
        "the client must report the USN NetGet's own server advertised. Output: {:?}",
        client.get_output().await
    );
    assert!(
        client
            .output_contains("http://127.0.0.1:8080/description.xml")
            .await,
        "the LOCATION must reach the log — NetGet never fetches it, so surfacing it is the \
         whole of what discovery delivers"
    );
    assert!(
        wait_for_log(&client, "1 responder(s)").await,
        "the search must complete with exactly one responder. Output: {:?}",
        client.get_output().await
    );

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    client.stop().await?;
    server.stop().await?;
    Ok(())
}
