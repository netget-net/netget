//! End-to-end NTP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with NTP prompts and validate the replies
//! byte by byte, plus with `rsntp` acting as a real SNTP client.
//!
//! Every assertion here used to be a `println!`. `test_ntp_basic_query` and
//! `test_ntp_time_sync` caught `rsntp`'s error, printed "this may be expected if LLM doesn't
//! fully implement NTP", then fell back to a raw socket whose three outcomes — a response, an
//! I/O error, and a timeout — were all printed and none asserted.
//! `test_ntp_stratum_levels` parsed the stratum out of byte 1 and printed it without
//! comparing it to anything. The suite therefore passed whether the server answered
//! correctly, answered garbage, or never answered at all.
//!
//! Two things make the difference concrete:
//!
//! - `rsntp` must now *succeed*. Its checks are the ones that matter for interoperability:
//!   the reply's originate timestamp must equal the request's transmit timestamp verbatim,
//!   mode must be server, stratum must not be 0, transmit must be non-zero, and the version
//!   must be the 4 it sent. A blocking `SntpClient` cannot be used from a `#[tokio::test]`
//!   here — the mock Ollama server is in-process, so blocking the runtime deadlocks the very
//!   LLM call the reply depends on, which is likely why the old fallback path existed at all.
//!   `AsyncSntpClient` is used throughout.
//! - The raw test decodes all 48 bytes and compares every field to what the handler asked
//!   for, including the origin-timestamp echo and the version echo.
//!
//! LLM call budget: 3 startups + 4 request events = 7 calls.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use rsntp::AsyncSntpClient;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// A decoded 48-byte NTP packet (RFC 5905 §7.3).
#[derive(Debug)]
struct NtpPacket {
    leap_indicator: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: u8,
    precision: i8,
    root_delay_fixed: u32,
    root_dispersion_fixed: u32,
    reference_id: [u8; 4],
    reference_timestamp: u64,
    origin_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
}

impl NtpPacket {
    fn parse(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            48,
            "an NTP reply is exactly 48 bytes; got {}",
            bytes.len()
        );
        let ts = |offset: usize| -> u64 {
            u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        Self {
            leap_indicator: (bytes[0] >> 6) & 0x03,
            version: (bytes[0] >> 3) & 0x07,
            mode: bytes[0] & 0x07,
            stratum: bytes[1],
            poll: bytes[2],
            precision: bytes[3] as i8,
            root_delay_fixed: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            root_dispersion_fixed: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            reference_id: bytes[12..16].try_into().unwrap(),
            reference_timestamp: ts(16),
            origin_timestamp: ts(24),
            receive_timestamp: ts(32),
            transmit_timestamp: ts(40),
        }
    }

    /// The whole-seconds half of a 64-bit NTP timestamp, as Unix seconds.
    fn unix_seconds(timestamp: u64) -> i64 {
        (timestamp >> 32) as i64 - NTP_UNIX_OFFSET as i64
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs()
}

/// Build a client request carrying a distinctive transmit timestamp.
///
/// The fraction is deliberately not zero: the server must copy all 64 bits into the reply's
/// origin timestamp, and a zero fraction would let a server that only copies the seconds
/// pass.
fn ntp_request(version: u8, transmit_timestamp: u64) -> Vec<u8> {
    let mut request = vec![0u8; 48];
    request[0] = ((version & 0x07) << 3) | 0x03; // LI=0, version, mode 3 (client)
    request[40..48].copy_from_slice(&transmit_timestamp.to_be_bytes());
    request
}

/// Send one request and return the reply, failing the test if none arrives.
async fn query(socket: &UdpSocket, address: &str, request: &[u8]) -> E2EResult<NtpPacket> {
    socket.send_to(request, address).await?;

    let mut buffer = vec![0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buffer))
        .await
        .map_err(|_| "no NTP reply within 15s")??;

    // The pcap oracle. `NtpPacket::parse` below is this test file's own reading of
    // RFC 5905, and rsntp is a client that checks a handful of fields it cares
    // about; Wireshark's `ntp` dissector decodes the whole packet — leap indicator,
    // mode, stratum, poll and precision as signed exponents, reference id, and every
    // 64-bit timestamp — and objects to a packet that is not 48 bytes or whose
    // fields are outside the ranges the RFC allows.
    crate::helpers::pcap_oracle::PcapOracle::udp("ntp")
        .to_server(request)
        .from_server(&buffer[..n])
        .assert_clean();

    Ok(NtpPacket::parse(&buffer[..n]))
}

/// Assertions every reply must satisfy, whatever the handler asked for.
fn assert_reply_envelope(reply: &NtpPacket, request_version: u8, request_transmit: u64) {
    assert_eq!(
        reply.mode, 4,
        "RFC 5905 §7.3: a server answers in mode 4; rsntp, chrony and ntpdate all \
         discard anything else"
    );
    assert_eq!(
        reply.version, request_version,
        "RFC 5905 §7.3: the reply must use the version the client used"
    );
    assert_eq!(
        reply.origin_timestamp, request_transmit,
        "RFC 5905 §8: the origin timestamp must be a verbatim copy of the client's \
         transmit timestamp. A client that does not find its own value here drops the \
         reply, which looks exactly like a timeout"
    );
    assert_ne!(
        reply.transmit_timestamp, 0,
        "a zero transmit timestamp is rejected outright"
    );
    assert_ne!(
        reply.stratum, 0,
        "stratum 0 means Kiss-o'-Death and is not a time answer"
    );

    // The server fills receive and transmit from its own clock, in that order.
    assert!(
        reply.receive_timestamp <= reply.transmit_timestamp,
        "receive ({}) must not be later than transmit ({})",
        reply.receive_timestamp,
        reply.transmit_timestamp
    );

    // Only the seconds half is checked: `NtpProtocol::get_current_ntp_time` builds its
    // timestamps from `Duration::as_secs()` and leaves the 32-bit fraction zero, so the
    // server's time resolution is one second. Clients accept that — it costs accuracy, not
    // compatibility — so this is recorded here rather than asserted against.
    let now = unix_now() as i64;
    for (what, timestamp) in [
        ("receive", reply.receive_timestamp),
        ("transmit", reply.transmit_timestamp),
        ("reference", reply.reference_timestamp),
    ] {
        let seconds = NtpPacket::unix_seconds(timestamp);
        assert!(
            (seconds - now).abs() < 300,
            "the {what} timestamp decodes to Unix {seconds}, {} seconds from now — \
             the server is using the wrong epoch or the wrong format",
            seconds - now
        );
    }
}

/// A real SNTP client must be able to synchronize against the server.
///
/// The old body treated `rsntp` failing as an acceptable outcome. It is the single most
/// informative signal in this suite: `rsntp` validates the origin-timestamp echo, the mode,
/// the version and the stratum, so its success means an off-the-shelf client would work.
#[tokio::test]
async fn test_ntp_basic_query() -> E2EResult<()> {
    println!("\n=== E2E Test: NTP Basic Query ===");

    let prompt = "listen on port {AVAILABLE_PORT} via ntp. Respond to NTP time requests with the current system time. Use stratum 2";

    let config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("ntp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NTP",
                        "instruction": "NTP server stratum 2"
                    }
                ]))
                .expect_calls(1)
                .and()
                // The server copies the client's transmit timestamp into the reply itself,
                // so unlike DNS or DHCP this mock needs nothing from the event.
                .on_event("ntp_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_ntp_time_response",
                        "stratum": 2,
                        "poll": 6
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    println!("NTP server started on port {}", server.port);

    let mut client = AsyncSntpClient::new();
    client.set_timeout(Duration::from_secs(20));
    let address = format!("127.0.0.1:{}", server.port);

    let result = client
        .synchronize(address.clone())
        .await
        .map_err(|e| format!("rsntp refused the reply from {address}: {e}"))?;

    println!("  Clock offset: {:?}", result.clock_offset());
    println!("  Round trip delay: {:?}", result.round_trip_delay());

    assert_eq!(
        result.stratum(),
        2,
        "the stratum the handler chose must reach the client"
    );
    assert_eq!(
        result.leap_indicator(),
        rsntp::LeapIndicator::NoWarning,
        "the default leap indicator is 'no warning'"
    );

    // The server answers from its own clock, which is this machine's clock, so a client on
    // the same host must measure an offset near zero. A server returning a constant or an
    // epoch-confused timestamp fails here even though rsntp accepted the packet.
    let offset = result.clock_offset().as_secs_f64();
    assert!(
        offset.abs() < 5.0,
        "clock offset against our own clock is {offset}s; the server is not returning \
         the current time"
    );
    let delay = result.round_trip_delay().as_secs_f64();
    assert!(
        (0.0..30.0).contains(&delay),
        "implausible round-trip delay over loopback: {delay}s"
    );

    println!("✓ rsntp synchronized against the server");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// A stratum 1 answer carries an ASCII reference identifier, which `rsntp` decodes.
///
/// For stratum 2 and above the same four bytes are read as an IPv4 address, so stratum 1 is
/// the case where the handler's `reference_id` is observable through a real client.
#[tokio::test]
async fn test_ntp_time_sync() -> E2EResult<()> {
    println!("\n=== E2E Test: NTP Time Synchronization ===");

    let prompt = "listen on port {AVAILABLE_PORT} via ntp. Act as a stratum 1 NTP server. Respond with accurate current time in NTP format";

    let config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("ntp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NTP",
                        "instruction": "NTP server stratum 1"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("ntp_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_ntp_time_response",
                        "stratum": 1,
                        "reference_id": "GPS."
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    println!("NTP server started on port {}", server.port);

    let mut client = AsyncSntpClient::new();
    client.set_timeout(Duration::from_secs(20));
    let address = format!("127.0.0.1:{}", server.port);

    let result = client
        .synchronize(address.clone())
        .await
        .map_err(|e| format!("rsntp refused the reply from {address}: {e}"))?;

    assert_eq!(
        result.stratum(),
        1,
        "a stratum 1 answer must be reported as stratum 1"
    );
    assert_eq!(
        result.reference_identifier().to_string(),
        "GPS.",
        "the reference identifier the handler chose must reach the client"
    );

    // rsntp exposes the server's time; it must agree with ours to within a few seconds.
    let server_time = result
        .datetime()
        .unix_timestamp()
        .map_err(|e| format!("server time is not representable: {e:?}"))?
        .as_secs() as i64;
    let delta = server_time - unix_now() as i64;
    assert!(
        delta.abs() < 5,
        "server time is {delta}s away from ours; it is not reporting the current time"
    );

    println!("✓ Stratum 1 reference identifier and time verified");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Decode every field of a raw reply, and prove `ignore_request` really sends nothing.
///
/// One server answers two requests that differ only in NTP version, so the mock can give
/// each a different handler: the v3 request gets a fully specified time response, the v4
/// request gets `ignore_request`. The second half is the fail-open check — a protocol that
/// answered anyway when told not to would be indistinguishable from one that works.
#[tokio::test]
async fn test_ntp_stratum_levels() -> E2EResult<()> {
    println!("\n=== E2E Test: NTP Stratum Levels ===");

    let prompt = "listen on port {AVAILABLE_PORT} via ntp. Act as a stratum 3 NTP server. Include reference identifier 'LOCL'";

    let config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("ntp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NTP",
                        "instruction": "NTP server stratum 3"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Rules are tried in order, so the version-specific ones come first.
                .on_event("ntp_request")
                .and_event_data_contains("client_version", "3")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_ntp_time_response",
                        "stratum": 3,
                        "reference_id": "LOCL",
                        "leap_indicator": 1,
                        "poll": 10,
                        "precision": -18,
                        "root_delay": 0.5,
                        "root_dispersion": 0.25
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("ntp_request")
                .and_event_data_contains("client_version", "4")
                .respond_with_actions(serde_json::json!([
                    { "type": "ignore_request" }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    println!("NTP server started on port {}", server.port);

    let address = format!("127.0.0.1:{}", server.port);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // A v3 request with a transmit timestamp whose fraction is distinctive.
    let request_transmit = ((unix_now() + NTP_UNIX_OFFSET) << 32) | 0xDEAD_BEEF;
    let reply = query(&socket, &address, &ntp_request(3, request_transmit)).await?;
    println!("  Decoded reply: {reply:?}");

    assert_reply_envelope(&reply, 3, request_transmit);

    // Every field the handler set must be on the wire exactly as asked.
    assert_eq!(reply.stratum, 3, "the handler asked for stratum 3");
    assert_eq!(
        &reply.reference_id,
        b"LOCL",
        "reference_id must occupy bytes 12-15 as four ASCII characters, got {:?}",
        String::from_utf8_lossy(&reply.reference_id)
    );
    assert_eq!(reply.leap_indicator, 1, "leap_indicator lives in bits 7-6");
    assert_eq!(reply.poll, 10, "poll lives in byte 2");
    assert_eq!(
        reply.precision, -18,
        "precision is a *signed* byte; an unsigned round-trip would read 238 here"
    );
    // Root delay and dispersion are 16.16 fixed point, so 0.5s is 0x8000 and 0.25s 0x4000.
    assert_eq!(
        reply.root_delay_fixed, 0x0000_8000,
        "root_delay 0.5s must encode as 16.16 fixed point"
    );
    assert_eq!(
        reply.root_dispersion_fixed, 0x0000_4000,
        "root_dispersion 0.25s must encode as 16.16 fixed point"
    );

    println!("✓ Every field of the stratum 3 reply matched the handler's action");

    // Now the v4 request, which the handler answers with `ignore_request`. Silence is the
    // correct behaviour and must be observable: a fallback reply here would mean the
    // protocol answers even when the model told it not to.
    let ignored_transmit = ((unix_now() + NTP_UNIX_OFFSET) << 32) | 0x0BAD_F00D;
    socket
        .send_to(&ntp_request(4, ignored_transmit), &address)
        .await?;

    let mut buffer = vec![0u8; 128];
    match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await {
        Err(_) => println!("✓ ignore_request produced no packet, as instructed"),
        Ok(Ok((n, _))) => panic!(
            "ignore_request must send nothing, but {n} bytes arrived: {}",
            hex::encode(&buffer[..n])
        ),
        Ok(Err(e)) => return Err(e.into()),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}
