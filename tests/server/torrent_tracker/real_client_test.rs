//! The BitTorrent tracker against a real, independent third-party client: **aria2c 1.37.0**.
//!
//! # Why this test exists
//!
//! Every other test in this directory drives the tracker with `reqwest` or a raw `TcpStream`
//! and decodes the reply with `serde_bencode` — which is the crate the *server* encodes with.
//! `metadata().e2e_testing` said so in as many words: that is one crate round-tripping through
//! itself, plus an independent *reading* of BEP 3, and it is the `rss`-before-`feed-rs`
//! situation. It proves the tracker answers; it cannot prove a real BitTorrent client can use
//! the answer.
//!
//! aria2 is a C++ BitTorrent implementation that has never seen this repository. It builds its
//! own announce URL, and — the part that matters — it must decode our **compact** peer list:
//! a bencode byte string carrying six bytes per peer, four for the IPv4 address and two for a
//! big-endian port. Nothing in that encoding is self-describing, so a wrong byte order, a wrong
//! stride or a bencode length that disagrees with the payload produces either no peers or the
//! wrong ones. The test asserts aria2 dialled the exact two peers the tracker named.
//!
//! # Not circular
//!
//! The server hand-rolls its HTTP (a raw `TcpListener`, `parse_http_request` in
//! `src/server/torrent_tracker/mod.rs`) and builds its bodies with `serde_bencode`. aria2 is an
//! unrelated binary on `PATH` that links neither. Nothing is shared between the two sides.
//!
//! # What aria2 pins that a hand-written client cannot
//!
//! `compact=1` is **hardcoded** in aria2's announce format string — it never asks for the
//! dictionary form. So the first test below exercises the compact encoder specifically, which
//! is the branch a real swarm always takes and which no existing test drives against a real
//! client. The second test asserts aria2's own parse of a `failure reason` dict, which it
//! prints verbatim.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tempfile::TempDir;

/// The info hash in the magnet link below, and therefore the one the tracker must see.
///
/// The server percent-decodes `info_hash` and hex-encodes it, so this exact lowercase string is
/// what reaches the event — matching on it proves aria2's 20 raw bytes survived that round trip.
const INFO_HASH: &str = "0123456789abcdef0123456789abcdef01234567";

/// Peers the tracker hands back, chosen in a range aria2 will genuinely try to dial.
const PEER_ONE: &str = "10.0.0.1:6881";
const PEER_TWO: &str = "10.0.0.2:6882";

/// Fail — never skip — when aria2c is missing.
fn require_aria2c() -> E2EResult<()> {
    match std::process::Command::new("aria2c")
        .arg("--version")
        .output()
    {
        Ok(out) if out.status.success() => {
            let v = String::from_utf8_lossy(&out.stdout);
            println!("{}", v.lines().next().unwrap_or("aria2c present"));
            Ok(())
        }
        Ok(out) => Err(format!(
            "`aria2c --version` exited {}: this test's whole point is driving a real \
             BitTorrent client",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "aria2c not available ({e}): this test's whole point is driving a real BitTorrent \
             client against NetGet's tracker, and skipping it would leave the tracker's \
             maturity rating resting on `serde_bencode` decoding what `serde_bencode` encoded. \
             Install it with `brew install aria2` (or your distribution's aria2 package)."
        )
        .into()),
    }
}

/// Run aria2c against `port` as the only tracker, and return everything it logged.
///
/// DHT, IPv6 DHT and local peer discovery are all disabled so the tracker is aria2's **only**
/// possible source of peers — otherwise a peer it found elsewhere would be indistinguishable
/// from one we returned, and the assertion would be vacuous.
///
/// aria2 is expected to exit non-zero: it is given a magnet for a swarm that does not exist, so
/// after announcing it fails to fetch metadata from the unreachable peers and gives up. The
/// download is not the point; the announce round trip is, and the exit status is deliberately
/// not asserted.
async fn run_aria2c(port: u16, dir: &std::path::Path) -> E2EResult<String> {
    let magnet =
        format!("magnet:?xt=urn:btih:{INFO_HASH}&tr=http%3A%2F%2F127.0.0.1%3A{port}%2Fannounce");

    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("aria2c")
            .arg(&magnet)
            .arg("--enable-dht=false")
            .arg("--enable-dht6=false")
            .arg("--bt-enable-lpd=false")
            .arg("--console-log-level=info")
            .arg("--bt-stop-timeout=12")
            .arg("--summary-interval=0")
            .arg(format!("--dir={}", dir.display()))
            .output(),
    )
    .await
    .map_err(|_| "aria2c did not finish within 120s")??;

    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(log)
}

#[tokio::test]
async fn test_tracker_compact_peers_are_decoded_by_real_aria2c() -> E2EResult<()> {
    println!("\n=== E2E Test: aria2c announces to NetGet's tracker and dials the peers ===");
    require_aria2c()?;

    let prompt = "Listen on port {AVAILABLE_PORT} via torrent-tracker. Answer every announce \
                  with the lab swarm's peers";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // Matching on BOTH fields is the server-side half of the assertion. `info_hash`
            // pins that aria2's 20 raw bytes were percent-decoded and hex-encoded correctly;
            // `compact` pins that aria2's hardcoded `compact=1` reached the event as 1. If
            // either is wrong the rule does not match, the tracker answers nothing, and the
            // client-side assertions below fail too — loudly, in both halves.
            .on_event("tracker_announce_request")
            .and_event_data_contains("info_hash", INFO_HASH)
            .and_event_data_contains("compact", "1")
            .respond_with_actions(serde_json::json!([{
                "type": "send_announce_response",
                "interval": 1800,
                "complete": 10,
                "incomplete": 5,
                "compact": 1,
                "peers": [
                    {"ip": "10.0.0.1", "port": 6881},
                    {"ip": "10.0.0.2", "port": 6882}
                ]
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via torrent-tracker")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Tracker",
                    "instruction": "Answer announces with the lab swarm's peers"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("tracker on 127.0.0.1:{}", server.port);

    let dir = TempDir::new()?;
    let log = run_aria2c(server.port, dir.path()).await?;

    // THE assertion. aria2 only prints these lines for peers it decoded out of the compact
    // byte string: four address octets and a big-endian port, six bytes apiece, with nothing
    // in the encoding to tell it where one peer ends and the next begins except our length.
    // Getting both back, with the right ports on the right addresses, means the encoder is
    // right in a way `serde_bencode` decoding `serde_bencode` could never show.
    assert!(
        log.contains(&format!("Connecting to {PEER_ONE}")),
        "aria2 never dialled {PEER_ONE}, so it did not decode the first compact peer. Its log \
         was:\n{log}"
    );
    assert!(
        log.contains(&format!("Connecting to {PEER_TWO}")),
        "aria2 never dialled {PEER_TWO}, so it did not decode the second compact peer — a \
         stride or length error would lose exactly this one. Its log was:\n{log}"
    );
    assert!(
        !log.contains("Tracker returned failure reason"),
        "aria2 read our announce response as a tracker failure:\n{log}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The refusal path, read back by the same real client.
///
/// `send_error_response` is the tracker's only way to say no, and it says it as a bencoded
/// `failure reason` dict inside an HTTP **200** — a shape that is wrong in every other
/// protocol and is what BEP 3 specifies here. aria2 prints the reason verbatim, so this is the
/// cleanest possible proof that a third-party implementation parsed our bencode rather than
/// merely receiving bytes.
#[tokio::test]
async fn test_tracker_failure_reason_is_read_back_by_real_aria2c() -> E2EResult<()> {
    println!("\n=== E2E Test: aria2c reads NetGet's bencoded failure reason ===");
    require_aria2c()?;

    // Deliberately distinctive: a substring match on it cannot be satisfied by anything aria2
    // or NetGet would say on its own.
    const REASON: &str = "netget refuses this announce";

    let prompt = "Listen on port {AVAILABLE_PORT} via torrent-tracker. Refuse every announce";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_event("tracker_announce_request")
            .and_event_data_contains("info_hash", INFO_HASH)
            .respond_with_actions(serde_json::json!([{
                "type": "send_error_response",
                "failure_reason": REASON
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via torrent-tracker")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Tracker",
                    "instruction": "Refuse every announce"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let dir = TempDir::new()?;
    let log = run_aria2c(server.port, dir.path()).await?;

    assert!(
        log.contains(&format!("Tracker returned failure reason: {REASON}")),
        "aria2 did not parse our bencoded `failure reason` dict out of the HTTP 200. Its log \
         was:\n{log}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
