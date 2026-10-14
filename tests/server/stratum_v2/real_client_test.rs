//! NetGet's Stratum V2 pool against **SRI's `mining_device`** (sv2-apps v0.8.0, built from its
//! own `noise_sv2`, `codec_sv2` and `binary_sv2` — code NetGet does not link). The device runs
//! the Noise NX handshake and checks NetGet's certificate against the authority key it was given,
//! sets up the connection, opens a standard channel, takes the job and prev hash the model chose,
//! hashes with its own SHA-256 and submits what meets the target; NetGet rebuilds each header
//! and checks it before the model credits odd sequence numbers and refuses even ones. The device
//! prints every hash it found, and each must be the hash NetGet computed for that share — the two
//! agreeing byte for byte on the header. Pointed at another authority key, the device must
//! refuse the handshake. `install_peers.py` prints `NETGET_SV2_MINING_DEVICE`; the test fails
//! rather than skips without it. No LLM calls: a python policy is the model.
use super::support;
use netget::server::stratum_v2::wire;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

const DIFFICULTY: f64 = 0.0005;

fn mining_device() -> String {
    let v = std::env::var("NETGET_SV2_MINING_DEVICE").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_SV2_MINING_DEVICE is required: python3 tests/server/stratum_v2/install_peers.py <dir> and export what it prints"
    );
    v
}

/// The device's log line without its terminal colours.
fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// "… with hash: [70, 246, …]" — the raw hash bytes the device printed, as RPC shows hashes.
fn printed_hash(line: &str) -> Option<String> {
    let list = line.split("with hash: [").nth(1)?.split(']').next()?;
    let bytes: Vec<u8> = list
        .split(',')
        .map(|b| b.trim().parse().ok())
        .collect::<Option<_>>()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(wire::display_hex(&bytes))
}

fn device(port: u16, key: &str, user: &str) -> tokio::process::Child {
    tokio::process::Command::new(mining_device())
        .arg("--address-pool")
        .arg(format!("127.0.0.1:{port}"))
        .args(["--pubkey-pool", key, "--id-user", user, "--cores", "1"])
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("mining_device")
}

#[tokio::test]
async fn sri_mining_device_mines_against_netget() {
    let (state, id, port) = support::start(
        support::policy(DIFFICULTY),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;
    let mut miner = device(port, support::PUBLIC, "netget.device1");
    let mut lines = BufReader::new(miner.stdout.take().unwrap()).lines();
    let mut seen = Vec::new();
    let mut found = Vec::new();
    let (mut accepted, mut refused) = (0, 0);
    let outcome = tokio::time::timeout(Duration::from_secs(120), async {
        while let Ok(Some(l)) = lines.next_line().await {
            let l = plain(&l);
            if let Some(h) = printed_hash(&l) {
                found.push(h);
            }
            if l.contains("Received SubmitSharesSuccess") {
                accepted += 1;
            }
            if l.contains("Received SubmitSharesError") {
                assert!(
                    l.contains("policy-rejected"),
                    "NetGet refused one of the device's shares on its own: {l}\n{}",
                    seen.join("\n")
                );
                refused += 1;
            }
            seen.push(l);
            if accepted >= 2 && refused >= 1 {
                return true;
            }
        }
        // The device exited before it had shares credited and refused.
        false
    })
    .await;
    // Stop the device, then read what it printed before it died: a share NetGet is still
    // answering was printed before it was sent.
    let _ = miner.kill().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(l)) = lines.next_line().await {
            if let Some(h) = printed_hash(&plain(&l)) {
                found.push(h);
            }
        }
    })
    .await;
    let log = seen.join("\n");
    assert!(
        outcome == Ok(true),
        "mining_device had no two shares credited and one refused:\n{log}"
    );
    assert!(
        log.contains("Received `SetupConnectionSuccess`: version=2"),
        "{log}"
    );
    assert!(log.contains("channel opened with"), "{log}");

    let setup = support::events(&state, id, "stratum_v2_setup_connection").await;
    assert_eq!(setup.len(), 1, "{setup:?}");
    assert_eq!(
        setup[0]["flags"],
        json!(["REQUIRES_STANDARD_JOBS"]),
        "{setup:?}"
    );
    let open = support::events(&state, id, "stratum_v2_open_channel").await;
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0]["user_identity"], "netget.device1", "{open:?}");
    assert!(
        open[0]["nominal_hash_rate"].as_f64().unwrap() > 0.0,
        "{open:?}"
    );

    // Every share the model was asked about is one the device found, by the same hash.
    let shares = support::events(&state, id, "stratum_v2_share").await;
    assert!(shares.len() >= 3, "{shares:?}");
    for s in &shares {
        let hash = s["hash"].as_str().unwrap();
        assert!(
            found.iter().any(|h| h == hash),
            "NetGet's hash {hash} is not one the device printed: {found:?}"
        );
        assert!(s["share_difficulty"].as_f64().unwrap() >= DIFFICULTY, "{s}");
        assert!(
            (s["difficulty"].as_f64().unwrap() / DIFFICULTY - 1.0).abs() < 1e-9,
            "{s}"
        );
        assert_eq!(s["user_identity"], "netget.device1");
        assert_eq!(s["channel_kind"], "standard");
    }
}

#[tokio::test]
async fn sri_mining_device_refuses_a_pool_its_key_did_not_sign() {
    let (state, id, port) = support::start(
        support::policy(DIFFICULTY),
        json!({"authority_secret_key": support::SECRET}),
    )
    .await;
    // The specification's example key: a valid key, but not the one that signed this pool.
    let mut miner = device(
        port,
        "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh",
        "netget.device2",
    );
    let status = tokio::time::timeout(Duration::from_secs(60), miner.wait())
        .await
        .expect("mining_device kept going against a pool whose certificate it cannot verify")
        .unwrap();
    let mut out = String::new();
    if let Some(mut stdout) = miner.stdout.take() {
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stdout, &mut out).await;
    }
    if let Some(mut stderr) = miner.stderr.take() {
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut out).await;
    }
    let out = plain(&out);
    assert!(!status.success(), "{out}");
    assert!(out.contains("InvalidCertificate"), "{out}");
    assert!(!out.contains("SetupConnectionSuccess"), "{out}");
    assert_eq!(support::model_calls(&state, id).await, 0);
}
