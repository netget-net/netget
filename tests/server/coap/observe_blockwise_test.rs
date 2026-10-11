//! Observe (RFC 7641) and Block-wise transfer (RFC 7959) on NetGet's CoAP server, against two
//! independent clients that share nothing with `src/server/coap/` or with each other:
//!
//! - libcoap's **`coap-client`** (C), the client CoAP's Stable rating already rests on;
//! - **aiocoap** 0.4 (Python, its own codec and its own observation and block-wise state
//!   machines), through `peer/aiocoap_peer.py`.
//!
//! Each client:
//!
//! 1. **observes** `/temp`, and receives the two notifications the handler pushes with
//!    `coap_notify` when another request PUTs a new value — the action a model takes when a
//!    write changes state somebody observes;
//! 2. **GETs** `/big`, a 3000-byte representation NetGet can only send as Block2 blocks, and
//!    reassembles it byte for byte — while the handler is asked **once**, because the later
//!    blocks are served from the answer it already gave;
//! 3. **PUTs** 3000 bytes to `/upload`, which it can only send as Block1 blocks, and the handler
//!    sees the body **whole**, once, with the block count.
//!
//! No model: a script handler answers everything (`observe_support.rs`). Neither client is
//! optional — a missing `coap-client` or `NETGET_AIOCOAP_PYTHON` fails the test.

use super::observe_support::{body, Device};
use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

fn aiocoap_python() -> String {
    let v = std::env::var("NETGET_AIOCOAP_PYTHON").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_AIOCOAP_PYTHON is required: a python with aiocoap 0.4 installed \
         (python3 -m venv v && v/bin/pip install aiocoap==0.4.12). This test is half the \
         evidence for CoAP Observe and Block-wise and does not skip."
    );
    v
}

/// Run `coap-client` to completion. Fails, never skips, when libcoap is absent.
async fn coap_client(args: &[&str]) -> (String, String) {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        Command::new("coap-client")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("coap-client {args:?} did not finish"))
    .unwrap_or_else(|e| {
        panic!(
            "coap-client is not available ({e}): install libcoap (libcoap3-bin, or build \
             libcoap 4.3.5). This test does not skip."
        )
    });
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "coap-client {args:?} failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    (stdout, stderr)
}

#[tokio::test]
async fn libcoap_observes_and_moves_blocks_both_ways() {
    let device = Device::start(None).await;
    let base = format!("coap://127.0.0.1:{}", device.port);

    // -- Observe -----------------------------------------------------------------------
    // `-s 6`: observe for six seconds, printing every representation as it arrives.
    let observer = Command::new("coap-client")
        .args(["-s", "6", "-m", "get", &format!("{base}/temp")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("coap-client is not available: install libcoap; this test does not skip");
    device.wait_for_observers(1).await;
    let registered = device.handle().await.observers();
    assert_eq!(registered[0].path, "/temp");

    for value in ["21", "22"] {
        coap_client(&["-m", "put", "-e", value, &format!("{base}/temp")]).await;
    }
    let out = tokio::time::timeout(Duration::from_secs(20), observer.wait_with_output())
        .await
        .expect("the observing coap-client did not end")
        .unwrap();
    let printed = String::from_utf8_lossy(&out.stdout).to_string();
    let positions: Vec<Option<usize>> = ["t=20", "t=21", "t=22"]
        .iter()
        .map(|v| printed.find(v))
        .collect();
    assert!(
        positions.iter().all(Option::is_some),
        "libcoap printed the registration's value and both notifications: {printed:?}\n\
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "in the order they were pushed: {printed:?}"
    );

    // -- Block2 ------------------------------------------------------------------------
    // Default block size, then 64-byte blocks the client asks for (47 of them): both
    // reassembled byte for byte, each from ONE handler call.
    let (stdout, _) = coap_client(&["-m", "get", &format!("{base}/big")]).await;
    assert_eq!(
        stdout.trim_end(),
        body(),
        "libcoap reassembled the Block2 body"
    );
    assert_eq!(
        device.asked("/big").await,
        1,
        "later blocks came from the cache"
    );

    let (stdout, _) = coap_client(&["-b", "64", "-m", "get", &format!("{base}/big/small")]).await;
    assert_eq!(stdout.trim_end(), body(), "reassembled from 64-byte blocks");
    assert_eq!(
        device.asked("/big/small").await,
        1,
        "47 blocks, one handler call"
    );

    // -- Block1 ------------------------------------------------------------------------
    // 3000 bytes in 256-byte blocks: twelve of them, eleven answered 2.31 by NetGet alone.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("body.txt");
    std::fs::write(&file, body()).unwrap();
    let (stdout, stderr) = coap_client(&[
        "-b",
        "256",
        "-m",
        "put",
        "-f",
        file.to_str().unwrap(),
        &format!("{base}/upload"),
    ])
    .await;
    assert!(
        stdout.contains("got 3000 bytes in 12 blocks"),
        "the handler saw the body whole: {stdout:?} {stderr:?}"
    );
    let uploads: Vec<Value> = device
        .requests()
        .await
        .into_iter()
        .filter(|r| r["path"] == "/upload")
        .collect();
    assert_eq!(uploads.len(), 1, "one handler call for twelve blocks");
    assert_eq!(uploads[0]["payload"], body());
    assert_eq!(uploads[0]["blocks"], 12);
}

#[tokio::test]
async fn aiocoap_observes_and_moves_blocks_both_ways() {
    let python = aiocoap_python();
    let device = Device::start(None).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/coap/peer/aiocoap_peer.py"
    );
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        Command::new(&python)
            .args(["-I", script, "client", &device.port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the aiocoap peer did not finish")
    .expect("the aiocoap peer could not run");
    assert!(
        out.status.success(),
        "aiocoap peer failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    println!("[aiocoap] {report}");

    // The registration's response carries Observe, and aiocoap delivered both pushes with
    // increasing sequence numbers.
    assert_eq!(report["registration"]["payload"], "t=20", "{report}");
    assert!(report["registration"]["observe"].is_u64(), "{report}");
    let notes = report["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 2, "{report}");
    assert_eq!(notes[0]["payload"], "t=21");
    assert_eq!(notes[1]["payload"], "t=22");
    let seq: Vec<u64> = notes
        .iter()
        .map(|n| n["observe"].as_u64().unwrap())
        .collect();
    assert!(
        report["registration"]["observe"].as_u64().unwrap() < seq[0] && seq[0] < seq[1],
        "{report}"
    );

    // Block2: aiocoap reassembled exactly the representation; NetGet asked the handler once.
    assert_eq!(report["big"]["size"], 3000, "{report}");
    assert_eq!(report["big"]["matches"], true, "{report}");
    assert!(
        report["big"]["etag"].is_string(),
        "every block carries the ETag: {report}"
    );
    assert_eq!(device.asked("/big").await, 1);

    // Block1: aiocoap split 3000 bytes at its 1024-byte maximum: three blocks.
    assert_eq!(
        report["upload"]["payload"], "got 3000 bytes in 3 blocks",
        "{report}"
    );
    let upload = device
        .requests()
        .await
        .into_iter()
        .find(|r| r["path"] == "/upload")
        .unwrap();
    assert_eq!(upload["payload"], body());
}
