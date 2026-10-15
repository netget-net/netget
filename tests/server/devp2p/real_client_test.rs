//! NetGet's devp2p node against two independent Ethereum implementations, both required:
//!
//! - **go-ethereum 1.17** (`brew install ethereum`; the geth-alltools tarball on Linux). geth
//!   dials NetGet after `admin_addPeer`, completes RLPx, Hello and the eth/69 Status, and lists
//!   NetGet in `admin_peers` with the client id and block range NetGet sent. With
//!   `--eth.requiredblocks 3=<hash>` geth then asks every new peer for block 3's header and
//!   checks its hash against its own block: NetGet's model wrote that header as JSON fields and
//!   NetGet encoded it, so geth logging `Peer required block verified` is geth's own keccak over
//!   NetGet's RLP. A second NetGet node serving a header with one field changed is dropped
//!   (`Required block mismatch`), which shows the check is real.
//! - **go-ethereum's `devp2p` tool**, `devp2p rlpx ping`: its RLPx and Hello reading of NetGet.
//!   Same code family as geth, a different program.
//! - **reth 2.7** (Rust, paradigmxyz; NetGet uses none of its crates): reth dials NetGet after
//!   `admin_addPeer`, completes the handshake and Status, and lists NetGet with eth/69.
//!
//! Every peer runs on loopback with discovery off (`tests/helpers/ethereum.rs`). No model:
//! a python policy answers. Fails, rather than skips, when a binary is missing.
use super::support::{self, CLIENT_ID, SERVER_KEY};
use crate::helpers::ethereum::{self, Geth, Reth, DEVP2P_TOOL};
use crate::helpers::real_server::missing_binary;
use crate::helpers::E2EResult;
use serde_json::{json, Value};
use std::time::Duration;

/// Blocks 0..=n as geth or reth reports them, keyed by decimal number.
async fn headers_from(get: impl AsyncFn(u64) -> E2EResult<Value>, n: u64) -> E2EResult<Value> {
    let mut m = serde_json::Map::new();
    for i in 0..=n {
        m.insert(i.to_string(), get(i).await?);
    }
    Ok(Value::Object(m))
}

#[tokio::test]
async fn geth_dials_netget_and_verifies_the_header_it_serves() -> E2EResult<()> {
    let chain = ethereum::geth_chain(4).await?;
    let required = format!("3={}", chain.hashes[3]);
    let geth = Geth::start(&chain, &["--eth.requiredblocks".into(), required]).await?;
    // The console may seal one more block before it exits: geth's own head is the reference.
    let head = geth
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    let head_number = u64::from_str_radix(
        head["number"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )?;
    let headers = headers_from(async |n| geth.block(n).await, head_number).await?;
    assert_eq!(headers["3"]["hash"], chain.hashes[3].as_str());

    let node = support::start(SERVER_KEY, support::policy(&headers), json!({})).await;
    // A second node whose block 3 has one field changed: its hash is not geth's.
    let mut forged = headers.clone();
    forged["3"]["extraData"] = json!("0x6e6f74206765746827"); // "not geth'"
    forged["3"].as_object_mut().unwrap().remove("hash");
    let forger_key = "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee";
    let forger = support::start(forger_key, support::policy(&forged), json!({})).await;

    for n in [&node, &forger] {
        geth.rpc("admin_addPeer", json!([n.enode()])).await?;
    }

    // geth's own view of NetGet: the eth/69 handshake completed, with the name and block
    // range NetGet sent (mirrored from geth's Status by the policy).
    let peer = ethereum::wait_for_peer(geth.http_port(), &node.node_id(), Duration::from_secs(30))
        .await
        .map_err(|e| {
            format!(
                "{e}\nNetGet log:\n{}\ngeth log:\n{}",
                node.log_text(),
                geth.server.log()
            )
        })?;
    assert_eq!(peer["name"], CLIENT_ID, "{peer}");
    assert_eq!(peer["protocols"]["eth"]["version"], 69, "{peer}");
    assert_eq!(
        peer["protocols"]["eth"]["latestBlock"], head_number,
        "{peer}"
    );
    assert_eq!(
        peer["protocols"]["eth"]["latestBlockHash"], head["hash"],
        "{peer}"
    );

    // geth asked NetGet for block 3, hashed the header NetGet sent, and accepted it…
    geth.server
        .wait_for_log("Peer required block verified", Duration::from_secs(30))
        .await
        .map_err(|e| format!("{e}\nNetGet log:\n{}", node.log_text()))?;
    // …and dropped the node that served a different block 3.
    geth.server
        .wait_for_log("Required block mismatch", Duration::from_secs(30))
        .await
        .map_err(|e| format!("{e}\nforger log:\n{}", forger.log_text()))?;

    // What NetGet's model was shown: geth's Status, then geth's request for exactly block 3.
    let status = node.wait_for_events("eth_status", 1).await;
    assert_eq!(
        status[0]["peer_status"]["genesis_hash"],
        chain.hashes[0].as_str()
    );
    assert_eq!(
        status[0]["peer_status"]["network_id"],
        ethereum::DEV_NETWORK_ID
    );
    assert_eq!(status[0]["eth_version"], 69);
    assert!(
        status[0]["client_id"]
            .as_str()
            .unwrap()
            .starts_with("Geth/"),
        "{}",
        status[0]
    );
    let asked = node.wait_for_events("eth_block_headers_requested", 1).await;
    assert_eq!(
        (asked[0]["origin"].clone(), asked[0]["amount"].clone()),
        (json!(3), json!(1))
    );
    assert!(
        node.log_text().contains("decision=model_answer"),
        "{}",
        node.log_text()
    );
    // The header NetGet sent is the one geth hashed: NetGet logs the hash it computed.
    assert!(
        node.log_text().contains(&chain.hashes[3]),
        "NetGet never logged sending {}:\n{}",
        chain.hashes[3],
        node.log_text()
    );
    Ok(())
}

#[tokio::test]
async fn the_devp2p_tool_reads_netgets_hello() -> E2EResult<()> {
    let node = support::start(SERVER_KEY, support::policy(&json!({})), json!({})).await;
    let mut command = tokio::process::Command::new(ethereum::binary("devp2p"));
    command
        .args(["rlpx", "ping", &node.enode()])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .map_err(|_| "devp2p rlpx ping did not finish in 30s")?
        .map_err(|e| missing_binary("devp2p", DEVP2P_TOOL, e))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{text}\nNetGet log:\n{}",
        node.log_text()
    );
    // The tool prints the Hello it decoded: NetGet's name, eth/69 and eth/68, its node id.
    assert!(text.contains(&format!("Name:{CLIENT_ID}")), "{text}");
    assert!(text.contains("eth/69") && text.contains("eth/68"), "{text}");
    assert!(text.contains("Version:5"), "{text}");
    Ok(())
}

#[tokio::test]
async fn reth_dials_netget_and_completes_the_eth_handshake() -> E2EResult<()> {
    let reth = Reth::start().await?;
    reth.wait_for_block(2).await?;
    let headers = headers_from(async |n| reth.block(n).await, 2).await?;
    let node = support::start(SERVER_KEY, support::policy(&headers), json!({})).await;
    reth.rpc("admin_addPeer", json!([node.enode()])).await?;
    let peer = ethereum::wait_for_peer(reth.http_port(), &node.node_id(), Duration::from_secs(30))
        .await
        .map_err(|e| {
            format!(
                "{e}\nNetGet log:\n{}\nreth log:\n{}",
                node.log_text(),
                reth.server.log()
            )
        })?;
    assert_eq!(peer["name"], CLIENT_ID, "{peer}");
    let status = node.wait_for_events("eth_status", 1).await;
    assert_eq!(
        status[0]["peer_status"]["genesis_hash"], headers["0"]["hash"],
        "{}",
        status[0]
    );
    assert!(
        status[0]["client_id"]
            .as_str()
            .unwrap()
            .starts_with("reth/"),
        "{}",
        status[0]
    );
    assert_eq!(status[0]["eth_version"], 69);
    // reth kept the session: still listed after the handshake settles, with eth.
    tokio::time::timeout(Duration::from_secs(5), node.wait_for_log("Status sent"))
        .await
        .ok();
    let peers = reth.rpc("admin_peers", json!([])).await?;
    assert!(
        peers.to_string().contains(&node.node_id()),
        "reth dropped NetGet: {peers}\nNetGet log:\n{}",
        node.log_text()
    );
    Ok(())
}
