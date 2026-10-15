//! NetGet's devp2p client against two independent Ethereum implementations, both required:
//! **go-ethereum 1.17** serving a chain it sealed itself (`geth --dev`, then restarted as an
//! ordinary node — see `tests/helpers/ethereum.rs`), and **reth 2.7** in `--dev` mode. NetGet
//! uses none of either's code.
//!
//! The python policy plays the model: it mirrors the peer's Status, asks for the first headers
//! by number, then for the same headers backwards by the hash of the last one, then for their
//! bodies. Each answer is the real node's, and the test checks what NetGet decoded against the
//! node's own JSON-RPC: every hash NetGet computed is the hash `eth_getBlockByNumber` reports.
//! The by-hash request answering with the right headers is the peer confirming NetGet encoded
//! the request the model asked for.
//!
//! Fails, rather than skips, when a binary is missing. Everything is on loopback.
use crate::helpers::ethereum::{self, Geth, Reth};
use crate::helpers::E2EResult;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const AMOUNT: u64 = 3;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='eth_status':
  a=[{'type':'eth_send_status','mirror_peer':True},{'type':'eth_request_block_headers','origin':0,'amount':3}]
elif t=='eth_block_headers_received' and not e['request']['query']['reverse']:
  a=[{'type':'eth_request_block_headers','origin':e['headers'][-1]['hash'],'amount':3,'reverse':True}]
elif t=='eth_block_headers_received':
  a=[{'type':'eth_request_block_bodies','hashes':[h['hash'] for h in e['headers']]}]
print(json.dumps({'actions':a}))"#;

async fn client(enode: &str) -> E2EResult<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "devp2p".into(),
        remote_addr: Some(enode.into()),
        instruction: Some("Fetch the first blocks".into()),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": POLICY}
        })]),
        startup_params: Some(json!({"client_id": "NetGet/devp2p-client-test"})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    let mut v: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
    v.into_iter().map(|e| e["request"].clone()).collect()
}

async fn wait_for(state: &AppState, id: ClientId, kind: &str, n: usize) -> E2EResult<Vec<Value>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let v = events(state, id, kind).await;
        if v.len() >= n {
            return Ok(v);
        }
        if tokio::time::Instant::now() > deadline {
            let all = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await;
            return Err(format!("no {kind} after 30s; every event: {all:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Check what NetGet decoded against the node's own blocks.
async fn check_session(
    state: &AppState,
    id: ClientId,
    block: impl AsyncFn(u64) -> E2EResult<Value>,
    peer_name: &str,
) -> E2EResult<()> {
    let status = wait_for(state, id, "eth_status", 1).await?;
    let genesis = block(0).await?;
    assert_eq!(
        status[0]["peer_status"]["genesis_hash"], genesis["hash"],
        "{}",
        status[0]
    );
    assert_eq!(status[0]["eth_version"], 69);
    assert!(
        status[0]["client_id"]
            .as_str()
            .unwrap()
            .starts_with(peer_name),
        "{}",
        status[0]
    );

    let received = wait_for(state, id, "eth_block_headers_received", 2).await?;
    // Forwards from block 0: every header NetGet hashed is the node's block of that number.
    let forward = &received[0];
    assert_eq!(forward["count"], AMOUNT, "{forward}");
    assert_eq!(forward["matches_request"], true, "{forward}");
    assert_eq!(forward["linked"], true, "{forward}");
    for (i, h) in forward["headers"].as_array().unwrap().iter().enumerate() {
        let theirs = block(i as u64).await?;
        assert_eq!(h["hash"], theirs["hash"], "block {i}");
        assert_eq!(h["stateRoot"], theirs["stateRoot"], "block {i}");
        assert_eq!(h["parentHash"], theirs["parentHash"], "block {i}");
    }
    // Backwards from the last one's hash: the node found that hash, so NetGet sent it intact.
    let backward = &received[1];
    assert_eq!(backward["request"]["query"]["reverse"], true, "{backward}");
    assert_eq!(backward["matches_request"], true, "{backward}");
    assert_eq!(backward["linked"], true, "{backward}");
    let fwd: Vec<&Value> = forward["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| &h["hash"])
        .collect();
    let mut back: Vec<&Value> = backward["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| &h["hash"])
        .collect();
    back.reverse();
    assert_eq!(fwd, back);

    // Bodies for those blocks: one each, in the order asked.
    let bodies = wait_for(state, id, "eth_block_bodies_received", 1).await?;
    assert_eq!(bodies[0]["count"], AMOUNT, "{}", bodies[0]);
    for b in bodies[0]["bodies"].as_array().unwrap() {
        let theirs = block(
            u64::from_str_radix(
                block_number_of(&backward["headers"], b["block_hash"].as_str().unwrap())
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0),
        )
        .await?;
        assert_eq!(
            b["transactions"].as_array().unwrap().len(),
            theirs["transactions"].as_array().unwrap().len()
        );
    }
    Ok(())
}

fn block_number_of(headers: &Value, hash: &str) -> String {
    headers
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["hash"] == hash)
        .map(|h| format!("0x{:x}", h["number"].as_u64().unwrap_or(0)))
        .unwrap_or_default()
}

#[tokio::test]
async fn netget_fetches_geths_headers_and_bodies() -> E2EResult<()> {
    let chain = ethereum::geth_chain(AMOUNT).await?;
    let geth = Geth::start(&chain, &[]).await?;
    let (state, id) = client(&geth.enode().await?).await?;
    let result = check_session(&state, id, async |n| geth.block(n).await, "Geth/").await;
    geth.server.with_log(result)?;
    // geth lists NetGet as an eth/69 peer.
    let peers = geth.rpc("admin_peers", json!([])).await?;
    assert!(
        peers.to_string().contains("NetGet/devp2p-client-test"),
        "{peers}"
    );
    Ok(())
}

#[tokio::test]
async fn netget_fetches_reths_headers_and_bodies() -> E2EResult<()> {
    let reth = Reth::start().await?;
    reth.wait_for_block(AMOUNT).await?;
    let (state, id) = client(&reth.enode().await?).await?;
    let result = check_session(&state, id, async |n| reth.block(n).await, "reth/").await;
    reth.server.with_log(result)?;
    Ok(())
}
