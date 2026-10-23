//! NetGet as a **Template Distribution client** of **sv2-tp 1.1.2** (stratum-mining/sv2-tp, the
//! C++ Template Provider derived from Bitcoin Core — no SRI code and no NetGet code), which
//! builds its templates from **Bitcoin Core 31.0**'s mempool over IPC, in regtest.
//!
//! The node's wallet puts three segwit transactions in its mempool before the provider starts,
//! so the first template carries them. NetGet pins the provider's authority key (read from its
//! log), sets up and sends CoinbaseOutputConstraints; the model (a python chain) answers the
//! provider's SetNewPrevHash by asking for the template's transactions and mining it. Rust
//! checks the provider's merkle path and witness commitment against the transactions it
//! parsed — real segwit transactions, whose wtxids differ from their txids — then builds the
//! coinbase the template describes and submits the block it finds. sv2-tp hands that to
//! Bitcoin Core, which must then have a block with the hash NetGet computed, carrying the three
//! transactions. A key the provider's certificate was not signed with is refused. No LLM calls.
use super::peers;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='stratum_v2_template_prev_hash':
  a=[{'type':'stratum_v2_request_transactions','template_id':e['template_id']},
     {'type':'stratum_v2_mine_template','template_id':e['template_id'],'message':'netget tdp'}]
print(json.dumps({'actions':a}))"#;

async fn wait_event(
    state: &AppState,
    id: ClientId,
    pred: impl Fn(&Value) -> bool,
) -> Option<Value> {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| pred(e))
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok()
}

async fn client(
    port: u16,
    key: &str,
    status: mpsc::UnboundedSender<String>,
    state: &AppState,
) -> anyhow::Result<ClientId> {
    ClientForm {
        protocol: "stratum_v2".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Take templates and mine them".into()),
        startup_params: Some(json!({"role": "template_client", "authority_public_key": key})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
        ]),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        status,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_mines_sv2_tp_templates_into_bitcoin_core() {
    let node = peers::Regtest::start(true, 1).await;
    node.cli(&["createwallet", "w"]).await.unwrap();
    let addr = node.cli(&["getnewaddress"]).await.unwrap();
    node.cli(&["generatetoaddress", "101", &addr])
        .await
        .unwrap();
    for _ in 0..3 {
        node.cli(&[
            "-named",
            "sendtoaddress",
            &format!("address={addr}"),
            "amount=1",
            "fee_rate=5",
        ])
        .await
        .unwrap();
    }
    let (_, height, _) = node.tip().await;
    let next = height + 1;

    let dir = node.tmp.path().to_path_buf();
    let tp_port = peers::free_port();
    let tp_log = dir.join("sv2-tp.log");
    let _tp = peers::spawn(
        &peers::env("NETGET_SV2_TP"),
        &[
            "-chain=regtest".into(),
            format!("-datadir={}", node.dir.display()),
            "-ipcconnect=unix".into(),
            format!("-sv2port={tp_port}"),
            "-debug=sv2".into(),
            "-conf=0".into(),
        ],
        &dir,
        &tp_log,
    );
    assert!(
        peers::wait_log(&tp_log, "listening for Stratum v2 connections", 60).await,
        "sv2-tp never listened:\n{}",
        peers::read(&tp_log)
    );
    let text = peers::read(&tp_log);
    let key = text
        .split("Template Provider authority key: ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("sv2-tp printed no authority key:\n{text}"))
        .to_string();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let status = peers::Status::default();
    let sink = status.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.0.lock().unwrap().push(line);
        }
    });
    let id = client(tp_port, &key, tx, &state)
        .await
        .expect("connect to sv2-tp");
    let dump = |what: &str| {
        format!(
            "{what}\n--- sv2-tp ---\n{}\n--- netget ---\n{}",
            peers::read(&tp_log),
            status.text()
        )
    };

    let template = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_template" && e["request"]["height"] == next
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("no template at the next height")));
    assert_eq!(
        template["merkle_path_len"], 2,
        "three transactions and the coinbase: {template}"
    );
    assert!(
        template["coinbase_value_sats"].as_u64().unwrap() > 5_000_000_000,
        "the subsidy plus the three fees: {template}"
    );
    let prev = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_template_prev_hash"
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("no SetNewPrevHash")));
    assert_eq!(prev["target_matches_nbits"], true, "{prev}");
    assert_eq!(prev["nbits"], "207fffff", "{prev}");
    let txs = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_template_transactions"
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("the transactions never arrived")));
    assert_eq!(txs["transaction_count"], 3, "{txs}");
    assert_eq!(txs["segwit_transactions"], 3, "{txs}");
    assert_eq!(
        txs["merkle_path_matches"],
        true,
        "{}",
        dump(&txs.to_string())
    );
    assert_eq!(
        txs["witness_commitment_matches"],
        true,
        "{}",
        dump(&txs.to_string())
    );
    let solved = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_template_solution"
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("the template was never mined")));
    assert_eq!(solved["submitted"], true, "{solved}");
    let hash = solved["hash"].as_str().unwrap().to_string();

    // sv2-tp handed the block to Bitcoin Core, which accepted it by the hash NetGet computed.
    let block = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(b) = node.cli(&["getblock", &hash, "2"]).await {
                return serde_json::from_str::<Value>(&b).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{}", dump(&format!("Bitcoin Core has no block {hash}"))));
    assert_eq!(block["height"], next, "{block}");
    assert_eq!(block["tx"].as_array().unwrap().len(), 4, "{block}");
    assert_eq!(
        block["tx"][0]["vout"][0]["scriptPubKey"]["asm"], "1",
        "NetGet's OP_TRUE output takes the value: {block}"
    );
    assert_eq!(node.cli(&["getbestblockhash"]).await.unwrap(), hash);

    let outcome = state
        .send_to_client(id, json!({"type": "disconnect"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
    let summary = status
        .wait("template client received: ", 30)
        .await
        .unwrap_or_else(|| panic!("{}", dump("no session summary")));
    println!("sv2-tp -> NetGet template client: {summary} (plus SetupConnection.Success)");
    for kind in [
        "NewTemplate=",
        "SetNewPrevHash (Template Distribution)=",
        "RequestTransactionData.Success=1",
    ] {
        assert!(summary.contains(kind), "{summary}");
    }

    // A key the provider's certificate was not signed with: no connection at all.
    let (tx, _) = mpsc::unbounded_channel();
    let err = client(tp_port, peers::PUBLIC, tx, &state)
        .await
        .expect_err("NetGet took templates from a provider its pinned key did not certify");
    assert!(format!("{err:#}").contains("not signed"), "{err:#}");
}
