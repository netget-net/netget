//! NetGet as a **Template Provider** (Template Distribution Protocol) for **SRI's `pool_sv2`**
//! (sv2-apps v0.8.0, `[template_provider_type.Sv2Tp]`, pinning NetGet's authority key), with
//! **SRI's `mining_device`** mining on the pool and **Bitcoin Core 31.0** in regtest as the judge.
//!
//! The model (a python policy) writes the template: the regtest tip as prev hash, the next
//! height, regtest's nbits, and one transaction spending an early `OP_TRUE` coinbase. Rust makes
//! it a template — merkle path, witness commitment, BIP 34 height — and the pool builds its
//! coinbase and jobs from it with its own code. The device mines; the pool, finding a block,
//! sends SubmitSolution; NetGet rebuilds the block, checks its hash against the target, logs
//! it, and tells the model, which answers with a template on top of it. The block NetGet
//! assembled is then handed to Bitcoin Core's `submitblock`, which accepts it only if the
//! merkle path, the commitment, the height, the coinbase value and the transaction are all
//! right — a node agreeing with a template NetGet wrote, through a pool and a miner that are
//! not NetGet. No LLM calls.
//!
//! Wireshark has no Stratum V2 dissector and every frame after the handshake is
//! ChaCha20-Poly1305 ciphertext, so there is no pcap oracle; Bitcoin Core is the oracle for the
//! bytes that matter.
use super::{peers, support};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sri_pool_mines_netget_templates_into_a_block_bitcoin_core_accepts() {
    let node = peers::Regtest::start(false, 101).await;
    let (tip, height, ntime) = node.tip().await;
    let (cb_txid, cb_value) = node.coinbase(1).await;
    let next = height + 1;
    let fee = 10_000u64;
    let txs = json!([{"inputs": [{"txid": cb_txid, "vout": 0, "value_sats": cb_value}],
        "outputs": [{"value_sats": cb_value - fee, "pay_to": "op_true"},
                    {"value_sats": 0, "op_return": "netget template"}]}]);
    let policy = support::script(&format!(
        r#"if t=='stratum_v2_tp_setup_connection':
  a=[{{'type':'stratum_v2_accept'}}]
elif t=='stratum_v2_tp_coinbase_output_constraints' and e['templates_sent']==0:
  a=[{{'type':'stratum_v2_new_template','prev_hash':'{tip}','height':{next},'nbits':'207fffff','ntime':{ntime},'transactions':json.loads('{txs}')}}]
elif t=='stratum_v2_tp_solution' and e['height']=={next} and not e['stale']:
  a=[{{'type':'stratum_v2_new_template','prev_hash':e['hash'],'height':e['height']+1,'ntime':e['ntime']}}]"#
    ));
    let (state, id, tp_port, status) = support::start_role(
        policy,
        json!({"role": "template_provider", "network": "regtest",
               "authority_secret_key": peers::SECRET}),
    )
    .await;

    let dir = node.tmp.path().to_path_buf();
    let (_pool, pool_port, pool_log) = peers::pool(
        &dir,
        &format!(
            "[template_provider_type.Sv2Tp]\naddress = \"127.0.0.1:{tp_port}\"\npublic_key = \"{}\"\n",
            peers::PUBLIC
        ),
    )
    .await;
    peers::wait_listening(pool_port, &pool_log, "pool_sv2", 60).await;
    let device_log = dir.join("device.log");
    let mut device = peers::mining_device(pool_port, &dir, &device_log);

    let dump = |what: &str| {
        format!(
            "{what}\n--- pool_sv2 ---\n{}\n--- mining_device ---\n{}\n--- netget ---\n{}",
            peers::read(&pool_log),
            peers::read(&device_log),
            status.text()
        )
    };
    let block_line = status
        .wait(&format!("at height {next} solved template"), 120)
        .await
        .unwrap_or_else(|| panic!("{}", dump("no solution reached NetGet")));
    let hex = block_line
        .rsplit("bytes: ")
        .next()
        .unwrap()
        .trim()
        .to_string();
    let hash = block_line
        .split("block ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string();

    // Bitcoin Core takes the block NetGet assembled from its own template and SRI's coinbase.
    let submitted = node.cli(&["submitblock", &hex]).await;
    assert_eq!(
        submitted.as_deref(),
        Ok(""),
        "{}",
        dump(&format!("Bitcoin Core refused block {hash}: {submitted:?}"))
    );
    let block: Value = node.json(&["getblock", &hash, "2"]).await;
    assert_eq!(block["height"], next, "{block}");
    let spent = &block["tx"][1];
    assert_eq!(
        spent["vin"][0]["txid"], cb_txid,
        "the template's transaction is not in the block: {block}"
    );
    assert_eq!(
        spent["vout"][1]["scriptPubKey"]["asm"],
        format!("OP_RETURN {}", hex::encode("netget template")),
        "{block}"
    );
    let paid: f64 = block["tx"][0]["vout"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["value"].as_f64().unwrap())
        .sum();
    assert_eq!(
        (paid * 1e8).round() as u64,
        cb_value + fee,
        "the coinbase claims the subsidy and the fee: {block}"
    );

    // The model heard of the solution, verified, and moved the pool onto a block on top of it.
    let solutions = support::events(&state, id, "stratum_v2_tp_solution").await;
    assert!(
        solutions.iter().any(|s| s["hash"] == hash.as_str()),
        "{solutions:?}"
    );
    assert!(
        peers::wait_log(&pool_log, "Received: NewTemplate(template_id: 2", 30).await,
        "{}",
        dump("the pool never received the model's second template")
    );
    let pool_text = peers::read(&pool_log);
    for needle in [
        "Received: NewTemplate(template_id: 1, future_template: true",
        "Received: SetNewPrevHash { template_id: 1",
        "Received: SetNewPrevHash { template_id: 2",
    ] {
        assert!(pool_text.contains(needle), "{}", dump(needle));
    }
    let constraints =
        support::events(&state, id, "stratum_v2_tp_coinbase_output_constraints").await;
    assert!(!constraints.is_empty());

    // What the pool sent, counted by NetGet when the connection ends.
    let _ = device.kill().await;
    drop(_pool);
    let summary = status
        .wait("received: ", 30)
        .await
        .unwrap_or_else(|| panic!("{}", dump("no connection summary")));
    println!("pool_sv2 -> NetGet template provider: {summary}");
    for kind in [
        "SetupConnection=1",
        "CoinbaseOutputConstraints=",
        "SubmitSolution=",
    ] {
        assert!(summary.contains(kind), "{summary}");
    }
}
