//! Work selection: NetGet as **both** the pool and the Job Declaration Server of **SRI's
//! `jd_client_sv2`** (sv2-apps v0.8.0, FULLTEMPLATE), one server in the
//! `pool_and_job_declarator` role, so the token its job declarator issues is the token its pool
//! redeems.
//!
//! `sri_jd_client_pushes_a_block_through_netget_pool_and_jds`: templates come from **sv2-tp
//! 1.1.2** over **Bitcoin Core 31.0** in regtest, whose wallet put two segwit transactions in the
//! mempool, and **SRI's `mining_device`** mines on the jd_client. Every party but the server
//! under test is SRI's, sv2-tp or Bitcoin Core. The jd_client declares its job to NetGet (which
//! asks for the transactions, checks them and the coinbase, and checks the height against the
//! node's next block), redeems the token with SetCustomMiningJob on NetGet's pool (which checks
//! the custom job against the declaration and the node's tip), and mines. A share meeting the
//! network target makes the jd_client send SubmitSolution to sv2-tp, which hands the block to
//! the node, and PushSolution to NetGet's JDS and SubmitSharesExtended to NetGet's pool, which
//! each rebuild the block from what was declared and relay it. Bitcoin Core is the oracle: the
//! block the JDS and the pool rebuilt — the same hash from both — is in its active chain, with
//! the two transactions. The test calls no `submitblock`; sv2-tp pushes the block (and NetGet's
//! relay, racing it, gets `duplicate` or is first).
//!
//! `custom_jobs_are_checked_against_their_declaration`: raw frames from NetGet's own codec for
//! everything SRI never sends — each field of a custom job that disagrees with its declaration,
//! tokens unknown, reused or issued by another server, work selection without negotiating it,
//! a model that fails — and the shares and PushSolution of a custom job rebuilt into the same
//! block. `declarations_and_custom_jobs_are_checked_against_the_node` does the same with a node:
//! a stale height, another prev hash and the wrong nbits refused, and the pool's own relay of a
//! custom job's block moving the node's tip. No LLM calls: python policies are the model.
use super::support::{self, Raw};
use super::{peers, support::SECRET};
use netget::server::stratum_v2::bitcoin::{self as btc, Tx, TxOut};
use netget::server::stratum_v2::{job_declarator, wire, wire::Message};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// The model for both tests: everyone is admitted, `netget.hard`'s channel at difficulty 1,
/// every token allocated to `OP_TRUE`, every declaration that pays it accepted, every custom job
/// accepted unless its user is `refused`, and the model fails outright for a custom job whose
/// min_ntime is 4242.
const POLICY: &str = r#"if t in ('stratum_v2_setup_connection','stratum_v2_jd_setup_connection','stratum_v2_share'):
  a=[{'type':'stratum_v2_accept'}]
elif t=='stratum_v2_open_channel':
  a=[{'type':'stratum_v2_accept'}]+([{'type':'stratum_v2_set_target','difficulty':1.0}] if e['user_identity']=='netget.hard' else [])
elif t=='stratum_v2_jd_allocate_token':
  a=[{'type':'stratum_v2_accept'},{'type':'stratum_v2_allocate_token','pay_to':'op_true'}]
elif t=='stratum_v2_jd_declare_job':
  a=[{'type':'stratum_v2_accept'}] if e['pays_required_outputs'] else [{'type':'stratum_v2_reject','error_code':'missing-pool-output'}]
elif t=='stratum_v2_custom_job':
  if e['min_ntime']==4242: sys.exit(3)
  a=[{'type':'stratum_v2_accept'}] if e['user_identity']!='refused' else [{'type':'stratum_v2_reject','error_code':'not-your-job'}]"#;

async fn wait_events(
    state: &AppState,
    id: ServerId,
    kind: &str,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    let found = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let hits: Vec<Value> = support::events(state, id, kind)
                .await
                .into_iter()
                .filter(|e| pred(e))
                .collect();
            if !hits.is_empty() {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    found.unwrap_or_default()
}

/// The line NetGet logs when a connection of `what` ends, counting what its peer sent.
async fn summary(status: &peers::Status, what: &str) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(l) = status
                .lines()
                .into_iter()
                .find(|l| l.contains(what) && l.contains(" received: "))
            {
                return l;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .ok()
}

/// The `Received: <Message>` lines of an SRI log, by message: what the other side sent it.
fn received_by_sri(log: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for line in log.lines() {
        if let Some(rest) = line.split("Received: ").nth(1) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if !name.is_empty() {
                *out.entry(name).or_default() += 1;
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sri_jd_client_pushes_a_block_through_netget_pool_and_jds() {
    let node = peers::Regtest::start(true, 1).await;
    node.cli(&["createwallet", "w"]).await.unwrap();
    let addr = node.cli(&["getnewaddress"]).await.unwrap();
    node.cli(&["generatetoaddress", "101", &addr])
        .await
        .unwrap();
    for _ in 0..2 {
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
    let tp_text = peers::read(&tp_log);
    let tp_key = tp_text
        .split("Template Provider authority key: ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("sv2-tp printed no authority key:\n{tp_text}"))
        .to_string();

    // The server under test: pool and job declarator on one port, relaying to the node.
    let (state, id, port, status) = support::start_role(
        support::script(POLICY),
        json!({"role": "pool_and_job_declarator", "network": "regtest",
               "authority_secret_key": SECRET,
               "bitcoin_rpc_url": format!("http://127.0.0.1:{}", node.rpc),
               "bitcoin_rpc_user": "netget", "bitcoin_rpc_password": "netget"}),
    )
    .await;

    let jdc_port = peers::free_port();
    let conf = dir.join("jdc.toml");
    std::fs::write(
        &conf,
        format!(
            r#"listening_address = "127.0.0.1:{jdc_port}"
max_supported_version = 2
min_supported_version = 2
authority_public_key = "{public}"
authority_secret_key = "{secret}"
cert_validity_sec = 3600
shares_per_minute = 60.0
share_batch_size = 1
mode = "FULLTEMPLATE"
jdc_signature = "SRI JDC for NetGet"
coinbase_reward_script = "raw(51)"
supported_extensions = []

[[upstreams]]
authority_pubkey = "{public}"
pool_address = "127.0.0.1"
pool_port = {port}
jds_address = "127.0.0.1"
jds_port = {port}
user_identity = "netget.jdc"

[template_provider_type.Sv2Tp]
address = "127.0.0.1:{tp_port}"
public_key = "{tp_key}"
"#,
            public = peers::PUBLIC,
            secret = SECRET,
        ),
    )
    .unwrap();
    let jdc_log = dir.join("jdc.log");
    let jdc = peers::spawn(
        &peers::env("NETGET_SV2_JD_CLIENT"),
        &["-c".into(), conf.display().to_string()],
        &dir,
        &jdc_log,
    );
    let device_log = dir.join("device.log");
    let dump = |what: &str| {
        format!(
            "{what}\n--- jd_client ---\n{}\n--- sv2-tp ---\n{}\n--- mining_device ---\n{}\n--- netget ---\n{}",
            peers::read(&jdc_log),
            peers::read(&tp_log),
            peers::read(&device_log),
            status.text()
        )
    };
    // jd_client opens its upstream channel, and so declares, only once a miner connects to it.
    peers::wait_listening(jdc_port, &jdc_log, "jd_client_sv2", 60).await;
    let mut device = peers::mining_device(jdc_port, &dir, &device_log);

    // On regtest every share is a block, and jd_client hands its blocks to sv2-tp before its
    // pool has acknowledged the job (optimistic mining), so the tip can move while a
    // declaration is being checked; NetGet then answers stale-chain-tip, which jd_client
    // treats as non-fatal. So the test keeps the mempool from running dry and waits for a
    // block that carries transactions, is in Bitcoin Core's chain, and was rebuilt by NetGet's
    // JDS from PushSolution — and by its pool, with the same hash, from SubmitSharesExtended.
    let kept = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let pending = node.json(&["getmempoolinfo"]).await;
            if pending["size"] == 0 {
                let _ = node
                    .cli(&[
                        "-named",
                        "sendtoaddress",
                        &format!("address={addr}"),
                        "amount=1",
                        "fee_rate=5",
                    ])
                    .await;
            }
            for s in support::events(&state, id, "stratum_v2_jd_solution").await {
                let (Some(h), Some(at)) = (s["hash"].as_str(), s["height"].as_u64()) else {
                    continue;
                };
                if node
                    .cli(&["getblockhash", &at.to_string()])
                    .await
                    .as_deref()
                    != Ok(h)
                {
                    continue;
                }
                let block: Value = node.json(&["getblock", h, "2"]).await;
                if block["tx"].as_array().map_or(0, Vec::len) >= 2 {
                    return (h.to_string(), s, block);
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    })
    .await;
    let (hash, solution, block) = kept.unwrap_or_else(|_| {
        panic!(
            "{}",
            dump(
                "no block with transactions that NetGet's JDS rebuilt reached Bitcoin Core's chain"
            )
        )
    });
    let at = solution["height"].as_u64().unwrap();
    assert!(at >= next, "{solution}");
    let custom = support::events(&state, id, "stratum_v2_custom_job")
        .await
        .into_iter()
        .find(|e| e["height"] == at)
        .unwrap_or_else(|| panic!("{}", dump(&format!("no custom job at height {at}"))));
    assert_eq!(custom["tip_checked"], true, "{custom}");
    assert_eq!(custom["nbits"], "207fffff", "{custom}");
    assert_eq!(
        custom["prev_hash"],
        node.cli(&["getblockhash", &(at - 1).to_string()])
            .await
            .unwrap()
            .as_str(),
        "{custom}"
    );
    let shares = wait_events(&state, id, "stratum_v2_share", 30, |e| {
        e["solves_block"] == true && e["hash"] == hash.as_str()
    })
    .await;
    assert!(
        shares.iter().any(|s| s["custom_job"] == true),
        "{}",
        dump(&format!(
            "the pool did not rebuild the block the JDS did ({hash}): {shares:?}"
        ))
    );
    println!(
        "Bitcoin Core's block {hash} at height {at}: {} transactions, rebuilt by NetGet's JDS and pool",
        block["tx"].as_array().unwrap().len()
    );
    assert_eq!(
        block["tx"].as_array().unwrap().len() as u64,
        custom["transactions"].as_u64().unwrap() + 1,
        "the coinbase and the custom job's transactions: {block}"
    );
    assert_eq!(
        block["tx"][0]["vout"][0]["scriptPubKey"]["asm"], "1",
        "the output NetGet's job declarator required, paid first: {block}"
    );
    let relayed = [
        solution["relay"].as_str().unwrap_or_default(),
        shares[0]["relay"].as_str().unwrap_or_default(),
    ];
    println!(
        "NetGet's relays of {hash}: JDS {:?}, pool {:?}",
        relayed[0], relayed[1]
    );
    for r in relayed {
        assert!(
            ["accepted", "duplicate", "inconclusive", "already-relayed"].contains(&r),
            "{}",
            dump(&format!(
                "Bitcoin Core did not take NetGet's relay of {hash}: {r}"
            ))
        );
    }

    // jd_client's own account: it pushed and propagated the block it found.
    let jdc_text = peers::read(&jdc_log);
    for needle in [
        "Received: AllocateMiningJobTokenSuccess",
        "Received: ProvideMissingTransactions",
        "Received: DeclareMiningJobSuccess",
        "Successfully sent SetCustomMiningJob",
        "Received: SetCustomMiningJobSuccess",
        "Block Found",
        "Propagating solution to the Template Provider",
    ] {
        assert!(jdc_text.contains(needle), "{}", dump(needle));
    }
    println!(
        "NetGet (pool and JDS) and sv2-tp -> jd_client, from its log: {:?}",
        received_by_sri(&jdc_text)
    );
    for line in status.lines() {
        if line.contains("refused") || line.contains("Bitcoin Core") {
            println!("netget: {line}");
        }
    }
    for line in jdc_text.lines() {
        if line.contains("DeclareMiningJobError") || line.contains("fallback") {
            println!("jd_client: {line}");
        }
    }

    // What jd_client sent each half of the server, counted by NetGet as each connection ends.
    let _ = device.kill().await;
    drop(jdc);
    let pool_summary = summary(&status, "pool connection")
        .await
        .unwrap_or_else(|| panic!("{}", dump("no pool connection summary")));
    let jds_summary = summary(&status, "job declarator connection")
        .await
        .unwrap_or_else(|| panic!("{}", dump("no job declarator connection summary")));
    println!("jd_client -> NetGet pool: {pool_summary}");
    println!("jd_client -> NetGet job declarator: {jds_summary}");
    for kind in [
        "SetupConnection=1",
        "OpenExtendedMiningChannel=1",
        "SetCustomMiningJob=",
        "SubmitSharesExtended=",
    ] {
        assert!(pool_summary.contains(kind), "{pool_summary}");
    }
    for kind in [
        "SetupConnection=1",
        "AllocateMiningJobToken=",
        "DeclareMiningJob=",
        "ProvideMissingTransactions.Success=",
        "PushSolution=",
    ] {
        assert!(jds_summary.contains(kind), "{jds_summary}");
    }
}

// ---- Raw frames ---------------------------------------------------------------------------

/// Harder than regtest's limit, so that PushSolution — which names no job — is not met by the
/// header of every job the connection declared, as it would be at 0x207fffff.
const NBITS: u32 = 0x1f00_ffff;
const PREV: [u8; 32] = [0x5a; 32];
const HEIGHT: u32 = 300;

fn setup(protocol: u8, flags: u32) -> Message {
    Message::SetupConnection {
        protocol,
        min_version: 2,
        max_version: 2,
        flags,
        endpoint_host: b"127.0.0.1".to_vec(),
        endpoint_port: 3333,
        vendor: b"raw".to_vec(),
        hardware_version: Vec::new(),
        firmware: Vec::new(),
        device_id: Vec::new(),
    }
}

fn tx(seed: u8) -> Tx {
    let (tx, _) = btc::tx_from_json(&json!({
        "inputs": [{"txid": format!("{seed:02x}").repeat(32), "vout": 0, "value_sats": 100_000}],
        "outputs": [{"value_sats": 99_000, "pay_to": "op_true"}]}))
    .unwrap();
    tx
}

/// A declaration accepted by a JDS: its new token and its coinbase halves.
#[derive(Debug)]
struct Declared {
    token: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    extranonce_len: usize,
}

/// Allocate a token on `jd`, declare `txs` at `HEIGHT` with a coinbase leaving
/// `extranonce_len` bytes, supply whatever the JDS asks for, and return what
/// DeclareMiningJob.Success issued.
async fn declare(jd: &mut Raw, request_id: u32, txs: &[Tx], extranonce_len: usize) -> Declared {
    declare_at(jd, request_id, HEIGHT, txs, extranonce_len)
        .await
        .unwrap_or_else(|answer| panic!("declaration {request_id} not accepted: {answer:?}"))
}

/// As `declare`, at `height`, returning the JDS's answer when it is not a success.
async fn declare_at(
    jd: &mut Raw,
    request_id: u32,
    height: u32,
    txs: &[Tx],
    extranonce_len: usize,
) -> Result<Declared, Box<Option<Message>>> {
    jd.send(&Message::AllocateMiningJobToken {
        user_identifier: b"netget".to_vec(),
        request_id,
    })
    .await;
    let Some(Message::AllocateMiningJobTokenSuccess {
        mining_job_token, ..
    }) = jd.recv().await
    else {
        panic!("no token")
    };
    let wtxids: Vec<[u8; 32]> = txs.iter().map(Tx::wtxid).collect();
    let outputs = vec![
        TxOut {
            value: 5_000_000_000,
            script: vec![0x51],
        },
        btc::witness_commitment(&wtxids, &[0u8; 32]),
    ];
    // The request id in the coinbase keeps every declaration's block distinct, so a
    // PushSolution (which names no job) matches exactly one.
    let (prefix, suffix) = netget::client::stratum_v2::job_declarator::declared_coinbase(
        height,
        format!("raw {request_id}").as_bytes(),
        &outputs,
        extranonce_len,
    );
    jd.send(&Message::DeclareMiningJob {
        request_id,
        mining_job_token,
        version: 0x2000_0000,
        coinbase_tx_prefix: prefix.clone(),
        coinbase_tx_suffix: suffix.clone(),
        wtxid_list: wtxids,
        excess_data: Vec::new(),
    })
    .await;
    let mut answer = jd.recv().await;
    if let Some(Message::ProvideMissingTransactions {
        unknown_tx_position_list,
        ..
    }) = &answer
    {
        jd.send(&Message::ProvideMissingTransactionsSuccess {
            request_id,
            transaction_list: unknown_tx_position_list
                .iter()
                .map(|i| txs[usize::from(*i)].serialize(true))
                .collect(),
        })
        .await;
        answer = jd.recv().await;
    }
    let Some(Message::DeclareMiningJobSuccess {
        new_mining_job_token,
        ..
    }) = answer
    else {
        return Err(Box::new(answer));
    };
    Ok(Declared {
        token: new_mining_job_token,
        prefix,
        suffix,
        extranonce_len,
    })
}

/// The SetCustomMiningJob a JDC sends for a declaration: every field as declared.
fn custom(channel_id: u32, request_id: u32, d: &Declared, txs: &[Tx]) -> Message {
    let (coinbase, _) = job_declarator::split_coinbase(&d.prefix, &d.suffix).unwrap();
    let script = &coinbase.inputs[0].script_sig;
    let txids: Vec<[u8; 32]> = txs.iter().map(Tx::txid).collect();
    Message::SetCustomMiningJob {
        channel_id,
        request_id,
        token: d.token.clone(),
        version: 0x2000_0000,
        prev_hash: PREV,
        min_ntime: wire::now_secs() - 60,
        nbits: NBITS,
        coinbase_tx_version: 2,
        coinbase_prefix: script[..script.len() - d.extranonce_len].to_vec(),
        coinbase_tx_input_n_sequence: u32::MAX,
        coinbase_tx_outputs: btc::output_vector_bytes(&coinbase.outputs),
        coinbase_tx_locktime: 0,
        merkle_path: btc::coinbase_merkle_path(&txids),
    }
}

fn refused(m: Option<Message>, request: u32, code: &str) -> bool {
    matches!(&m, Some(Message::SetCustomMiningJobError { request_id, error_code, .. })
        if *request_id == request && error_code == code.as_bytes())
}

/// A pool connection that negotiated work selection, with one extended channel: its id and
/// extranonce prefix. The pool's own job and prev hash that follow the channel are drained.
async fn work_selecting_channel(port: u16, user: &str) -> (Raw, u32, Vec<u8>) {
    let mut pool = Raw::connect(port).await;
    pool.send(&setup(
        0,
        wire::REQUIRES_WORK_SELECTION | wire::REQUIRES_VERSION_ROLLING,
    ))
    .await;
    assert!(matches!(
        pool.recv().await,
        Some(Message::SetupConnectionSuccess { .. })
    ));
    pool.send(&Message::OpenExtendedMiningChannel {
        request_id: 1,
        user_identity: user.as_bytes().to_vec(),
        nominal_hash_rate: 1000.0,
        max_target: [0xff; 32],
        min_extranonce_size: 8,
    })
    .await;
    let Some(Message::OpenExtendedMiningChannelSuccess {
        channel_id,
        extranonce_size: 8,
        extranonce_prefix,
        ..
    }) = pool.recv().await
    else {
        panic!("no extended channel")
    };
    assert!(matches!(
        pool.recv().await,
        Some(Message::NewExtendedMiningJob { .. })
    ));
    assert!(matches!(
        pool.recv().await,
        Some(Message::SetNewPrevHash { .. })
    ));
    (pool, channel_id, extranonce_prefix)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_jobs_are_checked_against_their_declaration() {
    let (state, id, port, status) = support::start_role(
        support::script(POLICY),
        json!({"role": "pool_and_job_declarator", "network": "regtest",
               "authority_secret_key": SECRET}),
    )
    .await;

    // A plain pool still refuses work selection: it has no token table to redeem against.
    let (_plain_state, _plain_id, plain_port, _) = support::start_role(
        support::script(POLICY),
        json!({"role": "pool", "authority_secret_key": SECRET}),
    )
    .await;
    let mut plain = Raw::connect(plain_port).await;
    plain.send(&setup(0, wire::REQUIRES_WORK_SELECTION)).await;
    assert!(matches!(plain.recv().await,
        Some(Message::SetupConnectionError { flags, error_code })
            if flags == wire::REQUIRES_WORK_SELECTION && error_code == b"unsupported-feature-flags"));

    // The job declarator half of the same port.
    let mut jd = Raw::connect(port).await;
    jd.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    assert!(matches!(
        jd.recv().await,
        Some(Message::SetupConnectionSuccess { flags: 1, .. })
    ));
    let txs = [tx(0x41), tx(0x42), tx(0x43)];
    let (mut pool, channel, prefix) = work_selecting_channel(port, "netget.hard").await;
    let full = prefix.len() + 8;

    // A token nobody issued, and one this channel cannot use: refused before anything else.
    let good = declare(&mut jd, 10, &txs, full).await;
    let mut unknown = custom(channel, 1, &good, &txs);
    if let Message::SetCustomMiningJob { token, .. } = &mut unknown {
        *token = vec![0x99; 8];
    }
    pool.send(&unknown).await;
    assert!(refused(pool.recv().await, 1, "invalid-mining-job-token"));
    pool.send(&custom(channel + 50, 2, &good, &txs)).await;
    assert!(refused(pool.recv().await, 2, "invalid-channel-id"));

    // Every field that disagrees with the declaration, each on a fresh token, refused with
    // its own code before the model is asked.
    type Mutate = fn(&mut Message);
    let cases: Vec<(&str, Mutate)> = vec![
        ("invalid-version", |m| {
            if let Message::SetCustomMiningJob { version, .. } = m {
                *version ^= 0x0000_0004;
            }
        }),
        ("invalid-nbits", |m| {
            if let Message::SetCustomMiningJob { nbits, .. } = m {
                *nbits = 0x2100_ffff;
            }
        }),
        ("invalid-min-ntime", |m| {
            if let Message::SetCustomMiningJob { min_ntime, .. } = m {
                *min_ntime = wire::now_secs() + 3 * 3600;
            }
        }),
        ("invalid-coinbase-tx-version", |m| {
            if let Message::SetCustomMiningJob {
                coinbase_tx_version,
                ..
            } = m
            {
                *coinbase_tx_version = 1;
            }
        }),
        ("invalid-coinbase-prefix", |m| {
            if let Message::SetCustomMiningJob {
                coinbase_prefix, ..
            } = m
            {
                coinbase_prefix[2] ^= 1;
            }
        }),
        ("invalid-coinbase-tx-input-n-sequence", |m| {
            if let Message::SetCustomMiningJob {
                coinbase_tx_input_n_sequence,
                ..
            } = m
            {
                *coinbase_tx_input_n_sequence = 0;
            }
        }),
        ("invalid-coinbase-tx-outputs", |m| {
            if let Message::SetCustomMiningJob {
                coinbase_tx_outputs,
                ..
            } = m
            {
                coinbase_tx_outputs[1] ^= 1;
            }
        }),
        ("invalid-coinbase-tx-locktime", |m| {
            if let Message::SetCustomMiningJob {
                coinbase_tx_locktime,
                ..
            } = m
            {
                *coinbase_tx_locktime = 1;
            }
        }),
        ("invalid-merkle-path", |m| {
            if let Message::SetCustomMiningJob { merkle_path, .. } = m {
                merkle_path.swap(0, 1);
            }
        }),
    ];
    for (i, (code, mutate)) in cases.into_iter().enumerate() {
        let d = declare(&mut jd, 100 + i as u32, &txs, full).await;
        let mut m = custom(channel, 100 + i as u32, &d, &txs);
        mutate(&mut m);
        pool.send(&m).await;
        let answer = pool.recv().await;
        assert!(
            refused(answer.clone(), 100 + i as u32, code),
            "{code}: {answer:?}"
        );
        // The token was spent by the refusal: the unaltered job cannot use it either.
        pool.send(&custom(channel, 200 + i as u32, &d, &txs)).await;
        assert!(refused(
            pool.recv().await,
            200 + i as u32,
            "invalid-mining-job-token"
        ));
    }
    // A declaration whose coinbase leaves room for a different extranonce than the channel's.
    let narrow = declare(&mut jd, 20, &txs, full - 1).await;
    pool.send(&custom(channel, 20, &narrow, &txs)).await;
    assert!(refused(pool.recv().await, 20, "invalid-coinbase-prefix"));
    assert!(
        support::events(&state, id, "stratum_v2_custom_job")
            .await
            .is_empty(),
        "nothing so far was the model's to decide"
    );

    // The model failing refuses the job and spends the token; the model refusing names its
    // code.
    let failing = declare(&mut jd, 30, &txs, full).await;
    let mut m = custom(channel, 30, &failing, &txs);
    if let Message::SetCustomMiningJob { min_ntime, .. } = &mut m {
        *min_ntime = 4242;
    }
    pool.send(&m).await;
    assert!(refused(pool.recv().await, 30, "service-unavailable"));
    pool.send(&custom(channel, 31, &failing, &txs)).await;
    assert!(refused(pool.recv().await, 31, "invalid-mining-job-token"));
    assert!(status
        .text()
        .contains("operation=set_custom_mining_job decision=fail_closed"));
    let (mut refused_pool, refused_channel, _) = work_selecting_channel(port, "refused").await;
    let r = declare(&mut jd, 32, &txs, full).await;
    refused_pool
        .send(&custom(refused_channel, 32, &r, &txs))
        .await;
    assert!(refused(refused_pool.recv().await, 32, "not-your-job"));

    // A token another server's job declarator issued is not this server's to redeem.
    let (_other_state, _other_id, other_port, _) = support::start_role(
        support::script(POLICY),
        json!({"role": "job_declarator", "network": "regtest", "authority_secret_key": SECRET}),
    )
    .await;
    let mut other = Raw::connect(other_port).await;
    other.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    let _ = other.recv().await;
    let foreign = declare(&mut other, 40, &txs, full).await;
    pool.send(&custom(channel, 40, &foreign, &txs)).await;
    assert!(refused(pool.recv().await, 40, "invalid-mining-job-token"));

    // Done right: accepted, then the token is gone.
    pool.send(&custom(channel, 50, &good, &txs)).await;
    let Some(Message::SetCustomMiningJobSuccess {
        channel_id,
        request_id: 50,
        job_id,
    }) = pool.recv().await
    else {
        panic!("the custom job was not accepted")
    };
    assert_eq!(channel_id, channel);
    pool.send(&custom(channel, 51, &good, &txs)).await;
    assert!(refused(pool.recv().await, 51, "invalid-mining-job-token"));
    let asked = support::events(&state, id, "stratum_v2_custom_job").await;
    let accepted = asked
        .iter()
        .find(|e| e["request_id"] == 50)
        .unwrap_or_else(|| panic!("{asked:?}"));
    assert_eq!(accepted["height"], HEIGHT, "{accepted}");
    assert_eq!(accepted["transactions"], 3, "{accepted}");
    assert_eq!(accepted["tip_checked"], false, "no node: {accepted}");
    assert_eq!(accepted["declaration_request_id"], 10, "{accepted}");

    // Shares on the custom job: the pool rebuilds the declared coinbase around the channel's
    // extranonce and folds its txid up the path. The channel is at difficulty 1, harder than
    // the job's nbits, so a hash can meet the network target and miss the channel's: that is a
    // block, and a block is never refused. PushSolution on the JDS side of the same server
    // rebuilds the same block.
    let extranonce = [7u8; 8];
    let coinbase = [&good.prefix[..], &prefix, &extranonce, &good.suffix[..]].concat();
    let txids: Vec<[u8; 32]> = txs.iter().map(Tx::txid).collect();
    let root = btc::fold_path(
        Tx::parse(&coinbase).unwrap().txid(),
        &btc::coinbase_merkle_path(&txids),
    );
    let ntime = wire::now_secs();
    let network = btc::compact_to_target(NBITS).unwrap();
    let (miss, _) = support::find_nonce(0x2000_0000, &PREV, &root, ntime, NBITS, &network, false);
    pool.send(&Message::SubmitSharesExtended {
        channel_id: channel,
        sequence_number: 0,
        job_id,
        nonce: miss,
        ntime,
        version: 0x2000_0000,
        extranonce: extranonce.to_vec(),
    })
    .await;
    assert!(matches!(pool.recv().await,
        Some(Message::SubmitSharesError { sequence_number: 0, error_code, .. }) if error_code == b"difficulty-too-low"));
    let (nonce, hash) =
        support::find_nonce(0x2000_0000, &PREV, &root, ntime, NBITS, &network, true);
    pool.send(&Message::SubmitSharesExtended {
        channel_id: channel,
        sequence_number: 1,
        job_id,
        nonce,
        ntime,
        version: 0x2000_0000,
        extranonce: extranonce.to_vec(),
    })
    .await;
    assert!(matches!(
        pool.recv().await,
        Some(Message::SubmitSharesSuccess {
            last_sequence_number: 1,
            ..
        })
    ));
    let share = &support::events(&state, id, "stratum_v2_share").await[0];
    assert_eq!(share["hash"], wire::display_hex(&hash), "{share}");
    assert_eq!(share["custom_job"], true, "{share}");
    assert_eq!(share["solves_block"], true, "{share}");
    assert!(
        status
            .text()
            .contains(&format!("is block {}", wire::display_hex(&hash))),
        "{}",
        status.text()
    );
    assert!(share["relay"].is_null(), "no node, no relay: {share}");
    jd.send(&Message::PushSolution {
        extranonce: [&prefix[..], &extranonce].concat(),
        prev_hash: PREV,
        nonce,
        ntime,
        nbits: NBITS,
        version: 0x2000_0000,
    })
    .await;
    let pushed = wait_events(&state, id, "stratum_v2_jd_solution", 20, |_| true).await;
    assert_eq!(pushed.len(), 1, "{pushed:?}");
    assert_eq!(pushed[0]["hash"], wire::display_hex(&hash));
    assert_eq!(pushed[0]["request_id"], 10);

    // Work selection is a negotiated feature: SetCustomMiningJob without it ends the session.
    let mut device = Raw::connect(port).await;
    device.send(&setup(0, wire::REQUIRES_VERSION_ROLLING)).await;
    let _ = device.recv().await;
    let d = declare(&mut jd, 60, &txs, full).await;
    device.send(&custom(1, 60, &d, &txs)).await;
    assert!(device.recv().await.is_none());
}

/// With a node (`bitcoin_rpc_url`, raw frames, Bitcoin Core 31.0 regtest): a declaration must
/// commit to the node's next height, a custom job must build on the tip recorded with its
/// declaration and carry that block's nbits, and a share on it that meets nbits is a block the
/// pool relays — the node's tip becomes NetGet's block, assembled from the declaration and the
/// share, with nobody else submitting it. PushSolution for the same block is not relayed twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declarations_and_custom_jobs_are_checked_against_the_node() {
    let node = peers::Regtest::start(false, 101).await;
    let (tip, height, earliest) = node.tip().await;
    let next = u32::try_from(height + 1).unwrap();
    let tip_bytes = wire::parse_display_hash(Some(&tip)).unwrap();
    let (state, id, port, status) = support::start_role(
        support::script(POLICY),
        json!({"role": "pool_and_job_declarator", "network": "regtest",
               "authority_secret_key": SECRET,
               "bitcoin_rpc_url": format!("http://127.0.0.1:{}", node.rpc),
               "bitcoin_rpc_user": "netget", "bitcoin_rpc_password": "netget"}),
    )
    .await;
    let mut jd = Raw::connect(port).await;
    jd.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    assert!(matches!(
        jd.recv().await,
        Some(Message::SetupConnectionSuccess { .. })
    ));
    let (mut pool, channel, prefix) = work_selecting_channel(port, "netget.ws").await;
    let full = prefix.len() + 8;

    // A height that is not the node's next block.
    let stale = declare_at(&mut jd, 1, next + 5, &[], full).await;
    assert!(
        matches!(stale.as_ref().map_err(|e| e.as_ref()), Err(Some(Message::DeclareMiningJobError { error_code, .. })) if error_code == b"stale-chain-tip"),
        "{stale:?}"
    );

    // Another prev hash, then nbits the node's next block does not have.
    let d = declare_at(&mut jd, 2, next, &[], full).await.unwrap();
    let mut m = custom(channel, 2, &d, &[]);
    if let Message::SetCustomMiningJob { nbits, .. } = &mut m {
        *nbits = 0x207f_ffff;
    }
    pool.send(&m).await;
    assert!(refused(pool.recv().await, 2, "stale-chain-tip"));
    let d = declare_at(&mut jd, 3, next, &[], full).await.unwrap();
    let mut m = custom(channel, 3, &d, &[]);
    if let Message::SetCustomMiningJob {
        prev_hash, nbits, ..
    } = &mut m
    {
        *prev_hash = tip_bytes;
        *nbits = 0x1f00_ffff;
    }
    pool.send(&m).await;
    assert!(refused(pool.recv().await, 3, "invalid-nbits"));

    // On the node's tip with its nbits: taken, and its first share is a block.
    let d = declare_at(&mut jd, 4, next, &[], full).await.unwrap();
    let mut m = custom(channel, 4, &d, &[]);
    if let Message::SetCustomMiningJob {
        prev_hash, nbits, ..
    } = &mut m
    {
        *prev_hash = tip_bytes;
        *nbits = 0x207f_ffff;
    }
    pool.send(&m).await;
    let Some(Message::SetCustomMiningJobSuccess { job_id, .. }) = pool.recv().await else {
        panic!(
            "the custom job on the node's tip was not accepted:\n{}",
            status.text()
        )
    };
    let asked = support::events(&state, id, "stratum_v2_custom_job").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["tip_checked"], true);
    assert_eq!(asked[0]["prev_hash"], tip.as_str());
    let declared = support::events(&state, id, "stratum_v2_jd_declare_job").await;
    assert!(
        declared.iter().all(|e| e["prev_hash"] == tip.as_str()),
        "{declared:?}"
    );

    let extranonce = [9u8; 8];
    let coinbase = [&d.prefix[..], &prefix, &extranonce, &d.suffix[..]].concat();
    let root = Tx::parse(&coinbase).unwrap().txid();
    // Quickly generated regtest blocks put the median time past ahead of the clock.
    let ntime = wire::now_secs().max(u32::try_from(earliest).unwrap());
    let (nonce, hash) = support::find_nonce(
        0x2000_0000,
        &tip_bytes,
        &root,
        ntime,
        0x207f_ffff,
        &btc::compact_to_target(0x207f_ffff).unwrap(),
        true,
    );
    pool.send(&Message::SubmitSharesExtended {
        channel_id: channel,
        sequence_number: 1,
        job_id,
        nonce,
        ntime,
        version: 0x2000_0000,
        extranonce: extranonce.to_vec(),
    })
    .await;
    assert!(matches!(
        pool.recv().await,
        Some(Message::SubmitSharesSuccess { .. })
    ));
    let hash = wire::display_hex(&hash);
    assert_eq!(
        node.cli(&["getbestblockhash"]).await.as_deref(),
        Ok(hash.as_str()),
        "NetGet's pool relayed nothing the node took:\n{}",
        status.text()
    );
    let block: Value = node.json(&["getblock", &hash, "2"]).await;
    assert_eq!(block["height"], next, "{block}");
    assert_eq!(
        block["tx"][0]["vout"][0]["scriptPubKey"]["asm"], "1",
        "{block}"
    );
    let share = &support::events(&state, id, "stratum_v2_share").await[0];
    assert_eq!(share["relay"], "accepted", "{share}");

    // The same block pushed to the JDS is rebuilt to the same hash and not relayed again.
    jd.send(&Message::PushSolution {
        extranonce: [&prefix[..], &extranonce].concat(),
        prev_hash: tip_bytes,
        nonce,
        ntime,
        nbits: 0x207f_ffff,
        version: 0x2000_0000,
    })
    .await;
    let pushed = wait_events(&state, id, "stratum_v2_jd_solution", 20, |_| true).await;
    assert_eq!(pushed.len(), 1, "{pushed:?}");
    assert_eq!(pushed[0]["hash"], hash.as_str());
    assert_eq!(pushed[0]["relay"], "already-relayed");
}
