//! The template provider and job declarator roles from raw frames written with NetGet's own
//! codec: every refusal Rust decides without asking the model, every bound a peer can push
//! against, and both fail-closed paths. The real-peer tests (`template_provider_test`,
//! `job_declarator_test`) prove the happy paths against SRI; these prove what SRI never sends.
use super::support::{self, Raw};
use netget::server::stratum_v2::bitcoin::{self as btc, Tx, TxIn, TxOut};
use netget::server::stratum_v2::{job_declarator, template_provider, wire, wire::Message};
use serde_json::{json, Value};

/// Regtest's easiest target, which most hashes meet.
const NBITS: u32 = 0x207f_ffff;
const PREV: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

fn setup(protocol: u8, flags: u32) -> Message {
    Message::SetupConnection {
        protocol,
        min_version: 2,
        max_version: 2,
        flags,
        endpoint_host: b"127.0.0.1".to_vec(),
        endpoint_port: 8442,
        vendor: b"raw".to_vec(),
        hardware_version: Vec::new(),
        firmware: Vec::new(),
        device_id: Vec::new(),
    }
}

/// A transaction as the model writes it: spends `txid:0` worth `value`, pays `value - fee`.
fn model_tx(txid_byte: &str, value: u64, fee: u64) -> Value {
    json!({"inputs": [{"txid": txid_byte.repeat(32), "vout": 0, "value_sats": value}],
           "outputs": [{"value_sats": value - fee, "pay_to": "op_true"}]})
}

/// The coinbase a pool builds on a template: its prefix, a tag, an extranonce; its own output
/// with the template's value, then the template's outputs; the 32-byte witness reserved value.
fn pool_coinbase(prefix: &[u8], value: u64, template_outputs: &[u8], count: u32) -> Tx {
    let mut script = prefix.to_vec();
    script.extend_from_slice(&[4, b'r', b'a', b'w', b'!', 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    let mut outputs = vec![TxOut {
        value,
        script: vec![0x51],
    }];
    let vector = [&[count as u8][..], template_outputs].concat();
    outputs.extend(btc::parse_output_vector(&vector, 16).unwrap());
    Tx {
        version: 2,
        inputs: vec![TxIn {
            prev_txid: [0; 32],
            vout: u32::MAX,
            script_sig: script,
            sequence: u32::MAX,
            witness: vec![vec![0; 32]],
        }],
        outputs,
        locktime: 0,
    }
}

const TP_POLICY: &str = r#"if t=='stratum_v2_tp_setup_connection':
  a=[{'type':'stratum_v2_accept'}] if e['vendor']!='blocked' else [{'type':'stratum_v2_reject','error_code':'not-today'}]
elif t=='stratum_v2_tp_coinbase_output_constraints' and e['templates_sent']==0:
  txs=[{'inputs':[{'txid':'11'*32,'vout':0,'value_sats':100000}],'outputs':[{'value_sats':90000,'pay_to':'op_true'}]},{'inputs':[{'txid':'22'*32,'vout':0,'value_sats':50000}],'outputs':[{'value_sats':45000,'pay_to':'op_true'},{'value_sats':0,'op_return':'hi'}]}]
  a=[{'type':'stratum_v2_new_template','prev_hash':'PREV','height':200,'nbits':'2100ffff','transactions':txs},
     {'type':'stratum_v2_new_template','prev_hash':'PREV','height':200,'coinbase_value_sats':2500015001,'transactions':txs},
     {'type':'stratum_v2_new_template','prev_hash':'PREV','height':200,'transactions':txs}]
elif t=='stratum_v2_tp_coinbase_output_constraints':
  a=[{'type':'stratum_v2_new_template','prev_hash':'00'*31+'bb','height':201}]"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_provider_builds_answers_and_verifies_by_the_rules() {
    let (state, id, port, _status) = support::start_role(
        support::script(&TP_POLICY.replace("PREV", PREV)),
        json!({"role": "template_provider", "network": "regtest",
               "authority_secret_key": support::SECRET}),
    )
    .await;

    // The wrong protocol, a flag TDP does not define, and anything before SetupConnection.
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(0, 0)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { error_code, .. }) if error_code == b"unsupported-protocol"));
    assert!(raw.recv().await.is_none());
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(2, 1)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { flags: 1, error_code }) if error_code == b"unsupported-feature-flags"));
    let mut raw = Raw::connect(port).await;
    raw.send(&Message::RequestTransactionData { template_id: 1 })
        .await;
    assert!(raw.recv().await.is_none(), "a message before setup ends it");
    assert_eq!(
        support::events(&state, id, "stratum_v2_tp_setup_connection")
            .await
            .len(),
        0
    );

    let mut raw = Raw::connect(port).await;
    raw.send(&setup(2, 0)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SetupConnectionSuccess { .. })
    ));
    raw.send(&Message::CoinbaseOutputConstraints {
        max_additional_size: 100,
        max_additional_sigops: 4,
    })
    .await;
    // Of the model's three templates, nbits easier than regtest allows and a coinbase
    // claiming a sat more than subsidy plus fees are refused; the third is sent.
    let Some(Message::NewTemplate {
        template_id,
        future_template,
        coinbase_prefix,
        coinbase_tx_value_remaining,
        coinbase_tx_outputs_count,
        coinbase_tx_outputs,
        merkle_path,
        version,
        ..
    }) = raw.recv().await
    else {
        panic!("no template")
    };
    assert_eq!(template_id, 1, "the refused templates took no id");
    assert!(future_template);
    assert_eq!(version, template_provider::DEFAULT_VERSION);
    // Height 200 is 0xc8, which needs a sign byte: push 2, c8 00.
    assert_eq!(coinbase_prefix, vec![2, 0xc8, 0]);
    // Regtest halves every 150 blocks: 25 BTC, plus 10000 + 5000 in fees.
    assert_eq!(coinbase_tx_value_remaining, 2_500_000_000 + 15_000);
    assert_eq!(coinbase_tx_outputs_count, 1);
    let Some(Message::TemplateSetNewPrevHash {
        template_id: 1,
        prev_hash,
        nbits,
        target,
        ..
    }) = raw.recv().await
    else {
        panic!("no SetNewPrevHash after a template on a new tip")
    };
    assert_eq!(wire::display_hex(&prev_hash), PREV);
    assert_eq!(nbits, NBITS);
    assert_eq!(target, btc::compact_to_target(NBITS).unwrap());

    // The transactions back, exactly as committed to: the path folds every coinbase to the
    // root of the full tree, and the commitment covers their wtxids.
    raw.send(&Message::RequestTransactionData { template_id: 1 })
        .await;
    let Some(Message::RequestTransactionDataSuccess {
        template_id: 1,
        transaction_list,
        ..
    }) = raw.recv().await
    else {
        panic!("no transaction data")
    };
    assert_eq!(transaction_list.len(), 2);
    let txs: Vec<Tx> = transaction_list
        .iter()
        .map(|t| Tx::parse(t).unwrap())
        .collect();
    let cb = pool_coinbase(
        &coinbase_prefix,
        coinbase_tx_value_remaining,
        &coinbase_tx_outputs,
        coinbase_tx_outputs_count,
    );
    let leaves = [cb.txid(), txs[0].txid(), txs[1].txid()];
    assert_eq!(merkle_path.len(), 2);
    assert_eq!(
        btc::fold_path(cb.txid(), &merkle_path),
        btc::merkle_root(&leaves),
        "the path does not fold to the tree's root"
    );
    let commitment = btc::witness_commitment(&[txs[0].wtxid(), txs[1].wtxid()], &[0u8; 32]);
    assert_eq!(cb.outputs.last(), Some(&commitment));
    raw.send(&Message::RequestTransactionData { template_id: 9 })
        .await;
    assert!(matches!(raw.recv().await,
        Some(Message::RequestTransactionDataError { template_id: 9, error_code }) if error_code == b"template-id-not-found"));

    // Solutions: Rust rebuilds the header; a hash above the target, a coinbase paying more
    // than the template allows, and a coinbase without the template's height never reach the
    // model; a valid one does, once.
    let ntime = wire::now_secs();
    let solve = |cb: &Tx, meet: bool| {
        let root = btc::fold_path(cb.txid(), &merkle_path);
        support::find_nonce(version, &prev_hash, &root, ntime, NBITS, &target, meet)
    };
    let submit = |cb: &Tx, nonce: u32| Message::SubmitSolution {
        template_id: 1,
        version,
        header_timestamp: ntime,
        header_nonce: nonce,
        coinbase_tx: cb.serialize(true),
    };
    let (miss, _) = solve(&cb, false);
    raw.send(&submit(&cb, miss)).await;
    let mut greedy = cb.clone();
    greedy.outputs[0].value += 1;
    let (n, _) = solve(&greedy, true);
    raw.send(&submit(&greedy, n)).await;
    let mut headless = cb.clone();
    headless.inputs[0].script_sig[1] ^= 1;
    let (n, _) = solve(&headless, true);
    raw.send(&submit(&headless, n)).await;
    let (nonce, hash) = solve(&cb, true);
    raw.send(&submit(&cb, nonce)).await;
    raw.send(&submit(&cb, nonce)).await;
    raw.send(&Message::CoinbaseOutputConstraints {
        max_additional_size: 100,
        max_additional_sigops: 4,
    })
    .await;
    // The model's answer to the second constraints moves the tip: template 2, future, then
    // its prev hash; template 1 is stale from then on.
    assert!(matches!(
        raw.recv().await,
        Some(Message::NewTemplate {
            template_id: 2,
            future_template: true,
            ..
        })
    ));
    assert!(matches!(
        raw.recv().await,
        Some(Message::TemplateSetNewPrevHash { template_id: 2, .. })
    ));
    raw.send(&Message::RequestTransactionData { template_id: 1 })
        .await;
    assert!(matches!(raw.recv().await,
        Some(Message::RequestTransactionDataError { template_id: 1, error_code }) if error_code == b"stale-template-id"));
    let solutions = support::events(&state, id, "stratum_v2_tp_solution").await;
    assert_eq!(solutions.len(), 1, "{solutions:?}");
    assert_eq!(solutions[0]["hash"], wire::display_hex(&hash));
    assert_eq!(solutions[0]["height"], 200);
    assert_eq!(solutions[0]["transactions"], 2);

    // A refused device is shown the model's code.
    let mut raw = Raw::connect(port).await;
    raw.send(&Message::SetupConnection {
        protocol: 2,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: Vec::new(),
        endpoint_port: 0,
        vendor: b"blocked".to_vec(),
        hardware_version: Vec::new(),
        firmware: Vec::new(),
        device_id: Vec::new(),
    })
    .await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { error_code, .. }) if error_code == b"not-today"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_provider_fails_closed_and_bounds_frames() {
    // No handler and no reachable model: setup is refused, nothing is invented.
    let (state, id, port, _status) = support::start_role(
        None,
        json!({"role": "template_provider", "authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(2, 0)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { error_code, .. }) if error_code == b"service-unavailable"));
    assert_eq!(
        support::events(&state, id, "stratum_v2_tp_setup_connection")
            .await
            .len(),
        1
    );

    // Frames: exactly the bound is read (an unknown extension, ignored); one more ends it.
    let (_s, _i, port, _status) = support::start_role(
        support::script("a=[{'type':'stratum_v2_accept'}]"),
        json!({"role": "template_provider", "authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(2, 0)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SetupConnectionSuccess { .. })
    ));
    raw.frame(&wire::Frame {
        extension_type: 0x0042,
        msg_type: 1,
        payload: vec![0; template_provider::MAX_INBOUND_PAYLOAD],
    })
    .await;
    raw.send(&Message::RequestTransactionData { template_id: 5 })
        .await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::RequestTransactionDataError { .. })
    ));
    raw.frame(&wire::Frame {
        extension_type: 0x0042,
        msg_type: 1,
        payload: vec![0; template_provider::MAX_INBOUND_PAYLOAD + 1],
    })
    .await;
    assert!(raw.recv().await.is_none(), "a frame over the bound ends it");
}

const JDS_POLICY: &str = r#"if t=='stratum_v2_jd_setup_connection':
  a=[{'type':'stratum_v2_accept'}]
elif t=='stratum_v2_jd_allocate_token':
  a=[{'type':'stratum_v2_accept'},{'type':'stratum_v2_allocate_token','pay_to':'op_true'}] if e['user_identifier']!='nobody' else [{'type':'stratum_v2_reject','error_code':'unknown-user'}]
elif t=='stratum_v2_jd_declare_job':
  if e['transactions']==99: sys.exit(3)
  a=[{'type':'stratum_v2_accept'}] if e['pays_required_outputs'] else [{'type':'stratum_v2_reject','error_code':'missing-pool-output'}]"#;

/// A declared job as a JDC builds one: the coinbase split around 8 bytes of extranonce.
fn declare(
    request_id: u32,
    token: &[u8],
    txs: &[Tx],
    pays_pool: bool,
    commitment: bool,
) -> Message {
    let wtxids: Vec<[u8; 32]> = txs.iter().map(Tx::wtxid).collect();
    let mut outputs = vec![TxOut {
        value: 5_000_000_000,
        script: if pays_pool { vec![0x51] } else { vec![0x6a] },
    }];
    if commitment {
        outputs.push(btc::witness_commitment(&wtxids, &[0u8; 32]));
    }
    let (prefix, suffix) =
        netget::client::stratum_v2::job_declarator::declared_coinbase(300, b"raw", &outputs, 8);
    Message::DeclareMiningJob {
        request_id,
        mining_job_token: token.to_vec(),
        version: 0x2000_0000,
        coinbase_tx_prefix: prefix,
        coinbase_tx_suffix: suffix,
        wtxid_list: wtxids,
        excess_data: Vec::new(),
    }
}

fn tx(seed: u8) -> Tx {
    let (tx, _) = btc::tx_from_json(&model_tx(&format!("{seed:02x}"), 100_000, 1000)).unwrap();
    tx
}

async fn allocate(raw: &mut Raw, request_id: u32, user: &str) -> Option<Vec<u8>> {
    raw.send(&Message::AllocateMiningJobToken {
        user_identifier: user.as_bytes().to_vec(),
        request_id,
    })
    .await;
    match raw.recv().await? {
        Message::AllocateMiningJobTokenSuccess {
            request_id: r,
            mining_job_token,
            coinbase_outputs,
        } => {
            assert_eq!(r, request_id);
            assert_eq!(
                btc::parse_output_vector(&coinbase_outputs, 4).unwrap(),
                vec![TxOut {
                    value: 0,
                    script: vec![0x51]
                }]
            );
            Some(mining_job_token)
        }
        other => panic!("{other:?}"),
    }
}

fn is_error(m: Option<Message>, request: u32, code: &str) -> bool {
    matches!(m, Some(Message::DeclareMiningJobError { request_id, error_code, .. })
        if request_id == request && error_code == code.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_declarator_keeps_tokens_transactions_and_solutions_by_the_rules() {
    let (state, id, port, _status) = support::start_role(
        support::script(JDS_POLICY),
        json!({"role": "job_declarator", "network": "regtest",
               "authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(1, 2)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { flags: 2, error_code }) if error_code == b"unsupported-feature-flags"));

    let mut raw = Raw::connect(port).await;
    raw.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SetupConnectionSuccess { flags: 1, .. })
    ));
    let a = allocate(&mut raw, 1, "netget").await.unwrap();
    assert_eq!(a.len(), 8);

    // A token never issued, then a declaration whose count is over the bound: refused before
    // the model, and neither spends a token.
    raw.send(&declare(10, &[9; 8], &[], true, true)).await;
    assert!(is_error(raw.recv().await, 10, "invalid-mining-job-token"));
    let mut huge = declare(11, &a, &[], true, true);
    if let Message::DeclareMiningJob { wtxid_list, .. } = &mut huge {
        *wtxid_list = vec![[7; 32]; job_declarator::MAX_DECLARED_TXS + 1];
    }
    raw.send(&huge).await;
    assert!(is_error(raw.recv().await, 11, "invalid-job"));

    // The JDS has none of the declared transactions: it asks for both. A transaction that is
    // not the one the wtxid named refuses the job and spends the token.
    let (t1, t2) = (tx(0x31), tx(0x32));
    raw.send(&declare(12, &a, &[t1.clone(), t2.clone()], true, true))
        .await;
    assert!(matches!(raw.recv().await,
        Some(Message::ProvideMissingTransactions { request_id: 12, unknown_tx_position_list }) if unknown_tx_position_list == vec![0, 1]));
    raw.send(&Message::ProvideMissingTransactionsSuccess {
        request_id: 12,
        transaction_list: vec![t1.serialize(true), tx(0x33).serialize(true)],
    })
    .await;
    assert!(is_error(raw.recv().await, 12, "invalid-job"));
    raw.send(&declare(13, &a, &[t1.clone()], true, true)).await;
    assert!(
        is_error(raw.recv().await, 13, "invalid-mining-job-token"),
        "a refused declaration's token is spent"
    );
    assert!(
        support::events(&state, id, "stratum_v2_jd_declare_job")
            .await
            .is_empty(),
        "nothing so far was the model's to decide"
    );

    // Done right: asked for, supplied, checked, accepted with a new token. t1 is now known,
    // so a second job naming it asks only for what is new.
    let b = allocate(&mut raw, 2, "netget").await.unwrap();
    raw.send(&declare(14, &b, &[t1.clone(), t2.clone()], true, true))
        .await;
    assert!(matches!(raw.recv().await,
        Some(Message::ProvideMissingTransactions { request_id: 14, unknown_tx_position_list }) if unknown_tx_position_list == vec![1]));
    raw.send(&Message::ProvideMissingTransactionsSuccess {
        request_id: 14,
        transaction_list: vec![t2.serialize(true)],
    })
    .await;
    let Some(Message::DeclareMiningJobSuccess {
        request_id: 14,
        new_mining_job_token,
    }) = raw.recv().await
    else {
        panic!("the job was not accepted")
    };
    assert_eq!(new_mining_job_token.len(), 8);
    assert_ne!(new_mining_job_token, b);
    raw.send(&declare(15, &b, &[], true, true)).await;
    assert!(is_error(raw.recv().await, 15, "invalid-mining-job-token"));

    // A coinbase whose witness commitment does not cover its transactions is refused in Rust;
    // one not paying the token's output reaches the model, which refuses it.
    let c = allocate(&mut raw, 3, "netget").await.unwrap();
    let mut bad = declare(16, &c, &[t1.clone()], true, true);
    if let Message::DeclareMiningJob { wtxid_list, .. } = &mut bad {
        wtxid_list.push(t2.wtxid());
    }
    raw.send(&bad).await;
    assert!(is_error(raw.recv().await, 16, "invalid-job"));
    let d = allocate(&mut raw, 4, "netget").await.unwrap();
    raw.send(&declare(17, &d, &[t1.clone()], false, true)).await;
    assert!(is_error(raw.recv().await, 17, "missing-pool-output"));
    let declared = support::events(&state, id, "stratum_v2_jd_declare_job").await;
    assert_eq!(declared.len(), 2, "{declared:?}");
    // The access log lists newest first.
    assert_eq!(declared[1]["height"], 300);
    assert_eq!(declared[1]["transactions"], 2);
    assert_eq!(declared[1]["pays_required_outputs"], true);
    assert_eq!(declared[0]["pays_required_outputs"], false);

    // The token table holds MAX_TOKENS: the oldest of MAX_TOKENS + 1 is gone.
    let first = allocate(&mut raw, 100, "netget").await.unwrap();
    let mut last = Vec::new();
    for i in 0..job_declarator::MAX_TOKENS as u32 {
        last = allocate(&mut raw, 101 + i, "netget").await.unwrap();
    }
    raw.send(&declare(18, &first, &[], true, true)).await;
    assert!(
        is_error(raw.recv().await, 18, "invalid-mining-job-token"),
        "the oldest token outlived the table's bound"
    );
    raw.send(&declare(19, &last, &[], true, true)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::DeclareMiningJobSuccess { request_id: 19, .. })
    ));

    // PushSolution: the accepted job (14), mined with an extranonce, reaches the model; a hash
    // above nbits does not. The message names no job, so a target this easy that any job's
    // header might meet would make the match ambiguous; 0x1f00ffff leaves a 2^-16 chance.
    let Message::DeclareMiningJob {
        coinbase_tx_prefix,
        coinbase_tx_suffix,
        ..
    } = declare(14, &b, &[t1.clone(), t2.clone()], true, true)
    else {
        unreachable!()
    };
    let extranonce = [5u8; 8];
    let coinbase = [
        &coinbase_tx_prefix[..],
        &extranonce,
        &coinbase_tx_suffix[..],
    ]
    .concat();
    let root = btc::merkle_root(&[Tx::parse(&coinbase).unwrap().txid(), t1.txid(), t2.txid()]);
    let prev = [0x44u8; 32];
    let bits = 0x1f00_ffff;
    let target = btc::compact_to_target(bits).unwrap();
    let ntime = wire::now_secs();
    let push = |nonce: u32| Message::PushSolution {
        extranonce: extranonce.to_vec(),
        prev_hash: prev,
        nonce,
        ntime,
        nbits: bits,
        version: 0x2000_0000,
    };
    let (miss, _) = support::find_nonce(0x2000_0000, &prev, &root, ntime, bits, &target, false);
    raw.send(&push(miss)).await;
    let (nonce, hash) = support::find_nonce(0x2000_0000, &prev, &root, ntime, bits, &target, true);
    raw.send(&push(nonce)).await;
    // Something answered after both, so both were handled.
    let _ = allocate(&mut raw, 200, "netget").await.unwrap();
    let solutions = support::events(&state, id, "stratum_v2_jd_solution").await;
    assert_eq!(solutions.len(), 1, "{solutions:?}");
    assert_eq!(solutions[0]["hash"], wire::display_hex(&hash));
    assert_eq!(solutions[0]["request_id"], 14);
    assert_eq!(solutions[0]["height"], 300);

    // The model refusing an allocation ends the connection: there is no error to send.
    raw.send(&Message::AllocateMiningJobToken {
        user_identifier: b"nobody".to_vec(),
        request_id: 300,
    })
    .await;
    assert!(raw.recv().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_declarator_never_accepts_a_job_the_model_did_not() {
    // The model's handler fails on declarations of 99 transactions; with no model behind it
    // the job is refused with service-unavailable, never accepted.
    let (state, id, port, _status) = support::start_role(
        support::script(JDS_POLICY),
        json!({"role": "job_declarator", "authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    assert!(matches!(
        raw.recv().await,
        Some(Message::SetupConnectionSuccess { .. })
    ));
    let token = allocate(&mut raw, 1, "netget").await.unwrap();
    let txs: Vec<Tx> = (0..99).map(|i| tx(i as u8)).collect();
    raw.send(&declare(2, &token, &txs, true, true)).await;
    let Some(Message::ProvideMissingTransactions {
        unknown_tx_position_list,
        ..
    }) = raw.recv().await
    else {
        panic!("not asked for the transactions")
    };
    assert_eq!(unknown_tx_position_list.len(), 99);
    raw.send(&Message::ProvideMissingTransactionsSuccess {
        request_id: 2,
        transaction_list: txs.iter().map(|t| t.serialize(true)).collect(),
    })
    .await;
    let answer = raw.recv().await;
    assert!(
        matches!(&answer, Some(Message::DeclareMiningJobError { request_id: 2, error_code, .. })
            if error_code == b"service-unavailable" || error_code == b"service-overloaded"),
        "{answer:?}"
    );
    assert_eq!(
        support::events(&state, id, "stratum_v2_jd_declare_job")
            .await
            .len(),
        1
    );

    // And with no model at all, nobody connects.
    let (_s, _i, port, _status) = support::start_role(
        None,
        json!({"role": "job_declarator", "authority_secret_key": support::SECRET}),
    )
    .await;
    let mut raw = Raw::connect(port).await;
    raw.send(&setup(1, wire::DECLARE_TX_DATA)).await;
    assert!(matches!(raw.recv().await,
        Some(Message::SetupConnectionError { error_code, .. }) if error_code == b"service-unavailable"));
}
