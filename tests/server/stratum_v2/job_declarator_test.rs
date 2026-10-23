//! NetGet as a **Job Declaration Server** for **SRI's `jd_client_sv2`** (sv2-apps v0.8.0,
//! FULLTEMPLATE mode), which frames, encrypts, builds coinbases and computes wtxids with SRI's
//! own crates and rust-bitcoin — none of which NetGet links.
//!
//! The chain around it: Bitcoin Core 31.0 in regtest feeds SRI's `pool_sv2` over IPC, and the
//! jd_client opens its upstream channel on that pool. Its templates come from a second NetGet
//! server in the template-provider role, whose model writes a template spending an early
//! `OP_TRUE` coinbase. So every party the job declarator talks to is SRI's, and the one NetGet
//! component besides the JDS under test is the template source.
//!
//! The jd_client sets up, asks for a token, requests the template's transactions from the
//! template provider (RequestTransactionData), builds its coinbase and declares the job with the
//! transaction's wtxid. NetGet's JDS has never seen the transaction, so it asks for it
//! (ProvideMissingTransactions); the jd_client supplies it; NetGet checks it is the transaction
//! that wtxid names and that the coinbase's witness commitment covers it, and only then does the
//! model accept the job. The jd_client must receive DeclareMiningJob.Success and send the custom
//! job to the pool. (SRI's pool v0.8.0 validates custom-job tokens with its own embedded JDS
//! only, so it answers SetCustomMiningJob with `jd-not-supported`; the job declaration itself is
//! complete by then, and PushSolution can never follow, because jd_client pushes solutions only
//! for jobs the pool acknowledged.) No LLM calls.
use super::{peers, support};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sri_jd_client_declares_its_job_to_netget() {
    let node = peers::Regtest::start(true, 101).await;
    let (tip, height, ntime) = node.tip().await;
    let (cb_txid, cb_value) = node.coinbase(1).await;
    let next = height + 1;
    let txs = json!([{"inputs": [{"txid": cb_txid, "vout": 0, "value_sats": cb_value}],
        "outputs": [{"value_sats": cb_value - 5000, "pay_to": "op_true"}]}]);

    // The template source: a NetGet template provider.
    let (_tp_state, _tp_id, tp_port, tp_status) = support::start_role(
        support::script(&format!(
            r#"if t=='stratum_v2_tp_setup_connection':
  a=[{{'type':'stratum_v2_accept'}}]
elif t=='stratum_v2_tp_coinbase_output_constraints':
  a=[{{'type':'stratum_v2_new_template','prev_hash':'{tip}','height':{next},'nbits':'207fffff','ntime':{ntime},'transactions':json.loads('{txs}')}}]"#
        )),
        json!({"role": "template_provider", "network": "regtest",
               "authority_secret_key": peers::SECRET}),
    )
    .await;
    // The server under test.
    let (state, id, jds_port, status) = support::start_role(
        support::script(
            r#"if t=='stratum_v2_jd_setup_connection':
  a=[{'type':'stratum_v2_accept'}]
elif t=='stratum_v2_jd_allocate_token':
  a=[{'type':'stratum_v2_accept'},{'type':'stratum_v2_allocate_token','pay_to':'op_true'}]
elif t=='stratum_v2_jd_declare_job':
  a=[{'type':'stratum_v2_accept'}] if e['transactions']==1 and e['pays_required_outputs'] else [{'type':'stratum_v2_reject','error_code':'invalid-job'}]"#,
        ),
        json!({"role": "job_declarator", "network": "regtest",
               "authority_secret_key": peers::SECRET}),
    )
    .await;

    let dir = node.tmp.path().to_path_buf();
    let (_pool, pool_port, pool_log) = peers::pool(
        &dir,
        &format!(
            "[template_provider_type.BitcoinCoreIpc]\nversion = 31\nnetwork = \"regtest\"\ndata_dir = \"{}\"\nfee_threshold = 0\nmin_interval = 5\n",
            node.dir.display()
        ),
    )
    .await;
    peers::wait_listening(pool_port, &pool_log, "pool_sv2", 90).await;

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
pool_port = {pool_port}
jds_address = "127.0.0.1"
jds_port = {jds_port}
user_identity = "netget.jdc"

[template_provider_type.Sv2Tp]
address = "127.0.0.1:{tp_port}"
public_key = "{public}"
"#,
            public = peers::PUBLIC,
            secret = peers::SECRET,
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
            "{what}\n--- jd_client ---\n{}\n--- pool_sv2 ---\n{}\n--- mining_device ---\n{}\n--- netget JDS ---\n{}\n--- netget TP ---\n{}",
            peers::read(&jdc_log),
            peers::read(&pool_log),
            peers::read(&device_log),
            status.text(),
            tp_status.text()
        )
    };
    // jd_client opens its upstream channel, and so declares, only once a miner connects to it.
    peers::wait_listening(jdc_port, &jdc_log, "jd_client_sv2", 60).await;
    let _device = peers::mining_device(jdc_port, &dir, &device_log);
    assert!(
        peers::wait_log(&jdc_log, "Received: DeclareMiningJobSuccess", 120).await,
        "{}",
        dump("jd_client never had a job accepted by NetGet")
    );
    assert!(
        peers::wait_log(&jdc_log, "Successfully sent SetCustomMiningJob", 30).await,
        "{}",
        dump("jd_client did not turn the accepted declaration into a custom job")
    );
    let jdc_text = peers::read(&jdc_log);
    for needle in [
        "Received: AllocateMiningJobTokenSuccess",
        "Received: ProvideMissingTransactions",
        "Received: RequestTransactionDataSuccess",
    ] {
        assert!(jdc_text.contains(needle), "{}", dump(needle));
    }

    // What the model was asked: one connection, a token, and a declaration Rust had already
    // completed — its one transaction known, matching its wtxid and its commitment.
    assert_eq!(
        support::events(&state, id, "stratum_v2_jd_setup_connection")
            .await
            .len(),
        1
    );
    assert!(!support::events(&state, id, "stratum_v2_jd_allocate_token")
        .await
        .is_empty());
    let declared = support::events(&state, id, "stratum_v2_jd_declare_job").await;
    let job = declared
        .iter()
        .find(|d| d["transactions"] == 1)
        .unwrap_or_else(|| panic!("{}", dump(&format!("{declared:?}"))));
    assert_eq!(job["height"], next, "{job}");
    assert_eq!(job["pays_required_outputs"], true, "{job}");
    assert!(
        tp_status
            .text()
            .contains("answered with RequestTransactionData.Success"),
        "{}",
        dump("the template provider never served transaction data")
    );

    drop(jdc);
    let summary = status
        .wait("received: ", 30)
        .await
        .unwrap_or_else(|| panic!("{}", dump("no connection summary")));
    println!("jd_client -> NetGet job declarator: {summary}");
    for kind in [
        "SetupConnection=1",
        "AllocateMiningJobToken=",
        "DeclareMiningJob=",
        "ProvideMissingTransactions.Success=",
    ] {
        assert!(summary.contains(kind), "{summary}");
    }
    let tp_summary = tp_status.wait("received: ", 30).await;
    println!("jd_client -> NetGet template provider: {tp_summary:?}");
}
