//! NetGet as a **Job Declarator Client** against **SRI's Job Declaration Server** — the JDS
//! embedded in `pool_sv2` (sv2-apps v0.8.0, `[jds]`), which validates every declared job with
//! **Bitcoin Core 31.0**'s own `checkBlock` over IPC, in regtest.
//!
//! The model (a python chain) declares the job it wants: the next height, a coinbase message
//! and one transaction spending an early `OP_TRUE` coinbase. Rust builds the coinbase the way
//! the JDS reads one, with the output the token required and the witness commitment. The JDS
//! does not have the transaction, so it asks (ProvideMissingTransactions) and NetGet answers;
//! Bitcoin Core then checks the assembled block — BIP 34 height, the coinbase value against
//! subsidy and fee, the commitment, the transaction against its UTXO set — and only then does
//! the JDS accept. The model then mines the accepted job on the regtest tip and pushes the
//! solution, which the JDS logs (SRI v0.8.0 does nothing further with a PushSolution yet).
//! A second declaration spending an output that does not exist must be refused by the JDS, and
//! the refusal reach the model. No LLM calls.
use super::peers;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_declares_a_job_sri_jds_and_bitcoin_core_accept() {
    let node = peers::Regtest::start(true, 101).await;
    let (tip, height, ntime) = node.tip().await;
    let (cb_txid, cb_value) = node.coinbase(1).await;
    let next = height + 1;
    let txs = json!([{"inputs": [{"txid": cb_txid, "vout": 0, "value_sats": cb_value}],
        "outputs": [{"value_sats": cb_value - 2000, "pay_to": "op_true"}]}]);

    let dir = node.tmp.path().to_path_buf();
    let jds_port = peers::free_port();
    let (_pool, pool_port, pool_log) = peers::pool(
        &dir,
        &format!(
            "[template_provider_type.BitcoinCoreIpc]\nversion = 31\nnetwork = \"regtest\"\ndata_dir = \"{}\"\nfee_threshold = 0\nmin_interval = 5\n\n[jds]\nlisten_address = \"127.0.0.1:{jds_port}\"\n",
            node.dir.display()
        ),
    )
    .await;
    peers::wait_listening(pool_port, &pool_log, "pool_sv2", 90).await;
    peers::wait_listening(jds_port, &pool_log, "pool_sv2's JDS", 90).await;

    let chain = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='stratum_v2_jd_token' and e['request_id']==1:
  a=[{{'type':'stratum_v2_declare_job','height':{next},'message':'netget jdc','transactions':json.loads('{txs}')}}]
elif t=='stratum_v2_jd_declare_result' and e['accepted']:
  a=[{{'type':'stratum_v2_push_solution','prev_hash':'{tip}','nbits':'207fffff','ntime':{ntime}}}]
print(json.dumps({{'actions':a}}))"#
    );
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let status = peers::Status::default();
    let sink = status.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.0.lock().unwrap().push(line);
        }
    });
    let id = ClientForm {
        protocol: "stratum_v2".into(),
        remote_addr: Some(format!("127.0.0.1:{jds_port}")),
        instruction: Some("Declare one job and push its solution".into()),
        startup_params: Some(json!({"role": "job_declarator", "network": "regtest",
            "authority_public_key": peers::PUBLIC, "user_identity": "netget.jdc"})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}}),
        ]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect to SRI's JDS");
    let dump = |what: &str| {
        format!(
            "{what}\n--- pool_sv2 + JDS ---\n{}\n--- netget ---\n{}",
            peers::read(&pool_log),
            status.text()
        )
    };

    let token = wait_event(&state, id, |e| e["event_type"] == "stratum_v2_jd_token")
        .await
        .unwrap_or_else(|| panic!("{}", dump("no token")));
    assert_eq!(
        token["coinbase_outputs"][0]["script_type"], "op_true",
        "the JDS's required output is its raw(51) reward script: {token}"
    );
    let result = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_jd_declare_result"
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("no answer to the declaration")));
    assert_eq!(result["accepted"], true, "{}", dump(&result.to_string()));
    assert_eq!(result["height"], next);
    assert_eq!(result["transaction_count"], 1);
    let pushed = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_jd_solution_pushed"
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("the accepted job was never mined")));
    assert_eq!(pushed["pushed"], true, "{pushed}");
    assert!(
        peers::wait_log(&pool_log, "Received: PushSolution", 30).await,
        "{}",
        dump("the JDS never received the solution")
    );
    let pool_text = peers::read(&pool_log);
    for needle in [
        "Received: AllocateMiningJobToken(user_identifier: netget.jdc",
        "Received: DeclareMiningJob(",
        "Received: ProvideMissingTransactionsSuccess(",
        "Validating DeclareMiningJob",
    ] {
        assert!(pool_text.contains(needle), "{}", dump(needle));
    }

    // A second job spending an output that does not exist: Bitcoin Core's checkBlock refuses
    // it, and the JDS's refusal reaches the model.
    let ask = |action: Value| state.send_to_client(id, action, Duration::from_secs(30));
    let outcome = ask(json!({"type": "stratum_v2_request_token"}))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
    let second = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_jd_token" && e["request"]["request_id"] != 1
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("no second token")));
    assert!(second["tokens_held"].as_u64().unwrap() >= 1, "{second}");
    let bogus = json!([{"inputs": [{"txid": "ab".repeat(32), "vout": 0, "value_sats": 100000}],
        "outputs": [{"value_sats": 90000, "pay_to": "op_true"}]}]);
    let outcome = ask(json!({"type": "stratum_v2_declare_job", "height": next,
        "transactions": bogus}))
    .await
    .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
    let refused = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_jd_declare_result" && e["request"]["accepted"] == false
    })
    .await
    .unwrap_or_else(|| panic!("{}", dump("the JDS never answered the bad declaration")));
    assert!(
        !refused["error_code"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "{refused}"
    );
    println!("SRI JDS refused the declaration spending a missing output: {refused}");

    // Refused before the wire: a coinbase claiming more than the subsidy and fees.
    let outcome = ask(json!({"type": "stratum_v2_declare_job", "height": next,
        "coinbase_value_sats": 5_000_000_001u64}))
    .await
    .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("subsidy")),
        "{outcome:?}"
    );

    let outcome = ask(json!({"type": "disconnect"})).await.unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
    let summary = status
        .wait("job declarator client received: ", 30)
        .await
        .unwrap_or_else(|| panic!("{}", dump("no session summary")));
    println!("SRI JDS -> NetGet job declarator client: {summary} (plus SetupConnection.Success)");
    for kind in [
        "AllocateMiningJobToken.Success=2",
        "ProvideMissingTransactions=",
        "DeclareMiningJob.Success=1",
        "DeclareMiningJob.Error=1",
    ] {
        assert!(summary.contains(kind), "{summary}");
    }
}
