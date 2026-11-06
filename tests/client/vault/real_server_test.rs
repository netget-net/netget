use super::common::*;
use crate::helpers::real_server::{find_binary, InstallHint, RealServer};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use tokio::{io::AsyncWriteExt, sync::mpsc};
const ROOT: &str = "netget-owned-dev-root-59";
const LOGIN_PASSWORD: &str = "fixture-password";
const WRAPPER: &str = r#"import os,pathlib,subprocess,sys,threading,time,urllib.request,json
binary,directory,port=sys.argv[1:]
home=pathlib.Path(directory)/'home';home.mkdir(exist_ok=True)
root='netget-owned-dev-root-59'
env={'PATH':os.environ.get('PATH',''),'HOME':str(home),'VAULT_ADDR':'http://127.0.0.1:'+port,'VAULT_DEV_LISTEN_ADDRESS':'127.0.0.1:'+port,'VAULT_DEV_ROOT_TOKEN_ID':root}
# Same process group as the RealServer guard; no token helper or user's HOME.
p=subprocess.Popen([binary,'server','-dev','-dev-no-store-token','-log-level=warn'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
started=threading.Event()
def logs():
 for line in p.stdout:
  if 'Vault server started!' in line:started.set()
  if any(word in line.lower() for word in ['unseal key','root token','license']):continue
  print(line.replace(root,'<redacted>'),end='',flush=True)
reader=threading.Thread(target=logs);reader.start()
deadline=time.monotonic()+25
while True:
 if p.poll() is not None:reader.join();sys.exit(p.returncode or 1)
 try:
  with urllib.request.urlopen(env['VAULT_ADDR']+'/v1/sys/seal-status',timeout=.2) as r:v=json.load(r)
  if started.is_set() and v['initialized'] and not v['sealed']:break
 except (OSError,ValueError):pass
 if time.monotonic()>deadline:raise TimeoutError('owned Vault readiness deadline')
 time.sleep(.02)
print('VAULT_PEER_READY',flush=True)
p.wait();reader.join();sys.exit(p.returncode)
"#;
fn binary() -> String {
    find_binary("vault").expect("required independent Vault daemon and CLI; brew install hashicorp/tap/vault or install the official HashiCorp release").to_string_lossy().into_owned()
}
async fn daemon() -> crate::helpers::E2EResult<RealServer> {
    RealServer::builder(
        "python3",
        InstallHint {
            brew: "python3 and hashicorp/tap/vault",
            apt: "python3 and the official HashiCorp Vault release",
        },
    )
    .config_file("vault_peer.py", WRAPPER)
    .args(["-u", "{dir}/vault_peer.py", &binary(), "{dir}", "{port}"])
    .ready_when_log_matches("VAULT_PEER_READY")
    .start()
    .await
}
async fn cli(home: &Path, addr: &str, args: &[&str], stdin: Option<String>) -> Value {
    let mut command = tokio::process::Command::new(binary());
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("VAULT_ADDR", format!("http://{addr}"))
        .env("VAULT_TOKEN", ROOT)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("required Vault CLI");
    let mut input = child.stdin.take().unwrap();
    if let Some(body) = stdin {
        input.write_all(body.as_bytes()).await.unwrap();
    }
    drop(input);
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("owned Vault CLI deadline")
        .unwrap();
    assert!(
        output.status.success(),
        "owned Vault CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .replace(ROOT, "<redacted>")
            .replace(LOGIN_PASSWORD, "<redacted>")
    );
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}
async fn provision(peer: &RealServer) {
    let home = peer.dir().join("home");
    let addr = peer.addr();
    cli(
        &home,
        &addr,
        &["auth", "enable", "-path=userpass", "userpass"],
        None,
    )
    .await;
    cli(&home,&addr,&["policy","write","netget-fixture","-"],Some("path \"secret/data/*\" { capabilities = [\"create\", \"update\", \"read\"] }\npath \"secret/metadata/*\" { capabilities = [\"read\", \"list\"] }\npath \"secret/metadata\" { capabilities = [\"list\"] }".into())).await;
    cli(
        &home,
        &addr,
        &["write", "auth/userpass/users/fixture-reader", "-"],
        Some(json!({"password":LOGIN_PASSWORD,"token_policies":["netget-fixture"]}).to_string()),
    )
    .await;
}
async fn login(state: &netget::state::AppState, id: netget::state::ClientId) -> Value {
    let after = latest(state, id).await;
    send(state,id,json!({"type":"vault_userpass_login","username":"fixture-reader","password":LOGIN_PASSWORD})).await;
    event(state, id, "vault_authentication", after).await.1
}
#[tokio::test]
async fn independent_userpass_token_drives_version_cas_lists_metadata_and_cli_readback(
) -> crate::helpers::E2EResult<()> {
    let peer = daemon().await?;
    provision(&peer).await;
    let state = state();
    let id = connected_client(&state, peer.addr()).await;
    let auth = login(&state, id).await;
    assert_eq!(auth["authentication_verified"], true);
    assert_eq!(auth["auth"]["token_type"], "service");
    assert!(auth["auth"]["lease_duration"].as_u64().unwrap() > 0);
    assert!(auth["auth"]["policies"]
        .as_array()
        .unwrap()
        .contains(&json!("netget-fixture")));
    for (cas, answer, version) in [(0, 41, 1), (1, 42, 2)] {
        let write=request(&state,id,json!({"operation":"write","path":"fixture/app","data":{"answer":answer,"application_secret":"domain-value"},"cas":cas})).await;
        assert_eq!(write["data"]["data"]["version"], version);
    }
    let old = request(
        &state,
        id,
        json!({"operation":"read","path":"fixture/app","version":1}),
    )
    .await;
    assert_eq!(old["data"]["data"]["data"]["answer"], 41);
    assert_eq!(old["data"]["data"]["metadata"]["version"], 1);
    let current = request(
        &state,
        id,
        json!({"operation":"read","path":"fixture/app","version":0}),
    )
    .await;
    assert_eq!(current["data"]["data"]["data"]["answer"], 42);
    assert_eq!(
        current["data"]["data"]["data"]["application_secret"],
        "domain-value"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"list","path":""})).await["data"]["data"]["keys"],
        json!(["fixture/"])
    );
    assert_eq!(
        request(&state, id, json!({"operation":"list","path":"fixture/"})).await["data"]["data"]
            ["keys"],
        json!(["app"])
    );
    let metadata = request(
        &state,
        id,
        json!({"operation":"metadata","path":"fixture/app"}),
    )
    .await;
    assert_eq!(metadata["data"]["data"]["current_version"], 2);
    assert_eq!(
        metadata["data"]["data"]["versions"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    let home = peer.dir().join("home");
    let addr = peer.addr();
    let cli_read = cli(
        &home,
        &addr,
        &["kv", "get", "-format=json", "secret/fixture/app"],
        None,
    )
    .await;
    assert_eq!(cli_read["data"]["data"], current["data"]["data"]["data"]);
    let cli_metadata = cli(
        &home,
        &addr,
        &[
            "kv",
            "metadata",
            "get",
            "-format=json",
            "secret/fixture/app",
        ],
        None,
    )
    .await;
    assert_eq!(
        cli_metadata["data"]["current_version"],
        metadata["data"]["data"]["current_version"]
    );
    for (action, status) in [
        (
            json!({"operation":"write","path":"fixture/app","data":{},"cas":0}),
            400,
        ),
        (json!({"operation":"read","path":"missing"}), 404),
    ] {
        let after = latest(&state, id).await;
        send(&state, id, action).await;
        assert_eq!(
            event(&state, id, "vault_request_error", after).await.1["status"],
            status
        );
    }
    let logs = serde_json::to_string(
        &state
            .list_access_logs_for(
                Some(netget::state::AccessLogOwner::Client(id.as_u32())),
                None,
            )
            .await,
    )
    .unwrap();
    assert!(!logs.contains(LOGIN_PASSWORD));
    assert!(!logs.contains(ROOT));
    assert!(!logs.contains("client_token"));
    assert!(!home.join(".vault-token").exists());
    assert!(!peer.log().contains(ROOT));
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn advertised_static_script_and_selected_action_examples_run_on_independent_daemon(
) -> crate::helpers::E2EResult<()> {
    use netget::llm::actions::protocol_trait::Protocol;
    let peer = daemon().await?;
    provision(&peer).await;
    cli(
        &peer.dir().join("home"),
        &peer.addr(),
        &["kv", "put", "secret/fixture/app", "-"],
        Some(json!({"answer":42}).to_string()),
    )
    .await;
    let state = state();
    let protocol = netget::client::vault::VaultClientProtocol::new();
    let examples = protocol.get_startup_examples();
    examples.validate("Vault").unwrap();
    for example in [examples.static_mode, examples.script_mode] {
        let id = client(
            &state,
            peer.addr(),
            json!({}),
            serde_json::from_value(example["event_handlers"].clone()).unwrap(),
        )
        .await;
        assert_eq!(
            event(&state, id, "vault_response", 0).await.1["operation"],
            "health"
        );
        let actions = protocol.get_async_actions(&state);
        let login = actions
            .iter()
            .find(|a| a.name == "vault_userpass_login")
            .unwrap()
            .example
            .clone();
        let after = latest(&state, id).await;
        send(&state, id, login).await;
        assert_eq!(
            event(&state, id, "vault_authentication", after).await.1["authentication_verified"],
            true
        );
        assert_eq!(
            request(
                &state,
                id,
                actions
                    .iter()
                    .find(|a| a.name == "vault_request")
                    .unwrap()
                    .example
                    .clone()
            )
            .await["data"]["data"]["data"]["answer"],
            42
        );
        let after = latest(&state, id).await;
        send(
            &state,
            id,
            actions
                .iter()
                .find(|a| a.name == "vault_clear_token")
                .unwrap()
                .example
                .clone(),
        )
        .await;
        assert_eq!(
            event(&state, id, "vault_authentication", after).await.1["token_present"],
            false
        );
        state.remove_client(id).await;
    }
    Ok(())
}
#[tokio::test]
async fn model_selects_native_login_and_kv_exchanges_with_shared_memory_and_redacted_auth(
) -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let peer = daemon().await?;
    provision(&peer).await;
    let config=MockLlmBuilder::new().on_event("vault_connected").respond_with_actions(json!([{"type":"set_memory","value":"Vault model authenticated workflow"},{"type":"vault_userpass_login","username":"fixture-reader","password":LOGIN_PASSWORD}])).expect_calls(1).and()
        .on_event("vault_authentication").and_prompt_containing("Vault model authenticated workflow").respond_with_actions(json!([{"type":"vault_request","operation":"write","path":"fixture/app","data":{"answer":42,"chosen":"by the mocked model"},"cas":0}])).expect_calls(1).and()
        .on_event("vault_response").and_event_data_contains("operation","write").respond_with_actions(json!([{"type":"vault_request","operation":"read","path":"fixture/app","version":1}])).expect_calls(1).and()
        .on_event("vault_response").and_event_data_contains("operation","read").respond_with_actions(json!([])).expect_calls(1).and().build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "vault".into(),
        remote_addr: Some(peer.addr()),
        instruction: Some("Authenticate, write and read fixture/app once".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    assert_eq!(mock.call_count().await, 4);
    assert_eq!(
        state.get_memory_for_client(id).await.as_deref(),
        Some("Vault model authenticated workflow")
    );
    let logs = state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Client(id.as_u32())),
            None,
        )
        .await;
    assert!(logs.iter().any(|e| e.event_type == "vault_response"
        && e.request["operation"] == "read"
        && e.request["data"]["data"]["data"]["answer"] == 42));
    // Condition 4 from Vault's side: HashiCorp's own CLI reads back, with the root token, the
    // secret the model wrote through the token the model's login obtained.
    let cli_read = cli(
        &peer.dir().join("home"),
        &peer.addr(),
        &["kv", "get", "-format=json", "secret/fixture/app"],
        None,
    )
    .await;
    assert_eq!(
        cli_read["data"]["data"],
        json!({"answer":42,"chosen":"by the mocked model"})
    );
    assert_eq!(cli_read["data"]["metadata"]["version"], 1);
    assert!(!serde_json::to_string(&logs)
        .unwrap()
        .contains(LOGIN_PASSWORD));
    while let Ok(status) = rx.try_recv() {
        assert!(!status.contains(LOGIN_PASSWORD));
        assert!(!status.contains(ROOT));
    }
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn netget_pair_preserves_programmable_kv_and_existing_login_refusal() {
    let state = state();
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let guard="import json,sys\ne=json.load(sys.stdin)['event']\nif not e['token_matches_configured']:\n print(json.dumps({'actions':[{'type':'send_vault_error','status':403,'errors':['permission denied']}]}));sys.exit(0)\n";
    let handlers = vec![
        json!({"event_pattern":"vault_read","handler":{"type":"script","language":"python","code":format!("{guard}print(json.dumps({{'actions':[{{'type':'send_vault_secret','data':{{'answer':42}},'version':7,'created_time':'{TIME}'}}]}}))")}}),
        static_handler(
            "vault_write",
            json!([{"type":"send_vault_write_ok","version":7,"created_time":TIME}]),
        ),
        static_handler(
            "vault_list",
            json!([{"type":"send_vault_list","keys":["app","folder/"]}]),
        ),
    ];
    let (tx, _) = mpsc::unbounded_channel();
    let sid = netget::cli::management::ServerForm {
        protocol: "vault".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        startup_params: Some(json!({"token":ROOT})),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(a) = state.get_server(sid).await.and_then(|s| s.local_addr) {
                break a.to_string();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let id = client(
        &state,
        address,
        json!({"token":ROOT}),
        vec![static_handler("*", json!([]))],
    )
    .await;
    event(&state, id, "vault_connected", 0).await;
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"read","path":"fixture/app","version":7})
        )
        .await["data"]["data"]["data"]["answer"],
        42
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"write","path":"fixture/app","data":{"answer":42},"cas":6})
        )
        .await["data"]["data"]["version"],
        7
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"metadata","path":"fixture/app"})
        )
        .await["data"]["data"]["current_version"],
        7
    );
    assert_eq!(
        request(&state, id, json!({"operation":"list","path":"fixture"})).await["data"]["data"]
            ["keys"],
        json!(["app", "folder/"])
    );
    let after = latest(&state, id).await;
    send(&state,id,json!({"type":"vault_userpass_login","username":"fixture-reader","password":LOGIN_PASSWORD})).await;
    let (_, error) = event(&state, id, "vault_request_error", after).await;
    assert_eq!(error["status"], 404);
    assert_eq!(error["token_present"], false);
    let after = latest(&state, id).await;
    send(&state, id, json!({"operation":"read","path":"fixture/app"})).await;
    assert_eq!(
        event(&state, id, "vault_request_error", after).await.1["status"],
        403
    );
    state.remove_client(id).await;
    state.remove_server(sid).await;
}
