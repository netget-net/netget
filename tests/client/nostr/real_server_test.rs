use super::common::*;
use crate::helpers::real_server::{find_binary, InstallHint, RealServer};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use tokio::{io::AsyncWriteExt, sync::mpsc};
const WRAPPER: &str = r#"import os,sys,subprocess,threading,time
binary,root,port,auth=sys.argv[1:]
home=os.path.join(root,'home');os.makedirs(home)
env={'HOME':home,'PATH':os.environ.get('PATH','')}
args=[binary,'serve','--hostname','127.0.0.1','--port',port]
if auth=='yes':args+=['--auth','--eager-auth']
p=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
ready=threading.Event()
def read():
 for line in p.stdout:
  print(line,end='',flush=True)
  if 'relay running at ws://' in line:ready.set()
t=threading.Thread(target=read,daemon=True);t.start()
while not ready.wait(0.05):
 if p.poll() is not None:sys.exit(p.returncode)
print('NAK_PEER_READY',flush=True)
p.wait();t.join();sys.exit(p.returncode)
"#;
fn binary() -> String {
    find_binary("nak").expect("required independent nak relay and CLI; brew install nak or install official nak0.20.7 release").to_string_lossy().into_owned()
}
async fn daemon(auth: bool) -> crate::helpers::E2EResult<RealServer> {
    RealServer::builder(
        "python3",
        InstallHint {
            brew: "python3 and nak",
            apt: "python3 and official nak0.20.7 release",
        },
    )
    .config_file("nak_peer.py", WRAPPER)
    .args([
        "-u",
        "{dir}/nak_peer.py",
        &binary(),
        "{dir}",
        "{port}",
        if auth { "yes" } else { "no" },
    ])
    .ready_when_log_matches("NAK_PEER_READY")
    .start()
    .await
}
async fn cli(home: &Path, args: &[&str], input: Option<String>) -> (String, String) {
    let mut command = tokio::process::Command::new(binary());
    command
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        // No input means no stdin at all: nak 0.21 reads events and filters from a piped
        // stdin instead of its arguments, so an empty pipe would make it do nothing.
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("required nak CLI");
    if let Some(input) = input {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.as_bytes()).await.unwrap();
    }
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("owned nak CLI deadline")
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr)
        .replace(SECRET, "<redacted>")
        .replace(OTHER_SECRET, "<redacted>");
    assert!(output.status.success(), "owned nak CLI failed: {stderr}");
    (String::from_utf8(output.stdout).unwrap(), stderr)
}
fn events(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|s| s.starts_with('{'))
        .map(|s| serde_json::from_str(s).expect("nak JSON event"))
        .collect()
}
const SDK_FETCH: &str = r#"import asyncio,json,sys
from datetime import timedelta
from nostr_sdk import Client,RelayUrl,Filter,ReqTarget,EventId
async def main():
 client=Client();await client.add_relay(RelayUrl.parse(sys.argv[1]));await client.try_connect(timedelta(seconds=5))
 events=await client.fetch_events(ReqTarget.auto([Filter().id(EventId.parse(sys.argv[2]))]),timedelta(seconds=5))
 out=[]
 for event in events:
  assert event.verify_id() and event.verify_signature()
  out.append(json.loads(event.as_json()))
 await client.shutdown();print(json.dumps(out))
asyncio.run(main())
"#;
#[tokio::test]
async fn independent_nak_relay_cli_and_sdk_agree_on_signed_publish_live_subscription_and_information(
) -> crate::helpers::E2EResult<()> {
    let peer = daemon(false).await?;
    let url = format!("ws://{}", peer.addr());
    let home = peer.dir().join("home");
    let state = state();
    let id = client(
        &state,
        url.clone(),
        json!({"secret_key":SECRET}),
        vec![static_handler("*", json!([]))],
    )
    .await;
    event(&state, id, "nostr_connected", 0).await;
    let after = latest(&state, id).await;
    send(&state,id,json!({"type":"nostr_subscribe","subscription_id":"live","filters":[{"kinds":[1],"#t":["film"],"limit":0}]})).await;
    assert_eq!(
        event(&state, id, "nostr_subscription", after).await.1["status"],
        "eose"
    );
    let after = latest(&state, id).await;
    let (stdout, stderr) = cli(
        &home,
        &[
            "event",
            "--sec",
            OTHER_SECRET,
            "-c",
            "independent live film",
            "-t",
            "t=film",
            &url,
        ],
        None,
    )
    .await;
    assert!(stderr.contains("success"));
    let published = events(&stdout);
    assert_eq!(published.len(), 1);
    let (_, received) = event(&state, id, "nostr_received_event", after).await;
    assert_eq!(received["event"], published[0]);
    assert_eq!(received["stored_phase"], false);
    let after = latest(&state, id).await;
    send(&state,id,json!({"type":"nostr_publish","kind":1,"content":"NetGet signed film ☃","tags":[["t","film"]]})).await;
    let (_, result) = event(&state, id, "nostr_publish_result", after).await;
    assert_eq!(result["accepted"], true);
    let event_id = result["id"].as_str().unwrap();
    let (stdout, _) = cli(
        &home,
        &[
            "req",
            "--sec",
            OTHER_SECRET,
            "-i",
            event_id,
            "-l",
            "1",
            &url,
        ],
        None,
    )
    .await;
    let fetched = events(&stdout);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0]["id"], event_id);
    assert_eq!(fetched[0]["content"], "NetGet signed film ☃");
    cli(&home, &["verify"], Some(fetched[0].to_string())).await;
    let python = std::env::var("NETGET_NOSTR_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(&python)
            .args(["-c", SDK_FETCH, &url, event_id])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("owned independent SDK deadline")?;
    assert!(
        output.status.success(),
        "required nostr_sdk peer {python} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sdk: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(sdk[0], fetched[0]);
    let after = latest(&state, id).await;
    send(&state, id, json!({"type":"nostr_relay_info"})).await;
    let (_, info) = event(&state, id, "nostr_relay_information", after).await;
    assert_eq!(info["information"]["name"], "nak serve");
    assert!(info["information"]["supported_nips"]
        .as_array()
        .unwrap()
        .contains(&json!(1)));
    send(
        &state,
        id,
        json!({"type":"nostr_close","subscription_id":"live"}),
    )
    .await;
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn independent_auth_required_relay_is_reported_without_auth_or_count_expansion(
) -> crate::helpers::E2EResult<()> {
    let peer = daemon(true).await?;
    let state = state();
    let id = connected_client(&state, format!("ws://{}", peer.addr())).await;
    let (_, notice) = event(&state, id, "nostr_notice", 0).await;
    assert_eq!(notice["message_type"], "AUTH");
    assert_eq!(notice["supported"], false);
    let after = latest(&state, id).await;
    send(
        &state,
        id,
        json!({"type":"nostr_publish","kind":1,"content":"requires auth"}),
    )
    .await;
    let (_, receipt) = event(&state, id, "nostr_publish_result", after).await;
    assert_eq!(receipt["accepted"], false);
    assert_eq!(receipt["reason_prefix"], "auth-required");
    let after = latest(&state, id).await;
    send(
        &state,
        id,
        json!({"type":"nostr_subscribe","subscription_id":"requires-auth","filters":[{}]}),
    )
    .await;
    let (_, receipt) = event(&state, id, "nostr_subscription", after).await;
    assert_eq!(receipt["status"], "closed");
    assert_eq!(receipt["reason_prefix"], "auth-required");
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn advertised_static_script_and_action_examples_run_against_independent_relay(
) -> crate::helpers::E2EResult<()> {
    use netget::{client::nostr::NostrClientProtocol, llm::actions::protocol_trait::Protocol};
    let peer = daemon(false).await?;
    let state = state();
    let protocol = NostrClientProtocol::new();
    let examples = protocol.get_startup_examples();
    for example in [&examples.static_mode, &examples.script_mode] {
        let handlers = example["event_handlers"].as_array().unwrap().clone();
        let id = client(&state, format!("ws://{}", peer.addr()), json!({}), handlers).await;
        assert_eq!(
            event(&state, id, "nostr_subscription", 0).await.1["status"],
            "eose"
        );
        for name in ["nostr_publish", "nostr_relay_info", "nostr_close"] {
            let action = protocol
                .get_async_actions(&state)
                .into_iter()
                .find(|a| a.name == name)
                .unwrap()
                .example;
            let after = latest(&state, id).await;
            send(&state, id, action).await;
            let expected = match name {
                "nostr_publish" => "nostr_publish_result",
                "nostr_relay_info" => "nostr_relay_information",
                _ => "nostr_subscription",
            };
            event(&state, id, expected, after).await;
        }
        state.remove_client(id).await;
    }
    Ok(())
}
#[tokio::test]
async fn mocked_model_selects_native_publish_and_common_memory_without_private_key_exposure(
) -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let peer = daemon(false).await?;
    let config=MockLlmBuilder::new().on_event("nostr_connected").respond_with_actions(json!([{"type":"set_memory","value":"Nostr shared memory"},{"type":"nostr_publish","kind":1,"content":"model film"}])).expect_calls(1).and()
        .on_event("nostr_publish_result").and_prompt_containing("Nostr shared memory").respond_with_actions(json!([{"type":"nostr_relay_info"}])).expect_calls(1).and()
        .on_event("nostr_relay_information").respond_with_actions(json!([])).expect_calls(1).and().build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "nostr".into(),
        remote_addr: Some(format!("ws://{}", peer.addr())),
        startup_params: Some(json!({"secret_key":SECRET})),
        instruction: Some("Publish one film, then read relay metadata".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    assert_eq!(mock.call_count().await, 3);
    assert_eq!(
        state.get_memory_for_client(id).await.as_deref(),
        Some("Nostr shared memory")
    );
    // Condition 4 from the relay's side: fiatjaf's `nak` fetches from `nak serve` the note the
    // model chose, signed by the key the client was started with, and verifies it.
    let (author, _) = cli(&peer.dir().join("home"), &["key", "public", SECRET], None).await;
    let (stdout, _) = cli(
        &peer.dir().join("home"),
        &[
            "req",
            "-k",
            "1",
            "-a",
            author.trim(),
            "-l",
            "5",
            &format!("ws://{}", peer.addr()),
        ],
        None,
    )
    .await;
    let stored = events(&stdout);
    assert_eq!(stored.len(), 1, "{stdout}");
    assert_eq!(stored[0]["content"], "model film");
    cli(
        &peer.dir().join("home"),
        &["verify"],
        Some(stored[0].to_string()),
    )
    .await;
    for call in mock.recorded_calls().await {
        assert!(!call.context.prompt.contains(SECRET));
    }
    let logs = state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Client(id.as_u32())),
            None,
        )
        .await;
    assert!(!serde_json::to_string(&logs)?.contains(SECRET));
    while let Ok(status) = rx.try_recv() {
        assert!(!status.contains(SECRET));
    }
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn netget_pair_preserves_model_as_relay_and_signed_event_filtering_without_an_archive() {
    let state = state();
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let sid=netget::cli::management::ServerForm{protocol:"nostr".into(),host:Some("127.0.0.1".into()),port:Some(0),startup_params:Some(json!({"relay_secret_key":OTHER_SECRET})),event_handlers:Some(vec![static_handler("nostr_event",json!([{"type":"accept_nostr_event"}])),static_handler("nostr_req",json!([{"type":"send_nostr_events","events":[{"kind":1,"content":"programmable film","tags":[["t","film"]],"created_at":1700000000},{"kind":7,"content":"filtered"}]}]))]),..Default::default()}.create(&state,tx).await.unwrap();
    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(addr) = state.get_server(sid).await.and_then(|s| s.local_addr) {
                break addr.to_string();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let id = connected_client(&state, address).await;
    let after = latest(&state, id).await;
    send(&state,id,json!({"type":"nostr_subscribe","subscription_id":"film","filters":[{"kinds":[1],"#t":["film"]}]})).await;
    let (_, received) = event(&state, id, "nostr_received_event", after).await;
    assert_eq!(received["event"]["content"], "programmable film");
    assert_eq!(
        received["event"]["pubkey"],
        netget::server::nostr::wire::RelayKey::from_hex(OTHER_SECRET)
            .unwrap()
            .pubkey_hex()
    );
    assert_eq!(received["stored_phase"], true);
    assert_eq!(
        event(&state, id, "nostr_subscription", after).await.1["status"],
        "eose"
    );
    let after = latest(&state, id).await;
    send(&state,id,json!({"type":"nostr_publish","kind":1,"content":"accepted live film","tags":[["t","film"]]})).await;
    assert_eq!(
        event(&state, id, "nostr_publish_result", after).await.1["accepted"],
        true
    );
    assert_eq!(
        event(&state, id, "nostr_received_event", after).await.1["stored_phase"],
        false
    );
    let after = latest(&state, id).await;
    send(&state, id, json!({"type":"nostr_relay_info"})).await;
    let (_, info) = event(&state, id, "nostr_relay_information", after).await;
    assert_eq!(info["information"]["supported_nips"], json!([1, 11]));
    assert_eq!(info["information"]["limitation"]["auth_required"], false);
    send(
        &state,
        id,
        json!({"type":"nostr_close","subscription_id":"film"}),
    )
    .await;
    state.remove_client(id).await;
    state.remove_server(sid).await;
}
#[tokio::test]
async fn native_wss_refuses_an_independent_untrusted_certificate() -> crate::helpers::E2EResult<()>
{
    let hint = InstallHint {
        brew: "openssl@3",
        apt: "openssl",
    };
    let peer = RealServer::builder("openssl", hint)
        .setup_command(
            "openssl",
            hint,
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "{dir}/key.pem",
                "-out",
                "{dir}/cert.pem",
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ],
        )
        .args([
            "s_server",
            "-accept",
            "127.0.0.1:{port}",
            "-key",
            "{dir}/key.pem",
            "-cert",
            "{dir}/cert.pem",
            "-www",
        ])
        .ready_when_log_matches("ACCEPT")
        .start()
        .await?;
    let state = state();
    let error = refused_start(
        &state,
        format!("wss://{}/", peer.addr()),
        json!({"secret_key":SECRET,"request_timeout_secs":2}),
    )
    .await;
    assert!(error.contains("TLS verification failed"), "{error}");
    assert!(!error.contains(SECRET));
    Ok(())
}
