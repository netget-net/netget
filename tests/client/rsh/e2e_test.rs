//! NetGet's rsh, rexec and rlogin clients against test-owned servers written from literal
//! bytes (what each client puts on the wire, the stderr connection, a refusal, the window-size
//! answer to an urgent request), and against NetGet's own servers as a regression (the handler
//! chain and its depth bound, injected actions). No LLM: python handlers play the model. The
//! independent servers are in `real_server_test.rs`.
use super::server_support::{self as server, non_loopback_address, REXEC_POLICY, RSH_POLICY};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

fn chain(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub async fn client(
    protocol: &str,
    remote: String,
    params: Value,
    handlers: Option<Vec<Value>>,
) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: protocol.into(),
        remote_addr: Some(remote),
        instruction: Some("Run what you are asked".into()),
        startup_params: Some(params),
        event_handlers: handlers,
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

pub async fn client_events(state: &AppState, id: ClientId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

/// Wait for the `nth` (from 0) event of a type.
pub async fn wait_event(state: &AppState, id: ClientId, event_type: &str, nth: usize) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(e) = client_events(state, id, event_type).await.get(nth) {
                return e.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {event_type} #{nth}"))
}

/// Read NUL-terminated fields off a raw connection.
async fn read_fields(s: &mut TcpStream, count: usize) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    let mut current = Vec::new();
    let mut byte = [0u8; 1];
    while fields.len() < count {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut byte))
            .await
            .expect("the client sends its handshake")
            .unwrap();
        assert_eq!(n, 1, "the client closed mid-handshake after {fields:?}");
        if byte[0] == 0 {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(byte[0]);
        }
    }
    fields
}

const RUN_ONCE: &str = r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'rsh_run','command':'uname -a','stdin':'from the model\n'}] if i['event_type_id']=='rsh_connected' else []
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn rsh_client_runs_the_models_command_with_a_stderr_connection() {
    let rshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = rshd.local_addr().unwrap();
    let (state, id) = client(
        "rsh",
        addr.to_string(),
        json!({"local_user": "alice", "remote_user": "bob"}),
        chain(RUN_ONCE),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "rsh_connected", 0).await;
    assert_eq!(connected["local_user"], "alice");
    assert_eq!(connected["remote_user"], "bob");

    let (mut main, from) = tokio::time::timeout(Duration::from_secs(10), rshd.accept())
        .await
        .expect("the model's rsh_run opens a connection")
        .unwrap();
    let fields = read_fields(&mut main, 4).await;
    let port: u16 = String::from_utf8(fields[0].clone())
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        &fields[1..],
        [b"alice".to_vec(), b"bob".to_vec(), b"uname -a".to_vec()]
    );
    let mut err = TcpStream::connect((from.ip(), port)).await.unwrap();
    main.write_all(b"\0Linux files 6.8.0\n").await.unwrap();
    err.write_all(b"uname: warning\n").await.unwrap();
    let mut stdin = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), main.read_to_end(&mut stdin))
        .await
        .expect("the client ends its input after stdin")
        .unwrap();
    assert_eq!(stdin, b"from the model\n");
    drop(main);
    drop(err);

    let result = wait_event(&state, id, "rsh_result", 0).await;
    assert_eq!(result["accepted"], true);
    assert_eq!(result["stdout"], "Linux files 6.8.0\n");
    assert_eq!(result["stderr"], "uname: warning\n");
    assert_eq!(result["remote_user"], "bob");
    assert_eq!(result["source_port"], from.port());
    assert_eq!(
        result["reserved_source_port"],
        (512..=1023).contains(&from.port())
    );
}

/// The stderr listener takes only the server's own address: a connection from anywhere else
/// is dropped unread, and the server's own is the one whose bytes become stderr.
#[tokio::test]
async fn rsh_client_ignores_a_stderr_connection_from_another_address() {
    let rshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, id) = client(
        "rsh",
        rshd.local_addr().unwrap().to_string(),
        json!({"local_user": "alice", "remote_user": "alice"}),
        chain(RUN_ONCE),
    )
    .await
    .unwrap();
    let (mut main, from) = rshd.accept().await.unwrap();
    let fields = read_fields(&mut main, 4).await;
    let port: u16 = String::from_utf8(fields[0].clone())
        .unwrap()
        .parse()
        .unwrap();
    let intruder_socket = tokio::net::TcpSocket::new_v4().unwrap();
    intruder_socket
        .bind(std::net::SocketAddr::new(non_loopback_address(), 0))
        .unwrap();
    let mut intruder = intruder_socket
        .connect(std::net::SocketAddr::new(from.ip(), port))
        .await
        .unwrap();
    let _ = intruder.write_all(b"forged stderr\n").await;
    let mut err = TcpStream::connect((from.ip(), port)).await.unwrap();
    main.write_all(b"\0ok\n").await.unwrap();
    err.write_all(b"real stderr\n").await.unwrap();
    let mut stdin = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), main.read_to_end(&mut stdin)).await;
    drop(main);
    drop(err);
    let result = wait_event(&state, id, "rsh_result", 0).await;
    assert_eq!(result["stderr"], "real stderr\n", "{result}");
    assert_eq!(result["stdout"], "ok\n");
}

#[tokio::test]
async fn rsh_client_reports_a_refusal_and_without_stderr_sends_an_empty_port() {
    let rshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, id) = client(
        "rsh",
        rshd.local_addr().unwrap().to_string(),
        json!({"local_user": "mallory", "remote_user": "root", "stderr": false}),
        chain(RUN_ONCE),
    )
    .await
    .unwrap();
    let (mut main, _) = rshd.accept().await.unwrap();
    let fields = read_fields(&mut main, 4).await;
    assert_eq!(fields[0], b"", "no stderr connection: an empty port field");
    main.write_all(b"\x01Permission denied.\n").await.unwrap();
    drop(main);
    let result = wait_event(&state, id, "rsh_result", 0).await;
    assert_eq!(result["accepted"], false);
    assert_eq!(result["error"], "Permission denied.");
    assert_eq!(result["stdout"], "");
}

#[tokio::test]
async fn a_client_whose_model_fails_sends_nothing() {
    let rshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // No handler and an unreachable model: the connected event fails, nothing runs.
    let (state, id) = client(
        "rsh",
        rshd.local_addr().unwrap().to_string(),
        json!({"local_user": "alice"}),
        None,
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), rshd.accept())
            .await
            .is_err(),
        "a failed model call must not run anything"
    );
    let _ = (state, id);
}

const REXEC_ONCE: &str = r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'rexec_run','command':'df -h'}] if i['event_type_id']=='rexec_connected' else []
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn rexec_client_sends_the_configured_password_and_the_model_never_sees_it() {
    let rexecd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, id) = client(
        "rexec",
        rexecd.local_addr().unwrap().to_string(),
        json!({"user": "alice", "password": "pa55-in-the-clear", "stderr": false}),
        chain(REXEC_ONCE),
    )
    .await
    .unwrap();
    let (mut main, _) = rexecd.accept().await.unwrap();
    let fields = read_fields(&mut main, 4).await;
    assert_eq!(
        fields,
        [
            b"".to_vec(),
            b"alice".to_vec(),
            b"pa55-in-the-clear".to_vec(),
            b"df -h".to_vec()
        ]
    );
    main.write_all(b"\0/dev/sda1 100G\n").await.unwrap();
    drop(main);
    let result = wait_event(&state, id, "rexec_result", 0).await;
    assert_eq!(result["accepted"], true);
    assert_eq!(result["stdout"], "/dev/sda1 100G\n");
    assert_eq!(result["user"], "alice");
    let everything: String = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap().to_string())
        .collect();
    assert!(!everything.contains("pa55-in-the-clear"), "{everything}");
}

/// The NetGet rexec server as the peer: a logged-in command, a refused one, a wrong password,
/// and the stderr connection, over the whole chain.
#[tokio::test]
async fn rexec_client_against_netget_rexec_over_the_handler_chain() {
    let srv = server::start(
        "rexec",
        server::policy(REXEC_POLICY),
        Some(json!({"accounts": [{"user": "alice", "password": "pw"}]})),
    )
    .await;
    let chain_code = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='rexec_connected': a=[{'type':'rexec_run','command':'ls'}]
elif e['command']=='ls': a=[{'type':'rexec_run','command':'rm x'}]
else: a=[]
print(json.dumps({'actions':a}))"#;
    let (state, id) = client(
        "rexec",
        format!("127.0.0.1:{}", srv.port),
        json!({"user": "alice", "password": "pw"}),
        chain(chain_code),
    )
    .await
    .unwrap();
    let first = wait_event(&state, id, "rexec_result", 0).await;
    assert_eq!(first["accepted"], true);
    assert_eq!(first["stdout"], "alice ran ls\n");
    assert_eq!(first["stderr"], "note\n", "stderr over its own connection");
    let second = wait_event(&state, id, "rexec_result", 1).await;
    assert_eq!(second["accepted"], false);
    assert_eq!(second["error"], "rm: Permission denied");

    let (state, id) = client(
        "rexec",
        format!("127.0.0.1:{}", srv.port),
        json!({"user": "alice", "password": "nope"}),
        chain(REXEC_ONCE),
    )
    .await
    .unwrap();
    let refused = wait_event(&state, id, "rexec_result", 0).await;
    assert_eq!(refused["accepted"], false);
    assert_eq!(refused["error"], "Login incorrect.");
}

/// A handler that answers every result with another command stops at the depth bound, and an
/// injected command runs and reports, with a malformed one refused.
#[tokio::test]
async fn the_chain_is_bounded_and_injected_commands_run() {
    let srv = server::start("rsh", server::policy(RSH_POLICY), None).await;
    let forever = r#"import json,sys
print(json.dumps({'actions':[{'type':'rsh_run','command':'again'}]}))"#;
    let (state, id) = client(
        "rsh",
        format!("127.0.0.1:{}", srv.port),
        json!({"local_user": "alice", "remote_user": "alice"}),
        chain(forever),
    )
    .await
    .unwrap();
    wait_event(&state, id, "rsh_result", 7).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let ran = server::events(&srv.state, srv.id, "rsh_command")
        .await
        .len();
    assert_eq!(ran, 8, "MAX_FOLLOWUP_DEPTH is 8");

    let outcome = state
        .send_to_client(
            id,
            json!({"type": "rsh_run", "command": "whoami"}),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
    match outcome {
        ClientSendOutcome::Executed { detail } => {
            let v: Value = serde_json::from_str(&detail).unwrap();
            assert_eq!(v["stdout"], "ran whoami\n");
        }
        other => panic!("{other:?}"),
    }
    let bad = state
        .send_to_client(id, json!({"type": "rsh_run"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(matches!(bad, ClientSendOutcome::Rejected { .. }), "{bad:?}");
}

const RLOGIN_CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='rlogin_output':
  d=e['data']
  if 'alice\n' in d: a=[{'type':'rlogin_send_key','key':'ctrl-d'}]
  elif d.endswith('$ '): a=[{'type':'rlogin_send_line','line':'whoami'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn rlogin_client_answers_the_window_request_and_types_the_models_lines() {
    let rlogind = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let created = client(
        "rlogin",
        rlogind.local_addr().unwrap().to_string(),
        json!({"local_user": "alice", "remote_user": "alice", "terminal": "vt100",
               "speed": 9600, "rows": 50, "cols": 132}),
        chain(RLOGIN_CHAIN),
    );
    let (accepted, created) = tokio::join!(
        async {
            let (mut s, _) = rlogind.accept().await.unwrap();
            let fields = read_fields(&mut s, 4).await;
            assert_eq!(
                fields,
                [
                    b"".to_vec(),
                    b"alice".to_vec(),
                    b"alice".to_vec(),
                    b"vt100/9600".to_vec()
                ]
            );
            s.write_all(b"\0").await.unwrap();
            s
        },
        created
    );
    let (state, id) = created.unwrap();
    let mut s = accepted;
    socket2::SockRef::from(&s)
        .send_out_of_band(&[0x80])
        .unwrap();
    let mut window = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut window))
        .await
        .expect("the window request is answered")
        .unwrap();
    assert_eq!(window, [0xFF, 0xFF, b's', b's', 0, 50, 0, 132, 0, 0, 0, 0]);
    s.write_all(b"Last login: today\r\n$ ").await.unwrap();
    let mut typed = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut typed))
        .await
        .expect("the model types a line")
        .unwrap();
    assert_eq!(&typed, b"whoami\r", "Enter is CR");
    s.write_all(b"whoami\r\nalice\r\n$ ").await.unwrap();
    let mut key = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut key))
        .await
        .expect("the model presses ^D")
        .unwrap();
    assert_eq!(key, [0x04]);
    let first = wait_event(&state, id, "rlogin_output", 0).await;
    assert!(
        first["control"]
            .as_array()
            .is_some_and(|c| c.iter().any(|v| v == "window_size_requested"))
            || client_events(&state, id, "rlogin_output")
                .await
                .iter()
                .any(|e| e["control"].to_string().contains("window_size_requested")),
        "{first}"
    );
    assert!(client_events(&state, id, "rlogin_output")
        .await
        .iter()
        .any(|e| e["data"]
            .as_str()
            .unwrap_or_default()
            .contains("Last login: today\n$ ")));
}

#[tokio::test]
async fn rlogin_client_refused_at_the_handshake_does_not_connect() {
    let rlogind = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = rlogind.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        let (mut s, _) = rlogind.accept().await.unwrap();
        read_fields(&mut s, 4).await;
        s.write_all(b"\x01rlogind: Permission denied.\r\n")
            .await
            .unwrap();
    });
    let err = client(
        "rlogin",
        addr.to_string(),
        json!({"local_user": "root"}),
        None,
    )
    .await
    .err()
    .expect("a refused login is a failed connect");
    assert!(
        format!("{err:#}").contains("rlogind: Permission denied."),
        "{err:#}"
    );
    serve.await.unwrap();
}

/// NetGet's rlogin client against NetGet's rlogin server: the password prompt answered by the
/// model, the session, logout.
#[tokio::test]
async fn rlogin_client_against_netget_rlogin_through_a_password() {
    let srv = server::start(
        "rlogin",
        server::policy(server::RLOGIN_POLICY),
        Some(json!({"accounts": [{"user": "bob", "password": "builder"}]})),
    )
    .await;
    let code = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='rlogin_output':
  d=e['data']
  if d.endswith('Password: '): a=[{'type':'rlogin_send_line','line':'builder'}]
  elif 'you typed date' in d: a=[{'type':'rlogin_send_line','line':'exit'}]
  elif d.endswith('$ '): a=[{'type':'rlogin_send_line','line':'date'}]
print(json.dumps({'actions':a}))"#;
    let (state, id) = client(
        "rlogin",
        format!("127.0.0.1:{}", srv.port),
        json!({"local_user": "bob", "remote_user": "bob"}),
        chain(code),
    )
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let outs = client_events(&state, id, "rlogin_output").await;
        if outs.iter().any(|e| e["closed"] == true) {
            let all: String = outs
                .iter()
                .map(|e| e["data"].as_str().unwrap_or_default().to_string())
                .collect();
            assert!(all.contains("Welcome bob\n"), "{all}");
            assert!(all.contains("you typed date\n"), "{all}");
            assert!(all.contains("logout\n"), "{all}");
            assert!(
                !all.contains("builder"),
                "the password is not echoed: {all}"
            );
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{outs:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let lines = server::events(&srv.state, srv.id, "rlogin_line").await;
    let typed: Vec<&str> = lines.iter().map(|e| e["line"].as_str().unwrap()).collect();
    assert_eq!(typed, ["date", "exit"]);
}
