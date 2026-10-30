//! The shipped listener replaces the ad-hoc Python MCP client: real process,
//! persistent JSON lines, actual bytes on the wire and reconnect after restart.
#![cfg(all(feature = "mcp-http", unix))]
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::{
    streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
};
use rmcp::{serve_client, RoleClient};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[path = "helpers/child_guard.rs"]
mod child_guard;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        child_guard::untie_child(self.0.id());
    }
}
fn control(port: u16) -> (Process, u16) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--mcp-http",
            &port.to_string(),
            "--llm-agent",
            "--log-level",
            "info",
        ])
        .env_remove("NETGET_MCP_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_guard::tie_child(child.id());
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(rest) = line.split("listening on http://").nth(1) {
                if let Some(port) = rest
                    .split('/')
                    .next()
                    .and_then(|a| a.rsplit(':').next())
                    .and_then(|p| p.parse::<u16>().ok())
                {
                    let _ = tx.send(port);
                }
            }
        }
    });
    let process = Process(child);
    let port = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("MCP listener started");
    (process, port)
}
async fn manage(port: u16) -> RunningService<RoleClient, ()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let transport = StreamableHttpClientTransport::with_client(
        reqwest_mcp::Client::builder().no_proxy().build().unwrap(),
        StreamableHttpClientTransportConfig::with_uri(format!("http://127.0.0.1:{port}/mcp")),
    );
    serve_client((), transport).await.unwrap()
}
async fn tcp_server(client: &RunningService<RoleClient, ()>) -> u16 {
    let mut params = CallToolRequestParams::new("start_server");
    params.arguments =
        json!({"protocol":"tcp","port":0,"instruction":"Return the agent's response."})
            .as_object()
            .cloned();
    let result = client.call_tool(params).await.unwrap();
    assert_ne!(result.is_error, Some(true));
    let result = client
        .call_tool(CallToolRequestParams::new("list_servers"))
        .await
        .unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<String>();
    text.split("port ")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}
async fn request(receiver: std::sync::Arc<std::sync::Mutex<mpsc::Receiver<String>>>) -> Value {
    let line = tokio::task::spawn_blocking(move || {
        receiver
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(20))
    })
    .await
    .unwrap()
    .expect("listener emits request JSON");
    serde_json::from_str(&line).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listener_delivers_answers_reconnects_and_exits_on_stdin_eof() {
    let (server, port) = control(0);
    let client = manage(port).await;
    let tcp = tcp_server(&client).await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--agent-connect",
            &format!("http://127.0.0.1:{port}/mcp"),
            "--log-level",
            "off",
        ])
        .env_remove("NETGET_MCP_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child_guard::tie_child(child.id());
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let mut listener = Process(child);
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", tcp))
        .await
        .unwrap();
    socket.write_all(b"first\n").await.unwrap();
    let first = request(rx.clone()).await;
    assert_eq!(first["type"], "request");
    assert_eq!(
        first["request"]["context"]["event_type"],
        "tcp_data_received"
    );
    writeln!(stdin,"{}",json!({"request_id":first["request"]["request_id"],"claim_token":first["request"]["claim_token"],"actions":[{"type":"send_tcp_data","data":"PONG\n"}]})).unwrap();
    let mut buf = [0; 5];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"PONG\n");
    drop(socket);
    drop(server);
    drop(client);
    let (server, _) = control(port);
    let client = manage(port).await;
    let tcp = tcp_server(&client).await;
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", tcp))
        .await
        .unwrap();
    socket.write_all(b"second\n").await.unwrap();
    let second = request(rx).await;
    assert_ne!(
        second["request"]["claim_token"], first["request"]["claim_token"],
        "tokens must not repeat across restarts"
    );
    // A delayed host answer for an old process must not match a recycled id.
    assert_eq!(
        second["request"]["request_id"],
        first["request"]["request_id"]
    );
    writeln!(stdin,"{}",json!({"request_id":first["request"]["request_id"],"claim_token":first["request"]["claim_token"],"actions":[{"type":"send_tcp_data","data":"STALE"}]})).unwrap();
    writeln!(stdin,"{}",json!({"request_id":second["request"]["request_id"],"claim_token":second["request"]["claim_token"],"actions":[{"type":"send_tcp_data","data":"BACK\n"}]})).unwrap();
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"BACK\n");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = listener.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("stdin EOF stops the waiting listener promptly");
    drop(listener);
    // Ctrl+C must also exit while stdin remains open and blocked. Tokio's
    // uncancellable stdin task would otherwise keep the process runtime alive.
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--agent-connect",
            &format!("http://127.0.0.1:{port}/mcp"),
            "--log-level",
            "off",
        ])
        .env_remove("NETGET_MCP_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_guard::tie_child(child.id());
    let stderr = child.stderr.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("agent: waiting") {
                let _ = ready_tx.send(());
            }
        }
    });
    let mut listener = Process(child);
    tokio::task::spawn_blocking(move || ready_rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("listener waits with stdin still open");
    assert_eq!(
        unsafe { libc::kill(listener.0.id() as i32, libc::SIGINT) },
        0
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = listener.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Ctrl+C must not wait for stdin to close");
    drop(listener);
    drop(client);
    drop(server);
}
