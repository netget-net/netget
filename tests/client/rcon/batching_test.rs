//! Does the RCON client answer command results that arrived during a model call together,
//! when it batches?
//!
//! The session runs the model's commands one after another while the dispatcher is still
//! asking the model about the first result, so with three commands in one answer the second
//! and third results queue during that call. With batching on the dispatcher answers
//! everything waiting in one call, one `rcon_response` event each; off, one call per result.
//!
//! The fixture is a Minecraft-dialect RCON server: it answers the first command at once
//! (`alpha`) and the other two only once the model is busy with it.

use std::time::Duration;

use crate::client::batching_support::{assert_one_event_per_message, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn packet(id: i32, kind: i32, body: &str) -> Vec<u8> {
    let mut out = ((body.len() + 10) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// One packet: (id, kind).
async fn read(s: &mut TcpStream) -> (i32, i32) {
    let mut size = [0u8; 4];
    s.read_exact(&mut size).await.expect("size");
    let mut rest = vec![0u8; i32::from_le_bytes(size) as usize];
    s.read_exact(&mut rest).await.expect("packet");
    (
        i32::from_le_bytes(rest[0..4].try_into().unwrap()),
        i32::from_le_bytes(rest[4..8].try_into().unwrap()),
    )
}

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (mut s, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    assert_eq!(read(&mut s).await, (0, 3), "login");
    s.write_all(&packet(0, 2, "")).await.expect("auth response");
    let mut go = Some(go);
    for output in ["alpha", "bravo", "charlie"] {
        let (id, kind) = read(&mut s).await;
        assert_eq!(kind, 2, "EXECCOMMAND");
        match output {
            "bravo" => {
                let _ = go.take().expect("once").await;
            }
            "charlie" => tokio::time::sleep(Duration::from_millis(200)).await,
            _ => {}
        }
        s.write_all(&packet(id, 0, output)).await.expect("output");
    }
    let mut sink = [0u8; 64];
    while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rcon_client_answers_results_that_arrived_during_a_call_together() {
    let commands = serde_json::json!([
        {"type": "rcon_command", "command": "one"},
        {"type": "rcon_command", "command": "two"},
        {"type": "rcon_command", "command": "three"},
    ]);
    assert_one_event_per_message(
        &Session {
            protocol: "rcon",
            startup_params: Some(serde_json::json!({"password": "secret", "dialect": "minecraft"})),
            data_event: "rcon_response",
            alpha: ("output", "alpha"),
            connected: Some(("rcon_connected", commands)),
        },
        peer,
    )
    .await;
}
