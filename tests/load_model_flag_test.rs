//! `netget --load <file> --model <name>` asks the model it was told to.
//!
//! The `--load` path built its state without reading `--model`, so the first model call
//! auto-selected the largest model the endpoint listed. Nothing failed: a seeded real-model
//! measurement run with `--model llama3.1:8b` simply measured another model.
//!
//! Drives the real binary against a hand-written Ollama that lists two models (the larger
//! first by size, so auto-selection would pick it) and records the `model` field of every
//! generate/chat request. A `--load`ed TCP server with an instruction asks the model once a
//! peer sends a line.

#[path = "helpers/child_guard.rs"]
mod child_guard;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Answer `/api/tags` with two models; record the model each generate/chat request names and
/// answer it 500 (the request is the evidence; the answer does not matter).
fn fake_ollama(listener: TcpListener, models_asked: Arc<Mutex<Vec<String>>>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let models_asked = models_asked.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                return;
            }
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let (status, reply) = if request_line.contains("/api/tags") {
                (
                    "200 OK",
                    serde_json::json!({"models": [
                        {"name": "huge-model:70b", "model": "huge-model:70b", "size": 40_000_000_000u64},
                        {"name": "small-model:1b", "model": "small-model:1b", "size": 800_000_000u64}
                    ]})
                    .to_string(),
                )
            } else {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                    if let Some(model) = json["model"].as_str() {
                        models_asked.lock().unwrap().push(model.to_string());
                    }
                }
                (
                    "500 Internal Server Error",
                    r#"{"error":"not answering"}"#.to_string(),
                )
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        });
    }
}

#[test]
fn a_loaded_run_asks_the_model_named_by_the_model_flag() {
    let ollama = TcpListener::bind("127.0.0.1:0").expect("bind fake ollama");
    let ollama_port = ollama.local_addr().unwrap().port();
    let models_asked = Arc::new(Mutex::new(Vec::new()));
    std::thread::spawn({
        let models_asked = models_asked.clone();
        move || fake_ollama(ollama, models_asked)
    });

    let dir = std::env::temp_dir().join(format!(
        "netget-load-model-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("run.netget");
    let ready = dir.join("ready.json");
    std::fs::write(
        &file,
        serde_json::json!({"actions": [{
            "type": "open_server",
            "port": 0,
            "host": "127.0.0.1",
            "base_stack": "tcp",
            "instruction": "Answer every line with the word ok."
        }]})
        .to_string(),
    )
    .expect("write load file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--load",
            file.to_str().unwrap(),
            "--model",
            "small-model:1b",
            "--ollama-url",
            &format!("http://127.0.0.1:{ollama_port}"),
            "--ready-file",
            ready.to_str().unwrap(),
            "--run-for",
            "60",
            "--log-level",
            "error",
        ])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn netget");
    child_guard::tie_child(child.id());

    let deadline = Instant::now() + Duration::from_secs(60);
    let port = loop {
        if let Ok(text) = std::fs::read_to_string(&ready) {
            if let Ok(report) = serde_json::from_str::<serde_json::Value>(&text) {
                break report["servers"][0]["port"].as_u64().expect("port") as u16;
            }
        }
        assert!(Instant::now() < deadline, "netget never became ready");
        assert!(child.try_wait().unwrap().is_none(), "netget exited early");
        std::thread::sleep(Duration::from_millis(50));
    };

    let mut peer = TcpStream::connect(("127.0.0.1", port)).expect("connect to the tcp server");
    peer.write_all(b"hello\n").expect("send a line");

    let deadline = Instant::now() + Duration::from_secs(60);
    while models_asked.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "the server never asked the model about the line"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let asked = models_asked.lock().unwrap().clone();
    assert!(
        asked.iter().all(|m| m == "small-model:1b"),
        "--model names the model a --load run asks; it asked {asked:?}"
    );
}
