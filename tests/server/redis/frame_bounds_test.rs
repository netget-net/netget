//! The size bounds on one inbound RESP frame, each driven at its boundary from a raw socket.
//!
//! `src/server/redis/mod.rs` declares `MAX_PENDING_FRAME_BYTES` (64 MiB) as its
//! `max_inbound_bytes`, and `src/utils/resp.rs` bounds what a frame may *declare* before it has
//! arrived: a `$N` no larger than the largest bulk string that fits that buffer, and
//! `MAX_RESP_ELEMENTS` values in one frame. `resp_depth_test.rs` covers the depth bound and an
//! absurd declared length; this file covers the numbers themselves:
//!
//! - a frame of exactly `MAX_PENDING_FRAME_BYTES` is answered, and one byte more is refused —
//!   whether the extra byte arrives with the rest of the frame or the frame never completes;
//! - the largest `$N` that can fit the buffer is answered and one more is refused on its
//!   header, so a declared length the cap guarantees can never complete is never waited on;
//! - `MAX_RESP_ELEMENTS` is a cap on the values of a whole frame, not on one array header;
//! - a frame's bytes are scanned once, not once per read. The guard used to re-walk the whole
//!   unfinished frame on every 4 KiB read, so a peer trickling a 64 MiB simple string cost the
//!   server about 16 000 walks of up to 64 MiB each — minutes of one tokio worker, from one
//!   unauthenticated connection, before the buffer cap was ever reached.
//!
//! Zero LLM calls: a `*` static handler answers `+PONG` to whatever gets through, and
//! `instruction: Some(String::new())` keeps `ServerForm::create` from substituting its default
//! instruction.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test server -- server::redis::frame_bounds --test-threads=8

use std::time::{Duration, Instant};

use netget::cli::management::ServerForm;
use netget::server::redis::{MAX_BULK_LEN, MAX_PENDING_FRAME_BYTES};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use netget::utils::resp::MAX_RESP_ELEMENTS;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const BUFFER_CAP_REFUSAL: &str = "-ERR Protocol error: invalid multibulk length\r\n";
const BULK_REFUSAL: &str = "-ERR Protocol error: invalid bulk length\r\n";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Redis server #{} never bound a port", id.as_u32());
}

/// A server that answers every command it is allowed to see with `+PONG`.
async fn start_pong_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "redis_simple_string", "value": "PONG" } ]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create redis server");
    wait_for_port(state, server_id).await
}

/// `*<n>\r\n` followed by one bulk string per entry of `lens`, each payload `len` bytes of `x`.
fn bulks(lens: &[usize]) -> Vec<u8> {
    let mut frame = format!("*{}\r\n", lens.len()).into_bytes();
    for &len in lens {
        frame.extend_from_slice(format!("${len}\r\n").as_bytes());
        frame.resize(frame.len() + len, b'x');
        frame.extend_from_slice(b"\r\n");
    }
    frame
}

/// Write `bytes` and stop, then collect everything the server writes until it closes or
/// `deadline` passes. The write runs beside the read, because a server refusing part-way stops
/// reading; every test here sends no more than the server reads before it decides, so the
/// close is a FIN, not a reset that could discard the refusal.
async fn exchange(port: u16, bytes: Vec<u8>, deadline: Duration) -> (Vec<u8>, bool) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();
    let writer = tokio::spawn(async move {
        let _ = write_half.write_all(&bytes).await;
        // Hold the write half open until the reader is done and aborts this task: a FIN from
        // this side would end the session for a reason other than the bound under test.
        std::future::pending::<()>().await;
    });
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = tokio::time::timeout(deadline, async {
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.ends_with(b"+PONG\r\n") {
                        return;
                    }
                }
            }
        }
    })
    .await
    .is_ok();
    writer.abort();
    (out, closed)
}

/// `frame` is accepted by the framing bounds: it is decoded and handed on, and the connection
/// survives it to answer a `PING` pipelined behind it in the same write.
///
/// What answers the frame itself depends on a separate bound downstream. An event larger than
/// the shared JSON budget every handler is held to
/// (`scripting::event_handler::MAX_INTERPOLATION_BYTES` / `_NODES`) is refused there with a
/// RESP error category, which the connection survives; a smaller one gets the static `+PONG`.
/// Either way it must never be the framing refusal, and the `PING` behind it must be answered —
/// which also proves the frame cap is measured after a complete frame is consumed, not over
/// the whole buffer with the pipelined command in it.
async fn assert_passes_framing(port: u16, mut frame: Vec<u8>, what: &str) {
    frame.extend_from_slice(b"*1\r\n$4\r\nPING\r\n");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.split();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    // Two replies: one to the frame, one to the PING.
    let read = async {
        while out.windows(2).filter(|w| w == b"\r\n").count() < 2 {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    };
    let write = async {
        let _ = write_half.write_all(&frame).await;
    };
    let _ = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(read, write);
    })
    .await;
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("Protocol error"),
        "{what} must pass the framing bounds: {text:?}"
    );
    assert!(
        text == "+PONG\r\n+PONG\r\n"
            || text == "-ERR netget: request could not be processed\r\n+PONG\r\n",
        "{what} must be answered or refused by the event budget, and the PING behind it \
         answered on the same connection: {text:?}"
    );
}

/// The frame cap, both sides of it, and both ways of passing it.
#[tokio::test]
async fn a_frame_of_exactly_the_buffer_cap_is_answered_and_one_byte_more_is_not() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    // Exactly the cap: the largest bulk string that fits, with the least framing a request can
    // have around it (`*1\r\n$N\r\n…\r\n`).
    let at_cap = bulks(&[MAX_BULK_LEN]);
    assert_eq!(at_cap.len(), MAX_PENDING_FRAME_BYTES);
    assert_passes_framing(port, at_cap, "a frame of exactly MAX_PENDING_FRAME_BYTES").await;

    // One byte over, complete: two bulk strings whose total frame is the cap plus one. The
    // last byte arrives in the read that completes the frame, so this is the case a check on
    // the *unfinished* buffer alone cannot see.
    let first = MAX_PENDING_FRAME_BYTES / 2;
    // `*2\r\n` and the first bulk string, then `$<L>\r\n<L bytes>\r\n` with L's eight digits.
    let ahead = bulks(&[first]).len();
    let second = MAX_PENDING_FRAME_BYTES + 1 - ahead - (1 + 8 + 2 + 2);
    let over = bulks(&[first, second]);
    assert_eq!(over.len(), MAX_PENDING_FRAME_BYTES + 1);
    let (out, closed) = exchange(port, over, Duration::from_secs(60)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        BUFFER_CAP_REFUSAL,
        "a complete frame one byte past the cap must be refused, never answered"
    );
    assert!(closed, "the server must close after refusing");

    // One byte over, never completing: the frame declares two 40 MB bulk strings and the peer
    // sends the cap plus one byte of it, then waits. Without the cap the server would wait
    // with it, buffering, until the 80 MB arrived.
    let mut unfinished = bulks(&[40_000_000, 40_000_000]);
    unfinished.truncate(MAX_PENDING_FRAME_BYTES + 1);
    let (out, closed) = exchange(port, unfinished, Duration::from_secs(60)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        BUFFER_CAP_REFUSAL,
        "an unfinished frame past the cap must be refused rather than buffered"
    );
    assert!(closed, "the server must close after refusing");
}

/// `$N` is refused on its header exactly when no frame carrying it could fit the buffer.
#[tokio::test]
async fn the_largest_bulk_that_fits_is_waited_for_and_one_larger_is_refused_on_its_header() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    // One past the largest that fits: refused on the header, before any payload is sent.
    let header = format!("*1\r\n${}\r\n", MAX_BULK_LEN + 1).into_bytes();
    let (out, closed) = exchange(port, header, Duration::from_secs(10)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        BULK_REFUSAL,
        "a $N that cannot fit MAX_PENDING_FRAME_BYTES even alone can never complete; it must \
         be refused on the header, not after the peer has filled the buffer"
    );
    assert!(closed, "the server must close after refusing");

    // The largest that fits: the header alone is not refused — the server waits for the
    // payload. (The first test sends that payload and gets `+PONG`.)
    let header = format!("*1\r\n${MAX_BULK_LEN}\r\n").into_bytes();
    let (out, closed) = exchange(port, header, Duration::from_secs(2)).await;
    assert!(
        out.is_empty() && !closed,
        "a $N that fits must be waited for, got {:?} (closed: {closed})",
        String::from_utf8_lossy(&out)
    );
}

/// `MAX_RESP_ELEMENTS` counts every value in the frame — the arrays themselves included — so
/// it bounds what the decoder allocates for the whole frame, not for one header.
#[tokio::test]
async fn the_element_cap_holds_for_a_whole_frame_not_one_header() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    // The outer array is one value, so it may promise MAX_RESP_ELEMENTS - 1 more. Sent whole
    // (four megabytes of `:1`) and answered.
    let elements = MAX_RESP_ELEMENTS - 1;
    let mut full = format!("*{elements}\r\n").into_bytes();
    full.extend_from_slice(&b":1\r\n".repeat(elements));
    let started = Instant::now();
    assert_passes_framing(port, full, "a frame of exactly MAX_RESP_ELEMENTS values").await;
    println!(
        "{} values scanned, decoded and answered in {:?}",
        MAX_RESP_ELEMENTS,
        started.elapsed()
    );

    // One more on a single header: refused at once.
    let header = format!("*{MAX_RESP_ELEMENTS}\r\n").into_bytes();
    let (out, closed) = exchange(port, header, Duration::from_secs(10)).await;
    assert_eq!(String::from_utf8_lossy(&out), BUFFER_CAP_REFUSAL);
    assert!(closed, "the server must close after refusing");

    // Split across two nested arrays, each header comfortably under the cap on its own: the
    // second is refused because of what the first already promised. A per-header check alone
    // would let this frame carry twice the cap.
    let first = MAX_RESP_ELEMENTS / 2 + 1000;
    let mut split = format!("*2\r\n*{first}\r\n").into_bytes();
    split.extend_from_slice(&b":1\r\n".repeat(first));
    split.extend_from_slice(format!("*{first}\r\n").as_bytes());
    let (out, closed) = exchange(port, split, Duration::from_secs(60)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        BUFFER_CAP_REFUSAL,
        "the frame's second array takes its total past MAX_RESP_ELEMENTS"
    );
    assert!(closed, "the server must close after refusing");
}

/// A simple string has no length prefix, so finding its end means looking for CRLF. Looking
/// from the start of the frame on every read made the cost of one unfinished line quadratic in
/// its length; looking only at the bytes that arrived since makes it linear. The deadline is
/// generous for a linear walk of 64 MiB in a debug build and hopeless for ~16 000 of them.
#[tokio::test]
async fn an_unfinished_line_is_walked_once_not_once_per_read() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    let mut line = b"*1\r\n+".to_vec();
    line.resize(MAX_PENDING_FRAME_BYTES + 1, b'a');
    let started = Instant::now();
    let (out, closed) = exchange(port, line, Duration::from_secs(45)).await;
    let elapsed = started.elapsed();
    assert!(
        closed,
        "a 64 MiB line with no CRLF was neither refused nor closed within 45s ({} bytes of \
         reply): the guard is re-walking the unfinished frame on every read",
        out.len()
    );
    assert_eq!(String::from_utf8_lossy(&out), BUFFER_CAP_REFUSAL);
    println!("64 MiB line refused at the buffer cap after {elapsed:?}");

    // And the server is still serving.
    let (out, _) = exchange(
        port,
        b"*1\r\n$4\r\nPING\r\n".to_vec(),
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&out), "+PONG\r\n");
}

/// `levels` arrays nested around `"x"`.
fn nested_json(levels: usize) -> serde_json::Value {
    (0..levels).fold(serde_json::json!("x"), |inner, _| {
        serde_json::json!([inner])
    })
}

/// `MAX_REPLY_DEPTH` bounds what the server *writes*: a model's RESP3 `redis_array` is encoded
/// natively, nested arrays and all, and a client's reader recurses over it as ours would. The
/// bound must hold at its number: 32 levels are written, 33 are refused and nothing of them
/// reaches the wire.
#[tokio::test]
async fn a_resp3_reply_nested_past_max_reply_depth_is_never_written() {
    use netget::server::redis::resp3::MAX_REPLY_DEPTH;

    for (levels, written) in [(MAX_REPLY_DEPTH, true), (MAX_REPLY_DEPTH + 1, false)] {
        let state = new_state().await;
        let (tx, _rx) = mpsc::unbounded_channel();
        // The outer array is the action itself; its one value carries the rest.
        let values = serde_json::json!([nested_json(levels - 1)]);
        let id = ServerForm {
            protocol: "redis".to_string(),
            port: Some(0),
            instruction: Some(String::new()),
            event_handlers: Some(vec![serde_json::json!({
                "event_pattern": "redis_command",
                "handler": {"type": "static", "actions": [
                    {"type": "redis_array", "values": values}
                ]}
            })]),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .expect("create redis server");
        let port = wait_for_port(&state, id).await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        // HELLO 3 is answered by the server itself; its map arrives whole in one small reply.
        stream
            .write_all(b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n")
            .await
            .expect("write HELLO");
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("HELLO reply")
            .expect("read HELLO reply");
        assert!(buf[..n].starts_with(b"%"), "HELLO 3 is answered with a map");

        stream
            .write_all(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
            .await
            .expect("write GET");
        let expected = {
            let mut frame = b"*1\r\n".repeat(levels);
            frame.extend_from_slice(b"$1\r\nx\r\n");
            frame
        };
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), async {
            while !(reply.ends_with(b"\r\n")
                && (reply.starts_with(b"-") || reply.len() >= expected.len()))
            {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => reply.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await;
        if written {
            assert_eq!(
                String::from_utf8_lossy(&reply),
                String::from_utf8_lossy(&expected),
                "{levels} levels is within MAX_REPLY_DEPTH and must be written natively"
            );
        } else {
            assert!(
                reply.starts_with(b"-ERR ") && !reply.starts_with(b"*"),
                "{levels} levels is past MAX_REPLY_DEPTH: the reply must be an error, never the \
                 frame or part of it; got {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
    }
}

/// While a command is being answered the server keeps reading its socket (so it notices a peer
/// that hangs up), and what arrives in that time is new inbound state. It must sit under the
/// same cap as the frame buffer: past it the server stops reading, the peer's writes back up in
/// TCP, and the oversize frame is refused once the answer is out.
///
/// The command is answered by a handler that sleeps, and the peer sends three times the cap of
/// an unfinished frame behind it. Without the bound the server would take all of it during the
/// call; with it, what the peer manages to write before the answer arrives is the cap plus
/// whatever the kernel's socket buffers hold.
#[tokio::test]
async fn bytes_arriving_while_a_command_is_answered_are_under_the_frame_cap() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "redis_command",
            "handler": {"type": "script", "language": "python", "code":
                "import json,sys,time\ntime.sleep(4)\nprint(json.dumps({'actions':[{'type':'redis_simple_string','value':'SLOW'}]}))"}
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create redis server");
    let port = wait_for_port(&state, id).await;

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();
    let written = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = written.clone();
    let writer = tokio::spawn(async move {
        let _ = write_half.write_all(b"*1\r\n$4\r\nSLOW\r\n").await;
        let mut first = b"*1\r\n+".to_vec();
        first.resize(1 << 20, b'a');
        let rest = vec![b'a'; 1 << 20];
        for i in 0..(3 * MAX_PENDING_FRAME_BYTES) >> 20 {
            let part = if i == 0 { &first } else { &rest };
            if write_half.write_all(part).await.is_err() {
                return;
            }
            counter.fetch_add(part.len(), Ordering::SeqCst);
        }
        // Hold the write half open until the reader aborts this task.
        std::future::pending::<()>().await;
    });

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut written_at_answer = None;
    let _ = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if written_at_answer.is_none() && out.starts_with(b"+SLOW\r\n") {
                        written_at_answer = Some(written.load(Ordering::SeqCst));
                    }
                }
            }
        }
    })
    .await;
    writer.abort();

    let written_at_answer = written_at_answer.unwrap_or_else(|| {
        panic!(
            "the slow command was never answered: {:?}",
            String::from_utf8_lossy(&out[..out.len().min(200)])
        )
    });
    println!("the peer had written {written_at_answer} bytes when the answer arrived");
    assert!(
        written_at_answer < MAX_PENDING_FRAME_BYTES + (32 << 20),
        "the server took {written_at_answer} bytes while answering one command: what arrives \
         mid-call is not bounded by the frame cap"
    );
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("+SLOW\r\n{BUFFER_CAP_REFUSAL}"),
        "after the answer, the unfinished frame behind it is refused at the cap and the \
         connection closed"
    );
}
