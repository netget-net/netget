//! Every connection deadline, each set short by its startup parameter with every other one long,
//! so the one under test is the only one that can close the connection: a peer that stalls is
//! cut off at that deadline — not before it, and not at the default (30, 60, 120 or 300 s) the
//! parameter replaces.
use super::support::{policy, start, Started, POLICY};
use super::wire_test::{
    bytes, call, create_req, extended, int, read_block_op, read_whole, src, write_block_op, Data,
    Raw,
};
use netget::server::hdfs::proto::hdfs as pb;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The deadline under test, seconds.
const SHORT: u64 = 2;
/// Every other deadline: far past anything a test waits for.
const LONG: u64 = 600;
/// How long a test waits for the close before calling the deadline broken.
const WAIT: Duration = Duration::from_secs(SHORT + 6);

/// Startup parameters with `short` at SHORT seconds and every other deadline LONG.
fn deadlines(short: &str) -> Value {
    let mut p = json!({});
    for k in [
        "header_timeout_secs",
        "frame_timeout_secs",
        "idle_timeout_secs",
        "op_idle_timeout_secs",
        "packet_timeout_secs",
    ] {
        p[k] = json!(if k == short { SHORT } else { LONG });
    }
    p
}

/// Read until the server closes the connection; how long that took from `since`, or `None`
/// when it is still open after WAIT.
async fn closed_after(s: &mut TcpStream, since: Instant) -> Option<Duration> {
    let mut buf = [0u8; 4096];
    loop {
        let left = WAIT.checked_sub(since.elapsed())?;
        match tokio::time::timeout(left, s.read(&mut buf)).await {
            Err(_) => return None,
            Ok(Ok(0)) | Ok(Err(_)) => return Some(since.elapsed()),
            Ok(Ok(_)) => continue,
        }
    }
}

fn assert_cut_at(what: &str, took: Option<Duration>, server: &Started) {
    let took = took.unwrap_or_else(|| {
        panic!(
            "{what}: still open {} s after the stall; the {SHORT} s deadline did not fire\n{}",
            WAIT.as_secs(),
            server.dump_logs()
        )
    });
    assert!(
        took >= Duration::from_millis(SHORT * 1000 - 150),
        "{what}: closed after {took:?}, before the {SHORT} s deadline"
    );
    println!("{what}: closed after {took:?} (deadline {SHORT} s)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namenode_header_deadline() {
    let server = start(policy(POLICY), Some(deadlines("header_timeout_secs"))).await;
    // Nothing at all: the connection header never comes.
    let mut s = TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    let t0 = Instant::now();
    assert_cut_at(
        "NameNode, no header",
        closed_after(&mut s, t0).await,
        &server,
    );
    // The header, but no connection context.
    let mut r = Raw::open(server.port).await;
    r.send(&[b"hrpc".to_vec(), vec![9, 0, 0]].concat()).await;
    let t0 = Instant::now();
    assert_cut_at(
        "NameNode, no context",
        closed_after(&mut r.s, t0).await,
        &server,
    );
    assert!(
        server
            .wait_line(&format!("no connection header within {SHORT} s"), 5)
            .await
            .is_some(),
        "{}",
        server.dump_logs()
    );
    assert!(server
        .wait_line(&format!("no frame began within {SHORT} s"), 5)
        .await
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namenode_frame_deadline() {
    let server = start(policy(POLICY), Some(deadlines("frame_timeout_secs"))).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let ok = r.call(1, "getFileInfo", &src("/README.txt")).await;
    assert!(ok.ok());
    // Two bytes of a frame's length, and then nothing.
    r.send(&[0, 0]).await;
    let t0 = Instant::now();
    assert_cut_at(
        "NameNode, half a frame",
        closed_after(&mut r.s, t0).await,
        &server,
    );
    assert!(server
        .wait_line(
            &format!("the rest of a frame did not arrive within {SHORT} s"),
            5
        )
        .await
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namenode_idle_deadline() {
    let server = start(policy(POLICY), Some(deadlines("idle_timeout_secs"))).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let ok = r.call(1, "getFileInfo", &src("/README.txt")).await;
    assert!(ok.ok());
    let t0 = Instant::now();
    assert_cut_at("NameNode, idle", closed_after(&mut r.s, t0).await, &server);
    assert!(server
        .wait_line(&format!("no frame began within {SHORT} s"), 5)
        .await
        .is_some());
}

/// The README's one block, located by a raw NameNode session.
async fn readme_block(server: &Started) -> pb::LocatedBlockProto {
    let mut r = Raw::hello(server.port, "alice").await;
    r.call(
        1,
        "getBlockLocations",
        &[src("/README.txt"), int(2, 0), int(3, 1 << 20)].concat(),
    )
    .await
    .decode::<pb::GetBlockLocationsResponseProto>()
    .locations
    .unwrap()
    .blocks
    .remove(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datanode_first_op_and_frame_deadlines() {
    let server = start(policy(POLICY), Some(deadlines("header_timeout_secs"))).await;
    let mut s = TcpStream::connect(("127.0.0.1", server.datanode_port))
        .await
        .unwrap();
    let t0 = Instant::now();
    assert_cut_at(
        "DataNode, no first op",
        closed_after(&mut s, t0).await,
        &server,
    );
    assert!(server
        .wait_line(&format!("no first op within {SHORT} s"), 5)
        .await
        .is_some());

    let server = start(policy(POLICY), Some(deadlines("frame_timeout_secs"))).await;
    let mut d = Data::open(server.datanode_port).await;
    // One byte of the version, and then nothing.
    d.send(&[0]).await;
    let t0 = Instant::now();
    assert_cut_at(
        "DataNode, half an op",
        closed_after(&mut d.s, t0).await,
        &server,
    );
    assert!(server
        .wait_line(
            &format!("an op's header did not arrive within {SHORT} s"),
            5
        )
        .await
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datanode_op_idle_deadline() {
    let server = start(policy(POLICY), Some(deadlines("op_idle_timeout_secs"))).await;
    let block = readme_block(&server).await;
    let mut d = Data::open(server.datanode_port).await;
    d.send(&read_block_op(&block.b, 0, 18)).await;
    let resp: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(resp.status, 0);
    assert_eq!(read_whole(&mut d).await, b"hello from netget\n");
    // The read status went; the connection is kept for a next op that never comes.
    let t0 = Instant::now();
    assert_cut_at(
        "DataNode, idle after an op",
        closed_after(&mut d.s, t0).await,
        &server,
    );
    assert!(server
        .wait_line(&format!("no next op within {SHORT} s"), 5)
        .await
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datanode_packet_deadline() {
    let server = start(policy(POLICY), Some(deadlines("packet_timeout_secs"))).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let client = "stalling-writer";
    let created = r
        .call(1, "create", &create_req("/tmp/stall.txt", client))
        .await;
    assert!(created.ok(), "{created:?}");
    let block = r
        .call(
            2,
            "addBlock",
            &[src("/tmp/stall.txt"), bytes(2, client.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AddBlockResponseProto>()
        .block;
    let mut d = Data::open(server.datanode_port).await;
    d.send(&write_block_op(&block.b, client)).await;
    let resp: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(resp.status, 0);
    // The pipeline is up and no packet follows.
    let t0 = Instant::now();
    assert_cut_at(
        "DataNode, no packet",
        closed_after(&mut d.s, t0).await,
        &server,
    );
    assert!(server
        .wait_line(&format!("within {SHORT} s; dropped and closed"), 5)
        .await
        .is_some());
    // Nothing of the block was kept.
    let mut last = block.b.clone();
    last.num_bytes = Some(0);
    r.send(&call(
        3,
        "complete",
        &[
            src("/tmp/stall.txt"),
            bytes(2, client.as_bytes()),
            bytes(3, &extended(&last)),
        ]
        .concat(),
    ))
    .await;
    let incomplete = r.response().await.unwrap();
    assert!(
        incomplete.message().contains("has not been written"),
        "{incomplete:?}"
    );
}
