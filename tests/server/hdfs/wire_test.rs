//! The HDFS server's bounds, call-id correlation, checksum verification and fail-closed paths,
//! driven by a raw client that writes every request byte by byte from the wire format
//! (`hrpc`, four-byte frame lengths, varint-delimited messages whose fields are encoded here,
//! DataTransferProtocol op headers and packets, CRC32C computed here). Responses are decoded
//! with prost against Hadoop's own .proto files. Every byte each way is kept for the pcap
//! oracle.
use super::support::{self, crc32c, policy, start, Started, POLICY};
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::hdfs::proto::common::{RpcResponseHeaderProto, RpcSaslProto};
use netget::server::hdfs::proto::hdfs as pb;
use prost::Message;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ------------------------------------------------------------------ protobuf, by hand

fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

fn key(field: u32, wire: u32) -> Vec<u8> {
    varint((field << 3 | wire) as u64)
}

fn int(field: u32, n: u64) -> Vec<u8> {
    [key(field, 0), varint(n)].concat()
}

fn sint(field: u32, n: i32) -> Vec<u8> {
    int(field, ((n << 1) ^ (n >> 31)) as u32 as u64)
}

fn bytes(field: u32, b: &[u8]) -> Vec<u8> {
    [key(field, 2), varint(b.len() as u64), b.to_vec()].concat()
}

fn delimited(m: &[u8]) -> Vec<u8> {
    [varint(m.len() as u64), m.to_vec()].concat()
}

fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
    let body = parts.concat();
    [(body.len() as u32).to_be_bytes().to_vec(), body].concat()
}

const CLIENT_ID: [u8; 16] = *b"netget-raw-test!";
const CLIENT_PROTOCOL: &str = "org.apache.hadoop.hdfs.protocol.ClientProtocol";

/// RpcRequestHeaderProto: rpcKind PROTOCOL_BUFFER, rpcOp FINAL_PACKET, callId, clientId, retry.
fn rpc_header(call_id: i32) -> Vec<u8> {
    [
        int(1, 2),
        int(2, 0),
        sint(3, call_id),
        bytes(4, &CLIENT_ID),
        sint(5, 0),
    ]
    .concat()
}

fn connection_context(user: &str) -> Vec<u8> {
    frame(&[
        delimited(&rpc_header(-3)),
        delimited(
            &[
                bytes(2, &bytes(1, user.as_bytes())),
                bytes(3, CLIENT_PROTOCOL.as_bytes()),
            ]
            .concat(),
        ),
    ])
}

fn call(call_id: i32, method: &str, request: &[u8]) -> Vec<u8> {
    let method_header = [
        bytes(1, method.as_bytes()),
        bytes(2, CLIENT_PROTOCOL.as_bytes()),
        int(3, 1),
    ]
    .concat();
    frame(&[
        delimited(&rpc_header(call_id)),
        delimited(&method_header),
        delimited(request),
    ])
}

fn src(path: &str) -> Vec<u8> {
    bytes(1, path.as_bytes())
}

// ------------------------------------------------------------------ the raw client

/// One NameNode connection, every byte each way recorded in order.
struct Raw {
    s: TcpStream,
    wire: Vec<(bool, Vec<u8>)>,
}

#[derive(Debug)]
struct Response {
    header: RpcResponseHeaderProto,
    body: Vec<u8>,
}

impl Response {
    fn call_id(&self) -> i32 {
        self.header.call_id as i32
    }
    fn ok(&self) -> bool {
        self.header.status == 0
    }
    fn class(&self) -> &str {
        self.header.exception_class_name.as_deref().unwrap_or("")
    }
    fn message(&self) -> &str {
        self.header.error_msg.as_deref().unwrap_or("")
    }
    fn decode<M: Message + Default>(&self) -> M {
        assert!(self.ok(), "a failed call: {self:?}");
        let (len, n) = read_varint(&self.body);
        M::decode(&self.body[n..n + len as usize]).expect("the response decodes")
    }
}

fn read_varint(b: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    for (i, x) in b.iter().enumerate().take(10) {
        v |= ((x & 0x7F) as u64) << (7 * i);
        if x & 0x80 == 0 {
            return (v, i + 1);
        }
    }
    panic!("an unterminated varint")
}

impl Raw {
    async fn open(port: u16) -> Raw {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        Raw { s, wire: vec![] }
    }

    /// The connection header (SIMPLE, no SASL) and the connection context for `user`.
    async fn hello(port: u16, user: &str) -> Raw {
        let mut r = Raw::open(port).await;
        r.send(&[b"hrpc".to_vec(), vec![9, 0, 0], connection_context(user)].concat())
            .await;
        r
    }

    async fn send(&mut self, b: &[u8]) {
        self.s.write_all(b).await.unwrap();
        self.wire.push((true, b.to_vec()));
    }

    /// One response frame, or `None` when the server closed the connection.
    async fn response(&mut self) -> Option<Response> {
        let mut len = [0u8; 4];
        let read = tokio::time::timeout(Duration::from_secs(30), self.s.read_exact(&mut len)).await;
        match read {
            Err(_) => panic!("no response within 30 s"),
            Ok(Err(_)) => return None,
            Ok(Ok(_)) => {}
        }
        let n = u32::from_be_bytes(len) as usize;
        assert!(n < 64 << 20, "a response of {n} bytes");
        let mut body = vec![0u8; n];
        self.s.read_exact(&mut body).await.unwrap();
        self.wire
            .push((false, [len.to_vec(), body.clone()].concat()));
        let (hlen, used) = read_varint(&body);
        let header = RpcResponseHeaderProto::decode(&body[used..used + hlen as usize]).unwrap();
        Some(Response {
            header,
            body: body[used + hlen as usize..].to_vec(),
        })
    }

    async fn call(&mut self, id: i32, method: &str, request: &[u8]) -> Response {
        self.send(&call(id, method, request)).await;
        let r = self.response().await.expect("a response");
        assert_eq!(
            r.call_id(),
            id,
            "the response names the call it answers: {r:?}"
        );
        r
    }

    /// Whether the server has closed the connection (end of stream within 10 s).
    async fn closed(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(10), self.s.read(&mut b)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }
}

/// One DataNode connection.
struct Data {
    s: TcpStream,
    wire: Vec<(bool, Vec<u8>)>,
}

impl Data {
    async fn open(port: u16) -> Data {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.set_nodelay(true).unwrap();
        Data { s, wire: vec![] }
    }

    async fn send(&mut self, b: &[u8]) {
        self.s.write_all(b).await.unwrap();
        self.wire.push((true, b.to_vec()));
    }

    async fn read_n(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(30), self.s.read_exact(&mut b))
            .await
            .expect("data within 30 s")
            .expect("the DataNode answers");
        self.wire.push((false, b.clone()));
        b
    }

    async fn delimited<M: Message + Default>(&mut self) -> M {
        let mut raw = Vec::new();
        loop {
            let b = self.read_n(1).await[0];
            raw.push(b);
            if b & 0x80 == 0 {
                break;
            }
        }
        let (len, _) = read_varint(&raw);
        let body = self.read_n(len as usize).await;
        M::decode(body.as_slice()).unwrap()
    }

    /// A packet: (offset in block, seqno, last, checksums, data).
    async fn packet(&mut self) -> (i64, i64, bool, Vec<u8>, Vec<u8>) {
        let p = self.read_n(6).await;
        let plen = u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize;
        let hlen = u16::from_be_bytes([p[4], p[5]]) as usize;
        let h = pb::PacketHeaderProto::decode(self.read_n(hlen).await.as_slice()).unwrap();
        let payload = self.read_n(plen - 4).await;
        let data_len = h.data_len as usize;
        let (sums, data) = payload.split_at(payload.len() - data_len);
        (
            h.offset_in_block,
            h.seqno,
            h.last_packet_in_block,
            sums.to_vec(),
            data.to_vec(),
        )
    }

    async fn closed(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(10), self.s.read(&mut b)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }
}

fn extended(b: &pb::ExtendedBlockProto) -> Vec<u8> {
    [
        bytes(1, b.pool_id.as_bytes()),
        int(2, b.block_id),
        int(3, b.generation_stamp),
        int(4, b.num_bytes.unwrap_or(0)),
    ]
    .concat()
}

/// ClientOperationHeaderProto { baseHeader { block }, clientName }.
fn op_header(b: &pb::ExtendedBlockProto, client: &str) -> Vec<u8> {
    [
        bytes(1, &bytes(1, &extended(b))),
        bytes(2, client.as_bytes()),
    ]
    .concat()
}

fn op(code: u8, message: &[u8]) -> Vec<u8> {
    [vec![0, 28, code], delimited(message)].concat()
}

fn read_block_op(b: &pb::ExtendedBlockProto, offset: u64, len: u64) -> Vec<u8> {
    op(
        81,
        &[
            bytes(1, &op_header(b, "raw-client")),
            int(2, offset),
            int(3, len),
        ]
        .concat(),
    )
}

/// OpWriteBlockProto with stage PIPELINE_SETUP_CREATE and CRC32C in 512-byte chunks.
fn write_block_op(b: &pb::ExtendedBlockProto, client: &str) -> Vec<u8> {
    op(
        80,
        &[
            bytes(1, &op_header(b, client)),
            int(4, 6),
            int(5, 1),
            int(6, 0),
            int(7, 0),
            int(8, b.generation_stamp),
            bytes(9, &[int(1, 2), int(2, 512)].concat()),
        ]
        .concat(),
    )
}

fn packet(offset: i64, seqno: i64, last: bool, data: &[u8], sums: &[u8]) -> Vec<u8> {
    let header = [
        key(1, 1),
        offset.to_le_bytes().to_vec(),
        key(2, 1),
        seqno.to_le_bytes().to_vec(),
        int(3, last as u64),
        key(4, 5),
        (data.len() as i32).to_le_bytes().to_vec(),
    ]
    .concat();
    [
        ((4 + sums.len() + data.len()) as u32)
            .to_be_bytes()
            .to_vec(),
        (header.len() as u16).to_be_bytes().to_vec(),
        header,
        sums.to_vec(),
        data.to_vec(),
    ]
    .concat()
}

fn sums_of(data: &[u8]) -> Vec<u8> {
    data.chunks(512)
        .flat_map(|c| crc32c(c).to_be_bytes())
        .collect()
}

/// Read a whole block's packets after the op response; the bytes and the chunk offset.
async fn read_whole(d: &mut Data) -> Vec<u8> {
    let mut data = Vec::new();
    loop {
        let (offset, _, last, sums, chunk) = d.packet().await;
        assert_eq!(offset as usize, data.len(), "packets are contiguous");
        assert_eq!(sums, sums_of(&chunk), "every chunk's CRC32C, checked here");
        data.extend_from_slice(&chunk);
        if last {
            assert!(chunk.is_empty(), "the last packet is empty");
            d.send(&delimited(&int(1, 6))).await; // CHECKSUM_OK
            return data;
        }
    }
}

fn oracle_rpc(r: &Raw, port: u16) -> PcapOracle {
    let mut o = PcapOracle::tcp("hdfs").port(port);
    for (to_server, b) in &r.wire {
        o = if *to_server {
            o.to_server(b)
        } else {
            o.from_server(b)
        };
    }
    o
}

// ------------------------------------------------------------------ the tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_session_answers_every_call_by_its_id() {
    let server = start(policy(POLICY), None).await;
    let mut r = Raw::hello(server.port, "alice").await;

    // Two calls in one write: each answered, in order, with its own call id.
    r.send(
        &[
            call(41, "getFileInfo", &src("/README.txt")),
            call(42, "getFileInfo", &src("/data")),
        ]
        .concat(),
    )
    .await;
    let a = r.response().await.unwrap();
    let b = r.response().await.unwrap();
    assert_eq!((a.call_id(), b.call_id()), (41, 42));
    let fa = a.decode::<pb::GetFileInfoResponseProto>().fs.unwrap();
    let fb = b.decode::<pb::GetFileInfoResponseProto>().fs.unwrap();
    assert_eq!(
        (fa.file_type, fa.length, fa.owner.as_str()),
        (2, 18, "alice")
    );
    assert_eq!(fb.file_type, 1, "/data is a directory");
    assert_eq!(
        a.header.client_id.as_deref(),
        Some(&CLIENT_ID[..]),
        "the client id is echoed"
    );
    assert_eq!(a.header.server_ipc_version_num, Some(9));

    // A missing path is no status, not an error; a missing file's blocks are Hadoop's
    // FileNotFoundException, and the connection goes on.
    let none = r.call(43, "getFileInfo", &src("/nope")).await;
    assert!(none.decode::<pb::GetFileInfoResponseProto>().fs.is_none());
    let err = r
        .call(
            44,
            "getBlockLocations",
            &[src("/nope"), int(2, 0), int(3, 10)].concat(),
        )
        .await;
    assert_eq!(err.header.status, 1, "ERROR, not FATAL");
    assert_eq!(err.class(), "java.io.FileNotFoundException");
    assert!(err.message().contains("/nope"));
    let unknown = r.call(45, "getSnapshottableDirListing", &[]).await;
    assert_eq!(
        unknown.class(),
        "org.apache.hadoop.ipc.RpcNoSuchMethodException"
    );
    assert_eq!(unknown.header.error_detail, Some(2), "ERROR_NO_SUCH_METHOD");

    // A listing in pages, and the README's one block, read and checked here.
    let page = r
        .call(
            46,
            "getListing",
            &[src("/"), bytes(2, b"data"), int(3, 0)].concat(),
        )
        .await
        .decode::<pb::GetListingResponseProto>()
        .dir_list
        .unwrap();
    let names: Vec<String> = page
        .partial_listing
        .iter()
        .map(|s| String::from_utf8_lossy(&s.path).into_owned())
        .collect();
    assert_eq!(
        names,
        ["secret", "silent", "tmp", "user"],
        "names after `data`"
    );
    let located = r
        .call(
            47,
            "getBlockLocations",
            &[src("/README.txt"), int(2, 0), int(3, 1 << 20)].concat(),
        )
        .await
        .decode::<pb::GetBlockLocationsResponseProto>()
        .locations
        .unwrap();
    assert_eq!(located.file_length, 18);
    let block = &located.blocks[0];
    assert_eq!(block.locs[0].id.xfer_port as u16, server.datanode_port);
    let mut d = Data::open(server.datanode_port).await;
    d.send(&read_block_op(&block.b, 6, 4)).await;
    let resp: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(resp.status, 0, "{resp:?}");
    let info = resp.read_op_checksum_info.unwrap();
    assert_eq!(
        (
            info.checksum.r#type,
            info.checksum.bytes_per_checksum,
            info.chunk_offset
        ),
        (2, 512, 0)
    );
    let bytes_read = read_whole(&mut d).await;
    assert_eq!(
        bytes_read, b"hello from netget\n",
        "the chunk holding 6..10, whole"
    );

    // The pcap oracle. tshark's `hdfs` and `hdfsdata` dissectors were written for Hadoop 1's
    // Writable RPC and op layout, so on Hadoop 3 they read the framing and not the protocol
    // buffers inside (they flag those as malformed, which says nothing about the bytes). What
    // they can read independently is asserted: the hrpc connection header, and the op header.
    let rpc = oracle_rpc(&r, server.port)
        .fields(&[
            "frame.protocols",
            "hdfs.type",
            "hdfs.version",
            "hdfs.auth_type",
        ])
        .unwrap();
    println!("tshark hdfs: {rpc:?}");
    assert!(
        rpc.iter()
            .any(|f| f[0].ends_with(":hdfs") && f[1] == "hrpc" && f[2] == "9" && f[3] == "0"),
        "tshark's hdfs dissector reads hrpc, version 9: {rpc:?}"
    );
    assert!(
        rpc.iter().filter(|f| f[0].ends_with(":hdfs")).count() >= 8,
        "every frame each way reaches the hdfs dissector: {rpc:?}"
    );
    let mut o = PcapOracle::tcp("hdfs_datanode").port(server.datanode_port);
    for (to_server, b) in &d.wire {
        o = if *to_server {
            o.to_server(b)
        } else {
            o.from_server(b)
        };
    }
    let data = o
        .fields(&["frame.protocols", "hdfsdata.version", "hdfsdata.cmd"])
        .unwrap();
    println!("tshark hdfsdata: {data:?}");
    assert!(
        data.iter()
            .any(|f| f[0].ends_with(":hdfsdata") && f[1] == "28" && f[2] == "81"),
        "tshark's hdfsdata dissector reads DataTransferProtocol 28, READ_BLOCK: {data:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_frames_over_the_bound_are_refused_from_their_length() {
    let server = start(policy(POLICY), None).await;
    let bound = netget::server::hdfs::rpc::MAX_REQUEST_FRAME;
    // One byte over: refused FATAL from the length alone, before any of the body is sent.
    let mut r = Raw::hello(server.port, "alice").await;
    let ok = r.call(1, "getFileInfo", &src("/")).await;
    assert!(ok.ok());
    r.send(&((bound + 1) as u32).to_be_bytes()).await;
    let refused = r.response().await.expect("a fatal response");
    assert_eq!(refused.header.status, 2, "FATAL: {refused:?}");
    assert!(
        refused.message().contains("Requested data length"),
        "{refused:?}"
    );
    assert!(r.closed().await, "the connection closes");
    // Exactly the bound is read whole (and refused as the garbage it is, not for its length).
    let mut r = Raw::hello(server.port, "alice").await;
    let mut big = (bound as u32).to_be_bytes().to_vec();
    big.extend(std::iter::repeat_n(0xFFu8, bound));
    r.send(&big).await;
    let garbage = r.response().await.expect("a fatal response");
    assert!(
        !garbage.message().contains("Requested data length"),
        "{garbage:?}"
    );
    // Before the connection context too.
    let mut r = Raw::open(server.port).await;
    r.send(
        &[
            b"hrpc".to_vec(),
            vec![9, 0, 0],
            ((bound + 1) as u32).to_be_bytes().to_vec(),
        ]
        .concat(),
    )
    .await;
    let early = r.response().await.expect("a fatal response");
    assert!(
        early.message().contains("Requested data length"),
        "{early:?}"
    );
    // No model call was spent on an oversized frame: only alice's admission was asked.
    assert_eq!(
        support::events(&server.state, server.id, "hdfs_connect")
            .await
            .len(),
        1
    );
}

/// A request body of ten thousand nested start-groups (field 15, wire type 3): prost skips an
/// unknown group by recursing into it, and stops at 100 levels. The call is refused as a
/// malformed request and the server — the whole process — is still there for the next call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nesting_bomb_is_refused_and_the_server_lives() {
    let server = start(policy(POLICY), None).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let bomb = [
        src("/tmp/a"),
        key(15, 3).repeat(10_000),
        key(15, 4).repeat(10_000),
    ]
    .concat();
    let refused = r.call(1, "create", &bomb).await;
    assert_eq!(refused.class(), "java.io.IOException", "{refused:?}");
    assert!(
        refused.message().contains("not a valid protocol buffer"),
        "{refused:?}"
    );
    let after = r.call(2, "getFileInfo", &src("/README.txt")).await;
    assert!(after.decode::<pb::GetFileInfoResponseProto>().fs.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_header_sasl_and_version() {
    let server = start(policy(POLICY), None).await;
    // Not hrpc: closed without a word.
    let mut r = Raw::open(server.port).await;
    r.send(b"GET / HTTP/1.1\r\n\r\n").await;
    assert!(r.closed().await);
    // A version this server does not speak: FATAL naming it.
    let mut r = Raw::open(server.port).await;
    r.send(&[b"hrpc".to_vec(), vec![7, 0, 0]].concat()).await;
    let v = r.response().await.unwrap();
    assert_eq!(v.class(), "org.apache.hadoop.ipc.RPC$VersionMismatch");
    assert!(v.message().contains("client version 7"));
    // SASL: NEGOTIATE is answered with SIMPLE, and the session goes on.
    let mut r = Raw::open(server.port).await;
    r.send(&[b"hrpc".to_vec(), vec![9, 0, 0xDF]].concat()).await;
    r.send(&frame(&[
        delimited(&rpc_header(-33)),
        delimited(&int(2, 1)),
    ]))
    .await;
    let neg = r.response().await.unwrap();
    assert_eq!(neg.call_id(), -33);
    let sasl: RpcSaslProto = neg.decode();
    assert_eq!(sasl.state, 1, "NEGOTIATE");
    assert_eq!(sasl.auths.len(), 1);
    assert_eq!(sasl.auths[0].method, "SIMPLE");
    r.send(&connection_context("alice")).await;
    let info = r.call(3, "getFileInfo", &src("/README.txt")).await;
    assert!(info.decode::<pb::GetFileInfoResponseProto>().fs.is_some());
    // Kerberos (INITIATE with GSSAPI): refused, not built.
    let mut r = Raw::open(server.port).await;
    r.send(&[b"hrpc".to_vec(), vec![9, 0, 0xDF]].concat()).await;
    let auth = [bytes(1, b"KERBEROS"), bytes(2, b"GSSAPI")].concat();
    r.send(&frame(&[
        delimited(&rpc_header(-33)),
        delimited(&[int(2, 2), bytes(4, &auth)].concat()),
    ]))
    .await;
    let k = r.response().await.unwrap();
    assert_eq!(k.header.status, 2);
    assert!(k.message().contains("SIMPLE only"), "{k:?}");
}

/// The model answers only `hdfs_connect`: every description fails closed.
const CONNECT_ONLY: &str = r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'hdfs_allow'}] if i['event_type_id']=='hdfs_connect' else []
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn model_failure_exposes_nothing() {
    // No handler and an unreachable backend: the connection itself is refused.
    let server = start(None, Some(json!({"decision_timeout_secs": 5}))).await;
    let mut r = Raw::hello(server.port, "alice").await;
    r.send(&call(
        1,
        "getListing",
        &[src("/"), bytes(2, b""), int(3, 0)].concat(),
    ))
    .await;
    let refused = r.response().await.expect("a fatal response");
    assert_eq!(refused.header.status, 2, "{refused:?}");
    assert_eq!(refused.class(), "java.io.IOException");
    assert!(
        !refused.message().contains("127.0.0.1:1"),
        "the backend's address does not leak: {refused:?}"
    );
    assert!(r.closed().await);
    assert!(server
        .wait_line("decision=fail_closed_llm_error", 10)
        .await
        .is_some());

    // The user is let in but no description arrives: the root lists nothing and errs.
    let server = start(policy(CONNECT_ONLY), None).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let listing = r
        .call(
            1,
            "getListing",
            &[src("/"), bytes(2, b""), int(3, 0)].concat(),
        )
        .await;
    assert_eq!(listing.header.status, 1, "{listing:?}");
    assert_eq!(listing.class(), "java.io.IOException");
    assert!(listing.body.is_empty(), "no entries travel with an error");
    let info = r.call(2, "getFileInfo", &src("/README.txt")).await;
    assert_eq!(info.class(), "java.io.IOException", "{info:?}");
    assert!(server
        .lines("decision=model_silent")
        .iter()
        .any(|l| l.contains("operation=describe")));
}

/// Creates under /tmp are allowed and content is refused unless it says "ok".
const WRITES: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='hdfs_connect' or t=='hdfs_create':
  a=[{'type':'hdfs_allow'}]
elif t=='hdfs_describe_directory':
  a=[{'type':'hdfs_directory','entries':[{'name':'tmp','kind':'dir','entries':[]}] if e['path']=='/' else []}]
elif t=='hdfs_write':
  a=[{'type':'hdfs_allow'}] if e['data'].startswith('ok') else [{'type':'hdfs_deny','exception':'AccessControlException','message':'content refused'}]
else:
  a=[{'type':'hdfs_deny'}]
print(json.dumps({'actions':a}))"#;

fn create_req(path: &str, client: &str) -> Vec<u8> {
    [
        src(path),
        bytes(2, &int(1, 0o644)),
        bytes(3, client.as_bytes()),
        int(4, 1),
        int(5, 0),
        int(6, 1),
        int(7, 65536),
    ]
    .concat()
}

/// Write one block of `data` with checksums `sums`: the acks' statuses.
async fn write_block(
    server: &Started,
    block: &pb::LocatedBlockProto,
    client: &str,
    data: &[u8],
    sums: &[u8],
) -> (Vec<i32>, Data) {
    let mut d = Data::open(server.datanode_port).await;
    d.send(&write_block_op(&block.b, client)).await;
    let resp: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(resp.status, 0, "{resp:?}");
    d.send(&packet(0, 0, false, data, sums)).await;
    let ack: pb::PipelineAckProto = d.delimited().await;
    assert_eq!(ack.seqno, 0);
    let mut statuses = ack.reply.clone();
    if statuses == [0] {
        d.send(&packet(data.len() as i64, 1, true, &[], &[])).await;
        let last: pb::PipelineAckProto = d.delimited().await;
        assert_eq!(last.seqno, 1);
        statuses.extend(last.reply);
    }
    (statuses, d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_are_checksummed_and_decided() {
    let server = start(policy(WRITES), None).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let client = "raw-writer";
    let used = |r: &Response| r.decode::<pb::GetFsStatsResponseProto>().used;

    // A packet whose checksums are wrong is refused with ERROR_CHECKSUM, and the block is not
    // kept: complete cannot go ahead.
    let created = r.call(1, "create", &create_req("/tmp/a.txt", client)).await;
    let file_id = created
        .decode::<pb::CreateResponseProto>()
        .fs
        .unwrap()
        .file_id
        .unwrap();
    let added = r
        .call(
            2,
            "addBlock",
            &[
                src("/tmp/a.txt"),
                bytes(2, client.as_bytes()),
                int(5, file_id),
            ]
            .concat(),
        )
        .await
        .decode::<pb::AddBlockResponseProto>()
        .block;
    let data = b"ok: these bytes are checked chunk by chunk".repeat(30);
    let mut bad = sums_of(&data);
    bad[5] ^= 0x40;
    let (statuses, mut d) = write_block(&server, &added, client, &data, &bad).await;
    assert_eq!(statuses, [2], "ERROR_CHECKSUM");
    assert!(d.closed().await);
    let mut last = added.b.clone();
    last.num_bytes = Some(data.len() as u64);
    let incomplete = r
        .call(
            3,
            "complete",
            &[
                src("/tmp/a.txt"),
                bytes(2, client.as_bytes()),
                bytes(3, &extended(&last)),
                int(4, file_id),
            ]
            .concat(),
        )
        .await;
    assert_eq!(incomplete.class(), "java.io.IOException", "{incomplete:?}");
    assert!(
        incomplete.message().contains("has not been written"),
        "{incomplete:?}"
    );

    // The same block with the right checksums: acked, completed, read back.
    let (statuses, _) = write_block(&server, &added, client, &data, &sums_of(&data)).await;
    assert_eq!(statuses, [0, 0]);
    let done = r
        .call(
            4,
            "complete",
            &[
                src("/tmp/a.txt"),
                bytes(2, client.as_bytes()),
                bytes(3, &extended(&last)),
                int(4, file_id),
            ]
            .concat(),
        )
        .await;
    assert!(done.decode::<pb::CompleteResponseProto>().result);
    let located = r
        .call(
            5,
            "getBlockLocations",
            &[src("/tmp/a.txt"), int(2, 0), int(3, 1 << 20)].concat(),
        )
        .await
        .decode::<pb::GetBlockLocationsResponseProto>()
        .locations
        .unwrap();
    let mut rd = Data::open(server.datanode_port).await;
    rd.send(&read_block_op(&located.blocks[0].b, 0, data.len() as u64))
        .await;
    let resp: pb::BlockOpResponseProto = rd.delimited().await;
    assert_eq!(resp.status, 0);
    assert_eq!(read_whole(&mut rd).await, data);

    // Content the model refuses: complete fails with its exception, and the overlay holds
    // exactly what it held before.
    let before = used(&r.call(6, "getFsStats", &[]).await);
    r.call(7, "create", &create_req("/tmp/b.txt", client)).await;
    let b_block = r
        .call(
            8,
            "addBlock",
            &[src("/tmp/b.txt"), bytes(2, client.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AddBlockResponseProto>()
        .block;
    let refused = b"not this".repeat(100);
    let (statuses, _) = write_block(&server, &b_block, client, &refused, &sums_of(&refused)).await;
    assert_eq!(statuses, [0, 0]);
    let mut b_last = b_block.b.clone();
    b_last.num_bytes = Some(refused.len() as u64);
    let denied = r
        .call(
            9,
            "complete",
            &[
                src("/tmp/b.txt"),
                bytes(2, client.as_bytes()),
                bytes(3, &extended(&b_last)),
            ]
            .concat(),
        )
        .await;
    assert_eq!(
        denied.class(),
        "org.apache.hadoop.security.AccessControlException"
    );
    assert_eq!(denied.message(), "content refused");
    let after = used(&r.call(10, "getFsStats", &[]).await);
    assert_eq!(after, before, "the refused bytes are gone, held nowhere");
    let b = r
        .call(11, "getFileInfo", &src("/tmp/b.txt"))
        .await
        .decode::<pb::GetFileInfoResponseProto>();
    assert_eq!(
        b.fs.unwrap().length,
        0,
        "the file keeps its earlier (empty) content"
    );

    // A DataNode packet over the bound is refused from its PLEN, and the connection closes.
    r.call(12, "create", &create_req("/tmp/c.txt", client))
        .await;
    let c_block = r
        .call(
            13,
            "addBlock",
            &[src("/tmp/c.txt"), bytes(2, client.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AddBlockResponseProto>()
        .block;
    let mut d = Data::open(server.datanode_port).await;
    d.send(&write_block_op(&c_block.b, client)).await;
    let _: pb::BlockOpResponseProto = d.delimited().await;
    d.send(&[0x7F, 0xFF, 0xFF, 0xFF, 0, 10]).await;
    assert!(d.closed().await);
    assert!(
        server
            .lines("is over the bound")
            .iter()
            .any(|l| l.contains("WRITE_BLOCK")),
        "{}",
        server.dump_logs()
    );
    // An unknown op and a wrong version are refused.
    let mut d = Data::open(server.datanode_port).await;
    d.send(&op(87, &[])).await;
    let r87: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(r87.status, 7, "ERROR_UNSUPPORTED");
    let mut d = Data::open(server.datanode_port).await;
    d.send(&[0, 27, 81, 0]).await;
    let old: pb::BlockOpResponseProto = d.delimited().await;
    assert!(old.message.unwrap().contains("Version Mismatch"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_and_read_only_changes_leave_the_namespace_alone() {
    let server = start(policy(POLICY), None).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let mkdirs = |p: &str| [src(p), bytes(2, &int(1, 0o755)), int(3, 1)].concat();
    let denied = r.call(1, "mkdirs", &mkdirs("/data/x/y")).await;
    assert_eq!(
        denied.class(),
        "org.apache.hadoop.security.AccessControlException"
    );
    let none = r.call(2, "getFileInfo", &src("/data/x")).await;
    assert!(none.decode::<pb::GetFileInfoResponseProto>().fs.is_none());
    let rename = r
        .call(
            3,
            "rename2",
            &[src("/README.txt"), bytes(2, b"/data/r.txt"), int(3, 0)].concat(),
        )
        .await;
    assert_eq!(
        rename.class(),
        "org.apache.hadoop.security.AccessControlException"
    );
    let still = r.call(4, "getFileInfo", &src("/README.txt")).await;
    assert!(still.decode::<pb::GetFileInfoResponseProto>().fs.is_some());
    // Refused by Rust before the model is asked: no event.
    let exists = r.call(5, "mkdirs", &mkdirs("/README.txt")).await;
    assert_eq!(
        exists.class(),
        "org.apache.hadoop.fs.FileAlreadyExistsException"
    );
    let events = support::events(&server.state, server.id, "hdfs_mkdirs").await;
    assert_eq!(events.len(), 1, "only the first mkdirs asked: {events:?}");
    assert_eq!(events[0]["creates"], json!(["/data/x", "/data/x/y"]));

    let server = start(policy(POLICY), Some(json!({"read_only": true}))).await;
    let mut r = Raw::hello(server.port, "alice").await;
    let ro = r.call(1, "mkdirs", &mkdirs("/user/alice/new")).await;
    assert_eq!(
        ro.class(),
        "org.apache.hadoop.hdfs.server.namenode.SafeModeException"
    );
    assert!(
        support::events(&server.state, server.id, "hdfs_mkdirs")
            .await
            .is_empty(),
        "the model was not asked"
    );
}
