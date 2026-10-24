//! append, truncate and concat at the wire, written by hand with the raw client from
//! `wire_test.rs`: the append pipeline (PIPELINE_SETUP_APPEND, the generation stamp
//! updateBlockForPipeline offers and updatePipeline adopts, the partial last chunk continued in
//! a packet of its own whose CRC32C covers only its new bytes, the block's chunks read back
//! with their CRC32Cs computed here over old and new bytes together), a truncate inside a block
//! going through recovery as Hadoop's NameNode reports it, concat's preconditions refused in Rust
//! before the model is asked, and each new mutation failing closed when the model gives no
//! answer.
use super::support::{self, crc32c, policy, start, Started};
use super::wire_test::{
    bytes, create_req, extended, int, op, op_header, packet, read_block_op, read_whole, src,
    sums_of, write_block, Data, Raw, Response,
};
use netget::server::hdfs::proto::hdfs as pb;
use serde_json::json;
use std::time::Duration;

/// Everything under /tmp is allowed, except content holding "forbidden"; the root holds /tmp
/// and /other (a second directory, for concat's same-directory rule).
const ALLOW_TMP: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='hdfs_connect':
  a=[{'type':'hdfs_allow'}]
elif t=='hdfs_describe_directory':
  a=[{'type':'hdfs_directory','entries':[{'name':'tmp','kind':'dir','mode':1023,'entries':[]},{'name':'other','kind':'dir','mode':1023,'entries':[]}] if e['path']=='/' else []}]
elif t=='hdfs_write' and 'forbidden' in e.get('data',''):
  a=[{'type':'hdfs_deny','exception':'DSQuotaExceededException','message':'the model refuses this content'}]
elif e.get('path','').startswith(('/tmp/','/other/')):
  a=[{'type':'hdfs_allow'}]
else:
  a=[{'type':'hdfs_deny'}]
print(json.dumps({'actions':a}))"#;

/// Creates, writes and mkdirs are allowed; append, truncate and concat get no answer at all.
const SILENT_ON_NEW: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t in ('hdfs_connect','hdfs_create','hdfs_write','hdfs_mkdirs'):
  a=[{'type':'hdfs_allow'}]
elif t=='hdfs_describe_directory':
  a=[{'type':'hdfs_directory','entries':[{'name':'tmp','kind':'dir','mode':1023,'entries':[]}] if e['path']=='/' else []}]
else:
  a=[]
print(json.dumps({'actions':a}))"#;

const CLIENT: &str = "raw-mutator";

/// A raw NameNode session with its own call ids.
struct Session {
    r: Raw,
    next: i32,
}

impl Session {
    async fn open(server: &Started) -> Session {
        Session {
            r: Raw::hello(server.port, "alice").await,
            next: 100,
        }
    }

    async fn call(&mut self, method: &str, request: &[u8]) -> Response {
        self.next += 1;
        self.r.call(self.next, method, request).await
    }

    async fn status(&mut self, path: &str) -> Option<pb::HdfsFileStatusProto> {
        self.call("getFileInfo", &src(path))
            .await
            .decode::<pb::GetFileInfoResponseProto>()
            .fs
    }

    async fn closed(&mut self, path: &str) -> bool {
        self.call("isFileClosed", &src(path))
            .await
            .decode::<pb::IsFileClosedResponseProto>()
            .result
    }

    async fn located(&mut self, path: &str) -> pb::LocatedBlocksProto {
        self.call(
            "getBlockLocations",
            &[src(path), int(2, 0), int(3, 1 << 30)].concat(),
        )
        .await
        .decode::<pb::GetBlockLocationsResponseProto>()
        .locations
        .expect("located")
    }

    async fn complete(&mut self, path: &str, last: Option<&pb::ExtendedBlockProto>) -> Response {
        let mut req = [src(path), bytes(2, CLIENT.as_bytes())].concat();
        if let Some(b) = last {
            req.extend(bytes(3, &extended(b)));
        }
        self.call("complete", &req).await
    }

    /// Create `path` with `block_size` and write `data` block by block through the DataNode.
    async fn put(&mut self, server: &Started, path: &str, data: &[u8], block_size: u64) {
        let mut req = create_req(path, CLIENT);
        // create_req asks for 64 KiB blocks (field 7); a later field 7 wins in protobuf.
        req.extend(int(7, block_size));
        let created = self.call("create", &req).await;
        assert!(created.ok(), "create {path}: {created:?}");
        let mut previous: Option<pb::ExtendedBlockProto> = None;
        for chunk in data.chunks(block_size as usize) {
            let mut add = [src(path), bytes(2, CLIENT.as_bytes())].concat();
            if let Some(p) = &previous {
                add.extend(bytes(3, &extended(p)));
            }
            let block = self
                .call("addBlock", &add)
                .await
                .decode::<pb::AddBlockResponseProto>()
                .block;
            let (statuses, _) = write_block(server, &block, CLIENT, chunk, &sums_of(chunk)).await;
            assert_eq!(statuses, [0, 0], "block of {path}");
            let mut b = block.b.clone();
            b.num_bytes = Some(chunk.len() as u64);
            previous = Some(b);
        }
        let done = self.complete(path, previous.as_ref()).await;
        assert!(
            done.decode::<pb::CompleteResponseProto>().result,
            "complete {path}"
        );
    }

    /// Every byte of a file, block by block, each chunk's CRC32C checked here.
    async fn read_all(&mut self, server: &Started, path: &str) -> Vec<u8> {
        let located = self.located(path).await;
        let mut out = Vec::new();
        for b in &located.blocks {
            let mut d = Data::open(server.datanode_port).await;
            d.send(&read_block_op(&b.b, 0, b.b.num_bytes.unwrap_or(0)))
                .await;
            let resp: pb::BlockOpResponseProto = d.delimited().await;
            assert_eq!(resp.status, 0, "READ_BLOCK {path}: {resp:?}");
            out.extend(read_whole(&mut d).await);
        }
        out
    }
}

/// OpWriteBlockProto for PIPELINE_SETUP_APPEND (stage 0): the block holds `held` bytes and the
/// pipeline runs under `latest`.
fn append_op(b: &pb::ExtendedBlockProto, held: u64, latest: u64) -> Vec<u8> {
    op(
        80,
        &[
            bytes(1, &op_header(b, CLIENT)),
            int(4, 0),
            int(5, 1),
            int(6, held),
            int(7, held),
            int(8, latest),
            bytes(9, &[int(1, 2), int(2, 512)].concat()),
        ]
        .concat(),
    )
}

/// An append pipeline's op and its answer.
async fn open_append(
    server: &Started,
    b: &pb::ExtendedBlockProto,
    held: u64,
    latest: u64,
) -> (Data, pb::BlockOpResponseProto) {
    let mut d = Data::open(server.datanode_port).await;
    d.send(&append_op(b, held, latest)).await;
    let resp: pb::BlockOpResponseProto = d.delimited().await;
    (d, resp)
}

async fn ack(d: &mut Data) -> pb::PipelineAckProto {
    d.delimited().await
}

fn bytes_of(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| b'a' + ((i + seed as usize) % 26) as u8)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_continues_the_partial_last_chunk() {
    let server = start(policy(ALLOW_TMP), None).await;
    let mut s = Session::open(&server).await;
    // 1000 bytes: one block, its last chunk holds 488 of 512 bytes.
    let old = bytes_of(1000, 0);
    s.put(&server, "/tmp/ap.txt", &old, 65536).await;
    let before = s.status("/tmp/ap.txt").await.unwrap();

    // append: the partial last block, located with the bytes it holds, and the file's status.
    let opened = s
        .call(
            "append",
            &[src("/tmp/ap.txt"), bytes(2, CLIENT.as_bytes()), int(3, 4)].concat(),
        )
        .await
        .decode::<pb::AppendResponseProto>();
    let last = opened.block.expect("the partial last block");
    assert_eq!(last.offset, 0);
    assert_eq!(last.b.num_bytes, Some(1000));
    assert_eq!(opened.stat.unwrap().length, 1000);
    let gs = last.b.generation_stamp;
    assert!(!s.closed("/tmp/ap.txt").await, "open for append");
    // The committed bytes stay readable while the file is open for append.
    assert_eq!(s.read_all(&server, "/tmp/ap.txt").await, old);

    // The DataNode refuses an append that names the wrong length, a stamp nobody offered, or
    // the create stage for a block that holds bytes.
    let (_, wrong_len) = open_append(&server, &last.b, 999, gs).await;
    assert_eq!(wrong_len.status, 3, "ERROR_INVALID: {wrong_len:?}");
    assert!(
        wrong_len.message().contains("holds 1000 bytes"),
        "{wrong_len:?}"
    );
    let (_, unoffered) = open_append(&server, &last.b, 1000, gs + 4242).await;
    assert_eq!(unoffered.status, 3, "{unoffered:?}");
    assert!(
        unoffered.message().contains("was not offered"),
        "{unoffered:?}"
    );
    let mut d = Data::open(server.datanode_port).await;
    d.send(&super::wire_test::write_block_op(&last.b, CLIENT))
        .await;
    let create_stage: pb::BlockOpResponseProto = d.delimited().await;
    assert_eq!(create_stage.status, 3, "{create_stage:?}");
    assert!(create_stage.message().contains("PIPELINE_SETUP_APPEND"));

    // A new generation stamp, adopted by updatePipeline once the DataNode has the pipeline.
    let fresh = s
        .call(
            "updateBlockForPipeline",
            &[bytes(1, &extended(&last.b)), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await
        .decode::<pb::UpdateBlockForPipelineResponseProto>()
        .block;
    let gs2 = fresh.b.generation_stamp;
    assert!(gs2 > gs, "a newer stamp: {gs} -> {gs2}");
    let (mut d, resp) = open_append(&server, &last.b, 1000, gs2).await;
    assert_eq!(resp.status, 0, "{resp:?}");
    let mut renewed = last.b.clone();
    renewed.generation_stamp = gs2;
    let updated = s
        .call(
            "updatePipeline",
            &[
                bytes(1, CLIENT.as_bytes()),
                bytes(2, &extended(&last.b)),
                bytes(3, &extended(&renewed)),
            ]
            .concat(),
        )
        .await;
    assert!(updated.ok(), "{updated:?}");

    // The first packet continues the partial chunk alone (24 bytes); its CRC32C covers only
    // those bytes. A CRC32C over the whole chunk (the 488 old bytes and the 24 new) is what the
    // DataNode serves afterwards, not what the client sends: it is refused.
    let new = bytes_of(2024, 7);
    let (head, tail) = new.split_at(24);
    let whole_chunk = crc32c(&[&old[512..], head].concat()).to_be_bytes();
    d.send(&packet(1000, 0, false, head, &whole_chunk)).await;
    let refused = ack(&mut d).await;
    assert_eq!(refused.reply, [2], "ERROR_CHECKSUM: {refused:?}");
    assert!(d.closed().await);

    // A packet that starts inside the chunk and runs past its end is refused too.
    let (mut d, resp) = open_append(&server, &renewed, 1000, gs2).await;
    assert_eq!(resp.status, 0, "{resp:?}");
    let across = &new[..100];
    d.send(&packet(1000, 0, false, across, &sums_of(across)))
        .await;
    assert_eq!(ack(&mut d).await.reply, [3], "ERROR_INVALID");

    // Right: the partial chunk's rest alone, then whole chunks from 1024, then the last packet.
    let (mut d, resp) = open_append(&server, &renewed, 1000, gs2).await;
    assert_eq!(resp.status, 0, "{resp:?}");
    d.send(&packet(1000, 0, false, head, &crc32c(head).to_be_bytes()))
        .await;
    assert_eq!(ack(&mut d).await.reply, [0]);
    d.send(&packet(1024, 1, false, tail, &sums_of(tail))).await;
    assert_eq!(ack(&mut d).await.reply, [0]);
    d.send(&packet(3024, 2, true, &[], &[])).await;
    assert_eq!(ack(&mut d).await.reply, [0]);
    let mut done = renewed.clone();
    done.num_bytes = Some(3024);
    let completed = s.complete("/tmp/ap.txt", Some(&done)).await;
    assert!(
        completed.decode::<pb::CompleteResponseProto>().result,
        "{completed:?}"
    );

    // Read back: the block under the new stamp, every chunk's CRC32C computed here over the
    // old and new bytes it now holds.
    let located = s.located("/tmp/ap.txt").await;
    assert_eq!(located.file_length, 3024);
    assert_eq!(located.blocks[0].b.generation_stamp, gs2);
    let all = s.read_all(&server, "/tmp/ap.txt").await;
    assert_eq!(all, [old.as_slice(), new.as_slice()].concat());
    let after = s.status("/tmp/ap.txt").await.unwrap();
    assert_eq!(after.length, 3024);
    assert!(after.file_id == before.file_id);

    // What the model was shown: may it be appended to, then what was appended.
    let appends = support::events(&server.state, server.id, "hdfs_append").await;
    assert_eq!(appends.len(), 1, "{appends:?}");
    assert_eq!(appends[0]["length"], 1000);
    assert_eq!(appends[0]["last_block_partial"], true);
    assert_eq!(appends[0]["new_block"], false);
    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    let appended = writes.last().unwrap();
    assert_eq!(appended["append"], true);
    assert_eq!(appended["offset"], 1000);
    assert_eq!(appended["length"], 2024);

    // An append that starts a fresh block after a partial one would leave a variable-length
    // block: refused before the model is asked.
    let new_block = s
        .call(
            "append",
            &[
                src("/tmp/ap.txt"),
                bytes(2, CLIENT.as_bytes()),
                int(3, 4 | 0x20),
            ]
            .concat(),
        )
        .await;
    assert_eq!(new_block.class(), "java.lang.UnsupportedOperationException");
    assert!(
        new_block.message().contains("partial block"),
        "{new_block:?}"
    );
    // Content the model refuses: complete fails and the file keeps what it had.
    let opened = s
        .call(
            "append",
            &[src("/tmp/ap.txt"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AppendResponseProto>();
    let last = opened.block.unwrap();
    let bad = b"forbidden".to_vec();
    let (mut d, resp) = open_append(&server, &last.b, 3024, last.b.generation_stamp).await;
    assert_eq!(resp.status, 0);
    // 3024 is 464 into a chunk: 9 bytes fit in it.
    d.send(&packet(3024, 0, false, &bad, &crc32c(&bad).to_be_bytes()))
        .await;
    assert_eq!(ack(&mut d).await.reply, [0]);
    d.send(&packet(3033, 1, true, &[], &[])).await;
    assert_eq!(ack(&mut d).await.reply, [0]);
    let mut b = last.b.clone();
    b.num_bytes = Some(3033);
    let denied = s.complete("/tmp/ap.txt", Some(&b)).await;
    assert_eq!(
        denied.class(),
        "org.apache.hadoop.hdfs.protocol.DSQuotaExceededException"
    );
    assert_eq!(s.status("/tmp/ap.txt").await.unwrap().length, 3024);
    assert!(
        s.closed("/tmp/ap.txt").await,
        "the refused append closed the file"
    );
    assert_eq!(
        s.read_all(&server, "/tmp/ap.txt").await,
        [old.as_slice(), new.as_slice()].concat()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_on_a_block_boundary_and_its_refusals() {
    let server = start(policy(ALLOW_TMP), None).await;
    let mut s = Session::open(&server).await;
    let full = bytes_of(65536, 3);
    s.put(&server, "/tmp/full.bin", &full, 65536).await;
    // The last block is full: no block comes back, and the next addBlock starts block 1.
    let opened = s
        .call(
            "append",
            &[src("/tmp/full.bin"), bytes(2, CLIENT.as_bytes()), int(3, 4)].concat(),
        )
        .await
        .decode::<pb::AppendResponseProto>();
    assert!(opened.block.is_none(), "{opened:?}");
    let block = s
        .call(
            "addBlock",
            &[src("/tmp/full.bin"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AddBlockResponseProto>()
        .block;
    assert_eq!(block.offset, 65536);
    let more = bytes_of(700, 9);
    let (statuses, _) = write_block(&server, &block, CLIENT, &more, &sums_of(&more)).await;
    assert_eq!(statuses, [0, 0]);
    let mut b = block.b.clone();
    b.num_bytes = Some(700);
    assert!(
        s.complete("/tmp/full.bin", Some(&b))
            .await
            .decode::<pb::CompleteResponseProto>()
            .result
    );
    assert_eq!(
        s.read_all(&server, "/tmp/full.bin").await,
        [full.as_slice(), more.as_slice()].concat()
    );

    // Refused in Rust, the model not asked: no such file, a directory, a file open elsewhere.
    let asked = support::events(&server.state, server.id, "hdfs_append")
        .await
        .len();
    let missing = s
        .call(
            "append",
            &[src("/tmp/none"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(missing.class(), "java.io.FileNotFoundException");
    let dir = s
        .call(
            "append",
            &[src("/tmp"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(
        dir.class(),
        "org.apache.hadoop.fs.FileAlreadyExistsException"
    );
    s.call(
        "append",
        &[src("/tmp/full.bin"), bytes(2, b"first-writer")].concat(),
    )
    .await
    .decode::<pb::AppendResponseProto>();
    let busy = s
        .call(
            "append",
            &[src("/tmp/full.bin"), bytes(2, b"second-writer")].concat(),
        )
        .await;
    assert_eq!(
        busy.class(),
        "org.apache.hadoop.hdfs.protocol.AlreadyBeingCreatedException"
    );
    assert!(
        busy.message().contains("currently owned by first-writer"),
        "{busy:?}"
    );
    assert_eq!(
        support::events(&server.state, server.id, "hdfs_append")
            .await
            .len(),
        asked + 1,
        "only the first writer's append asked the model"
    );
    // The model refuses an append outside /tmp.
    let s2 = start(policy(super::support::POLICY), None).await;
    let mut t = Session::open(&s2).await;
    let refused = t
        .call(
            "append",
            &[src("/README.txt"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(
        refused.class(),
        "org.apache.hadoop.security.AccessControlException"
    );
    assert!(
        t.closed("/README.txt").await,
        "a refused append opens nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncate_inside_a_block_goes_through_recovery() {
    let server = start(policy(ALLOW_TMP), None).await;
    let mut s = Session::open(&server).await;
    let data = bytes_of(69536, 1);
    s.put(&server, "/tmp/tr.bin", &data, 65536).await;
    let truncate = |len: u64, client: &str| {
        [src("/tmp/tr.bin"), int(2, len), bytes(3, client.as_bytes())].concat()
    };

    // Longer, and the same length: Rust answers, the model is not asked.
    let longer = s.call("truncate", &truncate(100_000, CLIENT)).await;
    assert_eq!(
        longer.class(),
        "org.apache.hadoop.HadoopIllegalArgumentException"
    );
    assert!(longer
        .message()
        .contains("Cannot truncate to a larger file size"));
    let same = s.call("truncate", &truncate(69536, CLIENT)).await;
    assert!(same.decode::<pb::TruncateResponseProto>().result);
    assert!(support::events(&server.state, server.id, "hdfs_truncate")
        .await
        .is_empty());

    // Inside block 1: false, and the file is under recovery — open, its old length reported,
    // its blocks readable up to the new length.
    let cut = s.call("truncate", &truncate(66000, CLIENT)).await;
    assert!(!cut.decode::<pb::TruncateResponseProto>().result, "{cut:?}");
    assert!(!s.closed("/tmp/tr.bin").await, "under recovery");
    assert_eq!(s.status("/tmp/tr.bin").await.unwrap().length, 69536);
    let located = s.located("/tmp/tr.bin").await;
    assert_eq!(located.file_length, 66000);
    assert!(located.under_construction && located.is_last_block_complete);
    // Asked again with the same length: false again, the model not asked twice; another
    // length, or an append, is refused while recovery runs.
    let again = s.call("truncate", &truncate(66000, CLIENT)).await;
    assert!(!again.decode::<pb::TruncateResponseProto>().result);
    let other = s.call("truncate", &truncate(65536, CLIENT)).await;
    assert_eq!(
        other.class(),
        "org.apache.hadoop.hdfs.protocol.AlreadyBeingCreatedException"
    );
    assert!(other.message().contains("is being truncated"), "{other:?}");
    let append = s
        .call(
            "append",
            &[src("/tmp/tr.bin"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(
        append.class(),
        "org.apache.hadoop.hdfs.protocol.RecoveryInProgressException"
    );
    let events = support::events(&server.state, server.id, "hdfs_truncate").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["length"], 66000);
    assert_eq!(events[0]["length_before"], 69536);
    assert_eq!(events[0]["on_block_boundary"], false);

    // Recovery finishes: closed, cut, block 1 holding 464 bytes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !s.closed("/tmp/tr.bin").await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "recovery never finished"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(s.status("/tmp/tr.bin").await.unwrap().length, 66000);
    assert_eq!(s.read_all(&server, "/tmp/tr.bin").await, &data[..66000]);
    assert!(server
        .lines("block recovery finished")
        .iter()
        .any(|l| l.contains("/tmp/tr.bin")));

    // On a block boundary: true, at once.
    let boundary = s.call("truncate", &truncate(65536, CLIENT)).await;
    assert!(boundary.decode::<pb::TruncateResponseProto>().result);
    assert!(s.closed("/tmp/tr.bin").await);
    assert_eq!(s.status("/tmp/tr.bin").await.unwrap().length, 65536);
    assert_eq!(s.read_all(&server, "/tmp/tr.bin").await, &data[..65536]);
    // A directory is not a file.
    let dir = s
        .call(
            "truncate",
            &[src("/tmp"), int(2, 0), bytes(3, b"x")].concat(),
        )
        .await;
    assert_eq!(dir.class(), "java.io.FileNotFoundException");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concat_preconditions_are_refused_before_the_model() {
    let server = start(policy(ALLOW_TMP), None).await;
    let mut s = Session::open(&server).await;
    let t = bytes_of(65536, 0);
    let s1 = bytes_of(131072, 5);
    let s2 = bytes_of(100, 11);
    s.put(&server, "/tmp/t", &t, 65536).await;
    s.put(&server, "/tmp/s1", &s1, 65536).await;
    s.put(&server, "/tmp/s2", &s2, 65536).await;
    s.put(&server, "/tmp/pt", &s2, 65536).await;
    s.put(&server, "/tmp/big", &t, 131072).await;
    s.put(&server, "/other/x", &t, 65536).await;
    let created = s.call("create", &create_req("/tmp/empty", CLIENT)).await;
    assert!(created.ok());
    assert!(
        s.complete("/tmp/empty", None)
            .await
            .decode::<pb::CompleteResponseProto>()
            .result
    );
    let concat = |target: &str, srcs: &[&str]| {
        let mut req = src(target);
        for p in srcs {
            req.extend(bytes(2, p.as_bytes()));
        }
        req
    };
    let cases: &[(&str, &[&str], &str, &str)] = &[
        (
            "/tmp/t",
            &[],
            "java.lang.IllegalArgumentException",
            "No sources given",
        ),
        (
            "/tmp/t",
            &["/other/x"],
            "org.apache.hadoop.HadoopIllegalArgumentException",
            "is not in the same directory",
        ),
        (
            "/tmp/t",
            &["/tmp/t"],
            "org.apache.hadoop.HadoopIllegalArgumentException",
            "is the same with the target",
        ),
        (
            "/tmp/t",
            &["/tmp/s1", "/tmp/s1"],
            "org.apache.hadoop.HadoopIllegalArgumentException",
            "at least two of the source files are the same",
        ),
        (
            "/tmp/t",
            &["/tmp/empty"],
            "org.apache.hadoop.HadoopIllegalArgumentException",
            "invalid or empty or underConstruction",
        ),
        (
            "/tmp/t",
            &["/tmp/big"],
            "org.apache.hadoop.HadoopIllegalArgumentException",
            "greater than the target file's preferred block size",
        ),
        (
            "/tmp/big",
            &["/tmp/s1"],
            "java.lang.UnsupportedOperationException",
            "this NameNode joins only files of the target's block size",
        ),
        (
            "/tmp/pt",
            &["/tmp/s1"],
            "java.lang.UnsupportedOperationException",
            "/tmp/pt holds 100 bytes, not a whole number",
        ),
        (
            "/tmp/t",
            &["/tmp/s2", "/tmp/s1"],
            "java.lang.UnsupportedOperationException",
            "/tmp/s2 holds 100 bytes, not a whole number",
        ),
        (
            "/tmp/none",
            &["/tmp/s1"],
            "java.io.FileNotFoundException",
            "/tmp/none",
        ),
    ];
    for (target, srcs, class, message) in cases {
        let r = s.call("concat", &concat(target, srcs)).await;
        assert_eq!(r.class(), *class, "{target} <- {srcs:?}: {r:?}");
        assert!(r.message().contains(message), "{target} <- {srcs:?}: {r:?}");
    }
    // A source open for writing.
    let reopened = s
        .call(
            "append",
            &[src("/tmp/s2"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await
        .decode::<pb::AppendResponseProto>()
        .block
        .expect("s2's partial block");
    let open = s
        .call("concat", &concat("/tmp/t", &["/tmp/s1", "/tmp/s2"]))
        .await;
    assert!(
        open.message()
            .contains("invalid or empty or underConstruction"),
        "{open:?}"
    );
    let closed = s.complete("/tmp/s2", Some(&reopened.b)).await;
    assert!(
        closed.decode::<pb::CompleteResponseProto>().result,
        "an append of nothing closes"
    );
    assert!(
        support::events(&server.state, server.id, "hdfs_concat")
            .await
            .is_empty(),
        "every refusal came before the model"
    );

    // Allowed: the sources' bytes follow the target's and the sources are gone.
    let joined = s
        .call("concat", &concat("/tmp/t", &["/tmp/s1", "/tmp/s2"]))
        .await;
    assert!(joined.ok(), "{joined:?}");
    assert!(s.status("/tmp/s1").await.is_none());
    assert!(s.status("/tmp/s2").await.is_none());
    let all = [t.as_slice(), s1.as_slice(), s2.as_slice()].concat();
    assert_eq!(s.status("/tmp/t").await.unwrap().length, all.len() as u64);
    let located = s.located("/tmp/t").await;
    assert_eq!(located.blocks.len(), 4);
    assert_eq!(s.read_all(&server, "/tmp/t").await, all);
    let events = support::events(&server.state, server.id, "hdfs_concat").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["sources"], json!(["/tmp/s1", "/tmp/s2"]));
    assert_eq!(events[0]["length_before"], 65536);
    assert_eq!(events[0]["length"], all.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_mutations_fail_closed_without_an_answer() {
    let server = start(
        policy(SILENT_ON_NEW),
        Some(json!({"decision_timeout_secs": 10})),
    )
    .await;
    let mut s = Session::open(&server).await;
    let data = bytes_of(70000, 2);
    s.put(&server, "/tmp/f.bin", &data, 65536).await;
    s.put(&server, "/tmp/g.bin", &data[..65536], 65536).await;
    s.put(&server, "/tmp/h.bin", &data[..10], 65536).await;

    let append = s
        .call(
            "append",
            &[src("/tmp/f.bin"), bytes(2, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(append.class(), "java.io.IOException", "{append:?}");
    assert_eq!(append.message(), "The NameNode could not decide");
    assert!(s.closed("/tmp/f.bin").await, "nothing was opened");
    let truncate = s
        .call(
            "truncate",
            &[src("/tmp/f.bin"), int(2, 100), bytes(3, CLIENT.as_bytes())].concat(),
        )
        .await;
    assert_eq!(truncate.class(), "java.io.IOException", "{truncate:?}");
    assert_eq!(s.status("/tmp/f.bin").await.unwrap().length, 70000);
    assert!(s.closed("/tmp/f.bin").await);
    let concat = s
        .call(
            "concat",
            &[src("/tmp/g.bin"), bytes(2, b"/tmp/h.bin")].concat(),
        )
        .await;
    assert_eq!(concat.class(), "java.io.IOException", "{concat:?}");
    assert!(s.status("/tmp/h.bin").await.is_some(), "the source stays");
    assert_eq!(s.status("/tmp/g.bin").await.unwrap().length, 65536);
    for op in ["append", "truncate", "concat"] {
        assert!(
            server
                .lines("decision=model_silent")
                .iter()
                .any(|l| l.contains(&format!("operation={op} "))),
            "{op}: {}",
            server.dump_logs()
        );
    }
}
