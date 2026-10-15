//! NetGet's kafka-protocol fork (`netget-kafka-protocol`, github.com/netget-net/kafka-protocol-rs)
//! is the one Cargo builds, still carries its patches, and the patches do what they are for.
//! The fork's NETGET.md lists every change.
//!
//! `every_decode_allocation_in_the_crate_is_bounded_by_the_bytes_present` is the ratchet:
//! it reads every `.rs` file under the fork's `src/` and fails on any `with_capacity`,
//! `reserve`, `vec![0; …]` or `resize` it cannot classify as bounded, so an upgrade that
//! brings a new peer-sized allocation in has to be looked at rather than inherited.
//!
//! The decode test is the reproduction: unpatched, `MetadataRequest::decode` on a topics
//! array declaring 0x7fffffff entries calls `Vec::with_capacity` for ~144 GiB and the test
//! binary aborts with "memory allocation of … bytes failed" rather than failing.

#[path = "helpers/fork_source.rs"]
mod fork_source;

use fork_source::{assert_fork_is_built, fork_dir, read_fork};
use std::fs;
use std::path::Path;

const FORK: &str = "netget-kafka-protocol";

#[test]
fn kafka_protocol_fork_keeps_its_version_and_licenses() {
    let manifest = read_fork(FORK, "Cargo.toml");
    assert!(manifest.contains("name = \"netget-kafka-protocol\""));
    assert!(manifest.contains("version = \"0.14.1\""));
    assert!(manifest.contains("license = \"MIT/Apache-2.0\""));
    for license in ["LICENSE-APACHE", "LICENSE-MIT"] {
        assert!(fork_dir(FORK).join(license).is_file(), "{license} missing");
    }
}

#[test]
fn cargo_builds_the_kafka_protocol_fork() {
    assert_fork_is_built("kafka-protocol", "0.14.1");
}

#[test]
fn both_array_decoders_bound_their_preallocation_by_the_bytes_remaining() {
    let types = read_fork(FORK, "src/protocol/types.rs");
    assert!(
        types.contains("Vec::with_capacity((n as usize).min(buf.remaining()))"),
        "Array<E>::decode lost its bound"
    );
    assert!(
        types.contains("Vec::with_capacity(((n - 1) as usize).min(buf.remaining()))"),
        "CompactArray<E>::decode lost its bound"
    );
    assert_eq!(
        types.matches("Vec::with_capacity(n as usize)").count()
            + types
                .matches("Vec::with_capacity((n - 1) as usize)")
                .count(),
        0,
        "an unbounded with_capacity from a wire count is back"
    );
}

#[test]
fn record_batch_counts_are_bounded_by_the_bytes_remaining() {
    let records = read_fork(FORK, "src/records.rs");
    assert!(
        records.contains("records.reserve(batch_decode_info.record_count.min(buf.remaining()))"),
        "RecordBatchDecoder::decode_new_records lost its bound: a ~61-byte batch declaring \
         0x7fffffff records reserves hundreds of GiB"
    );
    assert!(
        records.contains("IndexMap::with_capacity(num_headers.min(buf.len()))"),
        "Record::decode_new lost its header-count bound"
    );
    assert!(
        !records.contains("records.reserve(batch_decode_info.record_count);")
            && !records.contains("IndexMap::with_capacity(num_headers);"),
        "an unbounded record-batch reservation is back"
    );
}

#[test]
fn declared_byte_lengths_are_checked_before_they_are_zero_filled() {
    let types = read_fork(FORK, "src/protocol/types.rs");
    let lines: Vec<&str> = types.lines().collect();
    let fills: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].contains("vec![0;"))
        .collect();
    assert_eq!(
        fills.len(),
        4,
        "String, CompactString, Bytes and CompactBytes each zero-fill once"
    );
    for i in fills {
        assert!(
            lines[i.saturating_sub(4)..i]
                .iter()
                .any(|l| l.contains("> buf.remaining()")),
            "types.rs:{} zero-fills a declared length with no remaining-bytes check before it",
            i + 1
        );
    }

    let snappy = read_fork(FORK, "src/compression/snappy.rs");
    let guard = snappy
        .find("actual_len > buf.len().saturating_mul(32)")
        .expect("the snappy decompressor lost its declared-length ceiling");
    let fill = snappy
        .find("tmp.resize(actual_len, 0)")
        .expect("snappy's zero-fill moved; re-check the ceiling still precedes it");
    assert!(
        guard < fill,
        "the snappy ceiling must run before the zero-fill"
    );
}

/// Every allocation-sizing call in the fork, classified. A line that matches the
/// pattern and none of the known shapes fails the test, so a new site is looked at.
#[test]
fn every_decode_allocation_in_the_crate_is_bounded_by_the_bytes_present() {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = fork_dir(FORK).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() > 100, "walked only {} files", files.len());

    let mut unclassified = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            let sizes = [
                "with_capacity(",
                ".reserve(",
                "reserve_exact(",
                "vec![0;",
                ".resize(",
            ]
            .iter()
            .any(|p| code.contains(p));
            if !sizes {
                continue;
            }
            let before = &lines[i.saturating_sub(4)..i];
            let bounded = code.contains(".min(buf.remaining())")
                || code.contains(".min(buf.len())")
                || (code.contains("vec![0;")
                    && before.iter().any(|l| l.contains("> buf.remaining()")))
                || (code.contains("tmp.resize(actual_len, 0)")
                    && lines[i.saturating_sub(10)..i]
                        .iter()
                        .any(|l| l.contains("saturating_mul(32)")))
                // ByteBufMut::seek on the encode side: the offset is our own.
                || (code.trim() == "self.resize(offset, 0);"
                    && file.ends_with("protocol/buf.rs"));
            if !bounded {
                unclassified.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&root).unwrap().display(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "allocation sized by something other than the bytes present — bound it in the fork \
         (github.com/netget-net/kafka-protocol-rs, NETGET.md) or, if the size is our own, \
         classify it here:\n{}",
        unclassified.join("\n")
    );
}

mod decode {
    use bytes::Bytes;
    use kafka_protocol::messages::{FetchRequest, MetadataRequest, ProduceRequest};
    use kafka_protocol::protocol::Decodable;

    /// A non-flexible array whose Int32 count is i32::MAX, followed by nothing.
    const HOSTILE_ARRAY: [u8; 4] = [0x7f, 0xff, 0xff, 0xff];

    #[test]
    fn a_request_declaring_two_billion_topics_is_an_error_not_an_abort() {
        let mut buf = Bytes::from_static(&HOSTILE_ARRAY);
        let err = MetadataRequest::decode(&mut buf, 1).expect_err("truncated array");
        let text = format!("{err:#}");
        assert!(
            text.contains("Not enough bytes") || text.contains("remaining"),
            "unexpected error: {text}"
        );
    }

    #[test]
    fn fetch_and_produce_arrays_are_bounded_the_same_way() {
        // Fetch v4: replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, then
        // the topics array. Produce v3: transactional_id (nullable string), acks,
        // timeout_ms, then the topics array.
        let mut fetch = Vec::new();
        fetch.extend_from_slice(&(-1i32).to_be_bytes());
        fetch.extend_from_slice(&500i32.to_be_bytes());
        fetch.extend_from_slice(&1i32.to_be_bytes());
        fetch.extend_from_slice(&1_048_576i32.to_be_bytes());
        fetch.push(0);
        fetch.extend_from_slice(&HOSTILE_ARRAY);
        assert!(FetchRequest::decode(&mut Bytes::from(fetch), 4).is_err());

        let mut produce = Vec::new();
        produce.extend_from_slice(&(-1i16).to_be_bytes());
        produce.extend_from_slice(&1i16.to_be_bytes());
        produce.extend_from_slice(&1000i32.to_be_bytes());
        produce.extend_from_slice(&HOSTILE_ARRAY);
        assert!(ProduceRequest::decode(&mut Bytes::from(produce), 3).is_err());
    }
}
