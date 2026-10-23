//! `netget::server::libp2p::{ipfs, unixfs}` — the dag-pb / UnixFS decoders every Bitswap block
//! goes through, the walk the libp2p client's `ipfs_fetch` runs over a peer's DAG, and the
//! description parser and builder behind `ipfs_add`.
//!
//! The first byte picks what the rest is:
//!
//! - 0: one dag-pb block, decoded as a node and its UnixFS data. What decodes must encode and
//!   decode again to the same node.
//! - 1: a set of blocks (`u32` little-endian length, then the bytes, repeated). The first is
//!   the root, as dag-pb (or raw when the second byte is odd); the walk fetches from the set,
//!   each block found by the CID its own bytes hash to. Whatever the DAG, the walk stays inside
//!   `MAX_DAG_DEPTH`, `MAX_WALK_BLOCKS` and the bytes it was asked to keep. Links name blocks by
//!   hash, which mutation cannot forge, so the corpus carries a real chain 200 nodes deep (a
//!   depth bomb: the walk must refuse it at 33) and a fan-out bomb.
//! - 2: an `ipfs_add` description (JSON). The corpus's bomb nests directories a hundred deep,
//!   past `MAX_DIR_DEPTH` and short of serde_json's own 128-level limit, so the parser's own
//!   iterative walk is what refuses it. Small accepted descriptions are built, and every block
//!   built must hash to its CID.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::libp2p::ipfs::{self, Cid};
use netget::server::libp2p::unixfs::{self, Walk};

fn blocks(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while b.len() >= 4 && out.len() < 64 {
        let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        b = &b[4..];
        let n = n.min(b.len());
        out.push(b[..n].to_vec());
        b = &b[n..];
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            if let Ok(node) = ipfs::decode_pb_node(rest) {
                let again = ipfs::decode_pb_node(&ipfs::encode_pb_node(&node))
                    .expect("an encoded node decodes");
                assert_eq!(again, node);
                if let Some(d) = &node.data {
                    let _ = ipfs::decode_unixfs(d);
                }
                let _ = ipfs::describe(&Cid::v1(ipfs::DAG_PB, rest), rest);
            }
        }
        1 => {
            let Some((&flags, rest)) = rest.split_first() else {
                return;
            };
            let set = blocks(rest);
            let Some(first) = set.first() else {
                return;
            };
            let codec = if flags & 1 == 1 {
                ipfs::RAW
            } else {
                ipfs::DAG_PB
            };
            let keep = 4096;
            let mut walk = Walk::new(Cid::v1(codec, first), keep);
            for _ in 0..(unixfs::MAX_WALK_BLOCKS + 8) {
                match walk.step() {
                    Err(_) => return,
                    Ok(Some(done)) => {
                        assert!(done.depth <= unixfs::MAX_DAG_DEPTH);
                        assert!(done.blocks <= unixfs::MAX_WALK_BLOCKS);
                        assert!(done.data.len() <= keep);
                        assert!(done.data.len() as u64 <= done.size || done.kind != "file");
                        return;
                    }
                    Ok(None) => {}
                }
                let wants = walk.wants();
                if wants.is_empty() && !walk.ready() {
                    return;
                }
                for want in wants {
                    match set.iter().find(|b| want.matches(b)) {
                        Some(b) => walk.give(&want, b.clone()).expect("a matching block"),
                        None => return,
                    }
                }
            }
            panic!("the walk neither finished nor stopped within its block bound");
        }
        _ => {
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(rest) else {
                return;
            };
            let Ok(d) = unixfs::parse(&v) else {
                return;
            };
            if d.total_bytes() > 1 << 20 {
                return;
            }
            if let Ok(built) = unixfs::build(&d) {
                assert!(built.blocks.len() <= unixfs::MAX_ADD_BLOCKS);
                assert!(built.depth <= unixfs::MAX_DAG_DEPTH);
                for (cid, source) in &built.blocks {
                    let bytes = source.bytes();
                    assert!(
                        cid.matches(&bytes),
                        "a built block does not hash to its CID"
                    );
                    assert_eq!(bytes.len(), source.len());
                }
                assert!(built.blocks.iter().any(|(c, _)| *c == built.root));
            }
        }
    }
});
