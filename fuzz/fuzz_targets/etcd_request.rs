//! The etcd server's request decode path: `unary_message` (the 5-byte gRPC length-prefixed
//! message header, declared length honoured) and then the prost decoder for whichever KV
//! method the request's `:path` names — `RangeRequest`, `PutRequest`, `DeleteRangeRequest`,
//! `TxnRequest` or `CompactionRequest`, the types generated from `proto/etcd/rpc.proto`.
//!
//! The first input byte picks the method (the `:path` is a header, not part of the body);
//! the rest is the HTTP/2 request body exactly as `route_grpc_request` receives it, already
//! bounded by `MAX_REQUEST_BYTES`. No authentication stands in front of it.
//!
//! **Why this target exists: `TxnRequest` is recursive.** A `RequestOp` may hold a
//! `request_txn`, which holds `RequestOp`s, and an unknown field of wire type 3 is a group that
//! may hold groups. prost refuses nesting past its recursion limit of 100 *unless* any crate in
//! the build graph turns on prost's `no-recursion-limit` feature — Cargo unifies features, so
//! a dependency NetGet does not control can delete the limit for every prost decoder in the
//! process, and a 160 KB `TxnRequest` then overflows the stack. The corpus carries both bombs,
//! 20 000 levels each, so a build where that has happened dies here rather than in production.
//!
//! Asserted: nothing panics or overflows; a message that decodes re-encodes and decodes back
//! to the same value (prost drops unknown fields, so the second decode is the fixed point).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::etcd::etcdserverpb::{
    CompactionRequest, DeleteRangeRequest, PutRequest, RangeRequest, TxnRequest,
};
use netget::server::etcd::{unary_message, MAX_REQUEST_BYTES};
use prost::Message;

fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(msg: &[u8]) {
    let Ok(decoded) = M::decode(msg) else {
        return;
    };
    let encoded = decoded.encode_to_vec();
    let again = M::decode(&encoded[..]).expect("a message prost encoded did not decode back");
    assert_eq!(
        decoded, again,
        "encode/decode round trip changed the request"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&method, body)) = data.split_first() else {
        return;
    };
    if body.len() > MAX_REQUEST_BYTES {
        return;
    }
    let Ok(msg) = unary_message(body) else {
        return;
    };
    assert!(
        msg.len() + 5 <= body.len(),
        "unary_message returned bytes it was not given"
    );
    match method % 5 {
        0 => round_trip::<RangeRequest>(msg),
        1 => round_trip::<PutRequest>(msg),
        2 => round_trip::<DeleteRangeRequest>(msg),
        3 => round_trip::<TxnRequest>(msg),
        _ => round_trip::<CompactionRequest>(msg),
    }
});
