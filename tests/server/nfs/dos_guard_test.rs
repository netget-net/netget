//! The two pre-authentication denial-of-service paths `nfsserve` 0.10.2 opens, and NetGet's
//! refusal of both.
//!
//! `nfsserve` sizes buffers from numbers the peer supplies and never checks them
//! (`rpcwire::read_fragment` resizes by a 31-bit fragment length, `xdr.rs` by a 32-bit string
//! length), and its default `path_to_id` calls `lookup()` once per `/`-separated component of
//! a MOUNT `dirpath` — which in this server is one LLM round-trip each. Both are reachable
//! from a forty-byte unauthenticated `MOUNTPROC3_MNT`.
//!
//! Neither is fixable inside the crate from here, so `src/server/nfs/guard.rs` screens the
//! record-marking layer in front of it and `LlmNfsFileSystem::path_to_id` bounds the component
//! count. These tests drive the wire, not the guard's internals: remove either bound and the
//! matching test fails.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nfs --test server -- server::nfs::dos_guard --test-threads=100

#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use super::test::{xdr_opaque, RpcClient, Xdr, MOUNTPROC3_MNT, MOUNT_PROGRAM, MOUNT_V3};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// RFC 1813 `mountstat3`.
const MNT3_OK: u32 = 0;
const MNT3ERR_NOENT: u32 = 2;

/// RFC 5531 `accept_stat`.
const GARBAGE_ARGS: u32 = 4;

/// A `MOUNTPROC3_MNT` call body, minus the record marker, with a `dirpath` length the caller
/// chooses. This is the forty-byte message at the centre of the vulnerability.
fn mnt_call_body(xid: u32, dirpath_len: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&xid.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // msg_type: CALL
    body.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
    body.extend_from_slice(&MOUNT_PROGRAM.to_be_bytes());
    body.extend_from_slice(&MOUNT_V3.to_be_bytes());
    body.extend_from_slice(&MOUNTPROC3_MNT.to_be_bytes());
    body.extend_from_slice(&[0u8; 8]); // cred: AUTH_NULL, empty
    body.extend_from_slice(&[0u8; 8]); // verf: AUTH_NULL, empty
    body.extend_from_slice(&dirpath_len.to_be_bytes());
    body
}

/// A record marker announcing 2 GiB is refused before a byte of it is read, and the peer is
/// told so in its own protocol rather than dropped.
///
/// Without the guard these forty bytes reach `nfsserve`, which does
/// `append_to.resize(append_to.len() + 0x7FFF_FFFF, 0)` and then waits for 2 GiB that never
/// arrive: the process either aborts on the allocation or commits 2 GiB and blocks, and in
/// both cases no reply is ever written and the `read_exact` below times out. The test is what
/// tells the two apart from a working refusal.
#[tokio::test]
async fn test_nfs_refuses_oversize_rpc_record() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS refuses an oversize RPC record ===");

    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Export a directory";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Export a directory"
                }
            ]))
            .expect_calls(1)
            .and()
        // No `nfs_operation` rule: nothing here should reach the model at all.
    });

    let server = helpers::start_netget_server(server_config).await?;

    let mut hostile = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let xid = 0xDEAD_BEEFu32;

    // Last-fragment bit set, 31-bit length 0x7FFF_FFFF — the largest the wire format allows.
    let mut record = Vec::new();
    record.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    record.extend_from_slice(&mnt_call_body(xid, 0xFFFF_FFFF));
    assert!(
        record.len() < 64,
        "the whole attack is {} bytes; that asymmetry is the point",
        record.len()
    );
    hostile.write_all(&record).await?;
    hostile.flush().await?;

    // The refusal: one 28-byte record, GARBAGE_ARGS, addressed to our own xid.
    let mut reply = [0u8; 28];
    tokio::time::timeout(Duration::from_secs(20), hostile.read_exact(&mut reply))
        .await
        .map_err(|_| {
            "no answer to the oversize record within 20s - the guard did not refuse it, and \
             nfsserve is sitting on a 2 GiB buffer waiting for bytes that will never come"
        })??;

    let marker = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]);
    assert_eq!(
        marker, 0x8000_0018,
        "the refusal must be a well-formed last fragment of 24 bytes"
    );
    let mut xdr = Xdr::new(&reply[4..]);
    assert_eq!(
        xdr.u32("reply xid"),
        xid,
        "a refusal a client cannot match to its call is indistinguishable from silence"
    );
    assert_eq!(xdr.u32("msg_type"), 1, "expected msg_type REPLY");
    assert_eq!(xdr.u32("reply_stat"), 0, "expected MSG_ACCEPTED");
    assert_eq!(xdr.u32("verf.flavor"), 0, "expected an AUTH_NULL verifier");
    assert_eq!(
        xdr.u32("verf.length"),
        0,
        "AUTH_NULL verifier must be empty"
    );
    assert_eq!(
        xdr.u32("accept_stat"),
        GARBAGE_ARGS,
        "the record layer's only way of saying 'I will not decode that'"
    );

    // And the connection is closed, not left half-usable.
    let mut tail = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(10), hostile.read(&mut tail)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "a refused connection must be closed, got {closed:?}"
    );

    // The control, and the part that would catch a process-wide abort: the server is still
    // there afterwards and still answers a legitimate MOUNT. MOUNT "/" reaches no LLM call
    // (`path_to_id` short-circuits on the root), so this stays inside the mock's expectations.
    let mut rpc = RpcClient::connect(server.port).await?;
    let mnt = tokio::time::timeout(
        Duration::from_secs(20),
        rpc.call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &xdr_opaque(b"/")),
    )
    .await
    .map_err(|_| "the server stopped answering after refusing the oversize record")??;
    let mut xdr = Xdr::new(&mnt);
    assert_eq!(
        xdr.u32("mountstat3"),
        MNT3_OK,
        "refusing one peer must not disturb the next"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// A MOUNT `dirpath` with hundreds of components is refused outright, and costs no LLM calls.
///
/// `nfsserve`'s default `path_to_id` walks the components calling `lookup()` on each, and here
/// each `lookup` is one model round-trip: `a/a/a/...` is two bytes per call. The mock below
/// *succeeds* at every lookup on purpose — that is what makes the amplification real. Without
/// the bound in `LlmNfsFileSystem::path_to_id` the walk runs to completion, the rule records
/// one call per component instead of zero, and MOUNT answers MNT3_OK.
#[tokio::test]
async fn test_nfs_refuses_a_mount_path_that_would_amplify_into_llm_calls() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS refuses an over-long MOUNT path ===");

    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Export a directory";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Export a directory"
                }
            ]))
            .expect_calls(1)
            .and()
            // Every lookup would succeed, so nothing but the bound stops the walk.
            .on_event("nfs_operation")
            .and_event_data_contains("operation", "lookup")
            .respond_with_actions(serde_json::json!([
                { "type": "nfs_lookup_response", "fileid": 2 }
            ]))
            .expect_calls(0)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    let mut rpc = RpcClient::connect(server.port).await?;

    // 200 components, 400 bytes on the wire - comfortably inside every framing bound, which
    // is exactly why the framing screen cannot be what stops this one.
    let deep_path = vec!["a"; 200].join("/");
    let mnt = tokio::time::timeout(
        Duration::from_secs(30),
        rpc.call(
            MOUNT_PROGRAM,
            MOUNT_V3,
            MOUNTPROC3_MNT,
            &xdr_opaque(deep_path.as_bytes()),
        ),
    )
    .await
    .map_err(|_| "MOUNT never answered - the component walk is still running")??;

    let mut xdr = Xdr::new(&mnt);
    assert_eq!(
        xdr.u32("mountstat3"),
        MNT3ERR_NOENT,
        "an over-long dirpath must be refused, not resolved part-way"
    );

    // The control: a real MOUNT still works on the same connection, so the refusal is about
    // the path's depth and not about MOUNT being broken.
    let mnt = rpc
        .call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &xdr_opaque(b"/"))
        .await?;
    let mut xdr = Xdr::new(&mnt);
    assert_eq!(
        xdr.u32("mountstat3"),
        MNT3_OK,
        "MOUNT / must still succeed after a refused path"
    );

    // `expect_calls(0)` on the lookup rule is the amplification assertion: without the bound
    // it records 200.
    server.wait_for_mocks(15).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
