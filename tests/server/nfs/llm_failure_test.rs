//! What an NFS client gets when the LLM backend fails.
//!
//! The failure is forced the same way `tests/server/dns/llm_failure_test.rs` forces it: a mock
//! is configured for the *startup* instruction only, so the `nfs_operation` event matches no
//! rule, the mock Ollama server answers HTTP 500, and `consult_llm` returns `Err` — the same
//! shape as a real backend outage, an overload, or a malformed model response.
//!
//! Every NFS procedure in `LlmNfsFileSystem` used to answer that with `NFS3ERR_IO`, and every
//! *no-usable-action* response with the operation's own definite status — `NFS3ERR_NOENT` for
//! `lookup`, `NFS3ERR_ACCES` for `write`. Both are lies of a kind the client acts on: NOENT
//! tells it the file does not exist, when in truth the server never managed to ask. RFC 1813
//! has a status for precisely this case, `NFS3ERR_SERVERFAULT` (10006), "an error occurred on
//! the server which does not map to any of the legal NFS version 3 protocol error values".
//!
//! The assertions are at the protocol level. `RpcClient::call` (shared with `test.rs`) already
//! asserts the whole RPC envelope — REPLY, MSG_ACCEPTED, accept_stat SUCCESS, an AUTH_NULL
//! verifier and the call's own xid echoed — which matters here more than anywhere else: a
//! reply the client discards as malformed is indistinguishable from the silence this test
//! exists to prevent.

#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use super::test::{
    xdr_opaque, RpcClient, Xdr, MOUNTPROC3_MNT, MOUNT_PROGRAM, MOUNT_V3, NFSPROC3_GETATTR,
    NFSPROC3_LOOKUP, NFS_PROGRAM, NFS_V3,
};
use std::time::Duration;

/// RFC 1813 status codes this test cares about.
const NFS3_OK: u32 = 0;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_SERVERFAULT: u32 = 10006;

/// A failing NFS operation must be answered, not dropped, and must not claim to know anything.
#[tokio::test]
async fn test_nfs_answers_serverfault_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Export a directory \
                  containing readme.txt";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Export a directory containing readme.txt"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for the `nfs_operation` event: the mock answers 500, which is
        // what drives every filesystem operation down its LLM-failure path.
    });

    let server = helpers::start_netget_server(server_config).await?;
    let mut rpc = RpcClient::connect(server.port).await?;

    // MOUNT "/" reaches no LLM call at all — `path_to_id` short-circuits on the root — so it
    // still succeeds and hands over the root file handle the rest of the test needs. That it
    // works is also the control: the failures below are the model's, not the transport's.
    let mnt = rpc
        .call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &xdr_opaque(b"/"))
        .await?;
    let mut xdr = Xdr::new(&mnt);
    assert_eq!(
        xdr.u32("mountstat3"),
        0,
        "MNT needs no LLM call and must still succeed"
    );
    let root_fh = xdr.opaque("root file handle");
    assert!(!root_fh.is_empty(), "MNT must return a file handle");

    // ---- GETATTR: the first procedure that consults the model -------------------------
    let getattr = tokio::time::timeout(
        Duration::from_secs(30),
        rpc.call(NFS_PROGRAM, NFS_V3, NFSPROC3_GETATTR, &xdr_opaque(&root_fh)),
    )
    .await
    .map_err(|_| {
        "No NFS reply to GETATTR within 30s — the server went silent on LLM failure and left \
         the RPC hanging, which is the exact defect this test exists to catch"
    })??;

    let mut xdr = Xdr::new(&getattr);
    let status = xdr.u32("nfsstat3");
    assert_ne!(
        status, NFS3_OK,
        "an LLM failure must never be reported as a successful GETATTR"
    );
    assert_ne!(
        status, NFS3ERR_IO,
        "NFS3ERR_IO claims a hard I/O error on the object; the server simply could not reach \
         its backend"
    );
    assert_eq!(
        status, NFS3ERR_SERVERFAULT,
        "an LLM failure must be reported as NFS3ERR_SERVERFAULT (10006)"
    );
    assert_eq!(
        xdr.remaining(),
        0,
        "a failed GETATTR carries no fattr3; trailing bytes mean the reply is malformed and a \
         real client would discard it"
    );

    // ---- LOOKUP: the failure must not be dressed up as "no such file" ------------------
    let mut args = xdr_opaque(&root_fh);
    args.extend_from_slice(&xdr_opaque(b"readme.txt"));
    let lookup = tokio::time::timeout(
        Duration::from_secs(30),
        rpc.call(NFS_PROGRAM, NFS_V3, NFSPROC3_LOOKUP, &args),
    )
    .await
    .map_err(|_| "No NFS reply to LOOKUP within 30s — the server went silent on LLM failure")??;

    let mut xdr = Xdr::new(&lookup);
    let status = xdr.u32("nfsstat3");
    assert_ne!(
        status, NFS3_OK,
        "an LLM failure must never be reported as a successful LOOKUP"
    );
    assert_ne!(
        status, NFS3ERR_NOENT,
        "NFS3ERR_NOENT is a definite answer — it tells the client the file does not exist. The \
         server could not ask, so it does not know, and must not say so"
    );
    assert_eq!(
        status, NFS3ERR_SERVERFAULT,
        "an LLM failure must be reported as NFS3ERR_SERVERFAULT (10006)"
    );
    assert_eq!(
        xdr.u32("dir_attributes discriminant"),
        0,
        "LOOKUP3resfail carries post-op attributes for the directory; those come from a getattr \
         that also failed, so the discriminant must be Void (0)"
    );
    assert_eq!(xdr.remaining(), 0, "trailing bytes after LOOKUP3resfail");

    // The connection is still usable: answering an error must not tear the session down.
    let mnt_again = rpc
        .call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &xdr_opaque(b"/"))
        .await?;
    assert_eq!(
        Xdr::new(&mnt_again).u32("mountstat3"),
        0,
        "the RPC session must survive an NFS3ERR_SERVERFAULT"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
