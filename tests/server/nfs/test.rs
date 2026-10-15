//! End-to-end NFS tests for NetGet
//!
//! These tests spawn the actual NetGet binary with NFS prompts
//! and validate LLM-controlled NFS v3 filesystem operations.
//!
//! The NFS implementation uses nfsserve library which handles:
//! - RPC/XDR protocol encoding/decoding
//! - MOUNT protocol
//! - TCP connection management
//!
//! The LLM controls all filesystem operations through structured actions:
//! - File/directory lookup, creation, deletion
//! - File read/write operations
//! - Attribute getting/setting
//! - Directory listings
//!
//! These tests validate server startup, connection handling, and basic NFS protocol.

#![cfg(unix)]

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// A minimal ONC RPC / XDR client (RFC 5531, RFC 1813)
//
// This suite used to assert only that a TCP connection was accepted. That is why
// `NFS_OPERATION_EVENT` could ship with a *comment* where its action list belonged — leaving
// every `nfs_*_response` invisible to the model, so no NFS operation could be answered at
// all — without a single test failing. The tests below speak real RPC and decode the
// replies, so that class of defect cannot pass again.
//
// There is no Rust NFSv3 *server-side* test client, and `nfs3_client`'s builder does not
// take a port, so the wire format is hand-rolled here. It is small: RPC over TCP is
// record-marked, and only three procedures are needed.
//
// `RpcClient`, `Xdr` and `xdr_opaque` are `pub` because `llm_failure_test.rs` in this
// directory drives the same wire format; there is one RPC implementation, not two.
// ---------------------------------------------------------------------------

pub const NFS_PROGRAM: u32 = 100003;
pub const MOUNT_PROGRAM: u32 = 100005;
const RPC_VERSION: u32 = 2;

pub const NFS_V3: u32 = 3;
pub const MOUNT_V3: u32 = 3;

pub const PROC_NULL: u32 = 0;
pub const MOUNTPROC3_MNT: u32 = 1;
pub const NFSPROC3_GETATTR: u32 = 1;
pub const NFSPROC3_LOOKUP: u32 = 3;

/// Sequential reader over an XDR-encoded buffer.
///
/// Every accessor asserts it has the bytes it needs, so a truncated or misencoded reply
/// fails the test at the field that is wrong rather than producing a plausible value.
pub struct Xdr<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Xdr<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn u32(&mut self, what: &str) -> u32 {
        assert!(
            self.pos + 4 <= self.buf.len(),
            "reply ended before {what} at offset {}",
            self.pos
        );
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }

    pub fn u64(&mut self, what: &str) -> u64 {
        let hi = self.u32(what) as u64;
        let lo = self.u32(what) as u64;
        (hi << 32) | lo
    }

    /// XDR variable-length opaque: 4-byte length, then the bytes padded to a 4-byte boundary.
    pub fn opaque(&mut self, what: &str) -> Vec<u8> {
        let len = self.u32(what) as usize;
        assert!(
            self.pos + len <= self.buf.len(),
            "reply ended inside {what} ({len} bytes announced)"
        );
        let bytes = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len + (4 - len % 4) % 4;
        bytes
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// A decoded NFSv3 `fattr3`.
#[derive(Debug)]
struct Fattr3 {
    ftype: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    fileid: u64,
    mtime_seconds: u32,
}

fn read_fattr3(xdr: &mut Xdr<'_>) -> Fattr3 {
    let ftype = xdr.u32("fattr3.ftype");
    let mode = xdr.u32("fattr3.mode");
    let nlink = xdr.u32("fattr3.nlink");
    let uid = xdr.u32("fattr3.uid");
    let gid = xdr.u32("fattr3.gid");
    let size = xdr.u64("fattr3.size");
    let _used = xdr.u64("fattr3.used");
    let _rdev_major = xdr.u32("fattr3.rdev");
    let _rdev_minor = xdr.u32("fattr3.rdev");
    let _fsid = xdr.u64("fattr3.fsid");
    let fileid = xdr.u64("fattr3.fileid");
    let _atime = xdr.u64("fattr3.atime");
    let mtime_seconds = xdr.u32("fattr3.mtime.seconds");
    let _mtime_nseconds = xdr.u32("fattr3.mtime.nseconds");
    let _ctime = xdr.u64("fattr3.ctime");
    Fattr3 {
        ftype,
        mode,
        nlink,
        uid,
        gid,
        size,
        fileid,
        mtime_seconds,
    }
}

/// An RPC connection to the server under test.
pub struct RpcClient {
    stream: TcpStream,
    next_xid: u32,
}

impl RpcClient {
    pub async fn connect(port: u16) -> E2EResult<Self> {
        Ok(Self {
            stream: TcpStream::connect(format!("127.0.0.1:{port}")).await?,
            next_xid: 0x5A5A_0001,
        })
    }

    /// Issue one RPC call and return the decoded results, positioned just past the
    /// accepted-reply header.
    ///
    /// Asserts the whole RPC envelope: the reply must be a REPLY, MSG_ACCEPTED, SUCCESS, and
    /// must echo the call's xid. A server that got any of that wrong would be rejected by
    /// every real client.
    pub async fn call(
        &mut self,
        prog: u32,
        vers: u32,
        proc: u32,
        args: &[u8],
    ) -> E2EResult<Vec<u8>> {
        let xid = self.next_xid;
        self.next_xid += 1;

        let mut body = Vec::new();
        body.extend_from_slice(&xid.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes()); // msg_type: CALL
        body.extend_from_slice(&RPC_VERSION.to_be_bytes());
        body.extend_from_slice(&prog.to_be_bytes());
        body.extend_from_slice(&vers.to_be_bytes());
        body.extend_from_slice(&proc.to_be_bytes());
        // cred and verf, both AUTH_NULL with an empty body
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(args);

        // TCP record marking: high bit set marks the last fragment.
        let marker = 0x8000_0000u32 | (body.len() as u32);
        self.stream.write_all(&marker.to_be_bytes()).await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;

        // Read one (possibly multi-fragment) record.
        let mut reply = Vec::new();
        loop {
            let mut marker = [0u8; 4];
            self.stream.read_exact(&mut marker).await?;
            let marker = u32::from_be_bytes(marker);
            let last = marker & 0x8000_0000 != 0;
            let len = (marker & 0x7FFF_FFFF) as usize;
            let start = reply.len();
            reply.resize(start + len, 0);
            self.stream.read_exact(&mut reply[start..]).await?;
            if last {
                break;
            }
        }

        let mut xdr = Xdr::new(&reply);
        assert_eq!(
            xdr.u32("reply xid"),
            xid,
            "RPC reply must echo the call xid"
        );
        assert_eq!(xdr.u32("msg_type"), 1, "expected msg_type REPLY");
        assert_eq!(xdr.u32("reply_stat"), 0, "expected MSG_ACCEPTED");
        assert_eq!(xdr.u32("verf.flavor"), 0, "expected an AUTH_NULL verifier");
        assert_eq!(
            xdr.u32("verf.length"),
            0,
            "AUTH_NULL verifier must be empty"
        );
        assert_eq!(xdr.u32("accept_stat"), 0, "expected accept_stat SUCCESS");

        Ok(reply[xdr.pos..].to_vec())
    }
}

/// XDR-encode a variable-length opaque (used for dirpath, filename and file handles).
pub fn xdr_opaque(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + (4 - bytes.len() % 4) % 4, 0);
    out
}

#[tokio::test]
async fn test_nfs_server_start() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS Server Start ===");

    // PROMPT: Basic NFS server
    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Provide NFSv3 filesystem with export /data";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Provide NFSv3 filesystem with export /data"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let mut server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    // Verify it's an NFS server
    assert_eq!(
        server.stack, "NFS",
        "Expected NFS server but got {}",
        server.stack
    );
    assert!(server.is_running(), "Server should be running");

    println!("✓ NFS server initialized successfully");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_nfs_tcp_connection() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS TCP Connection ===");

    // PROMPT: NFS server that accepts connections
    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Accept NFS client connections";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Accept NFS client connections"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    // VALIDATION: Establish TCP connection to NFS port
    let addr = format!("127.0.0.1:{}", server.port);

    // Give the server a moment to fully initialize

    // A bare "the socket accepted" check cannot distinguish an NFS server from any other
    // listener, and its EOF and read-error branches only printed a warning. Issue a real
    // RPC NULL instead: it needs no LLM call, and only something speaking ONC RPC for the
    // NFS program can answer it. `call()` asserts the whole reply envelope.
    let mut rpc = RpcClient::connect(server.port).await?;
    let null = rpc.call(NFS_PROGRAM, NFS_V3, PROC_NULL, &[]).await?;
    assert!(
        null.is_empty(),
        "NFSPROC3_NULL returns void, got {} bytes",
        null.len()
    );
    println!("✓ NFS NULL answered over {addr}");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_nfs_multiple_connections() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS Multiple Connections ===");

    // PROMPT: NFS server with multiple client support
    let prompt =
        "listen on port {AVAILABLE_PORT} using nfs stack. Support multiple concurrent NFS clients";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Support multiple concurrent NFS clients"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    let addr = format!("127.0.0.1:{}", server.port);

    // VALIDATION: Open multiple concurrent connections
    let mut connections = Vec::new();

    for i in 1..=3 {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => {
                println!("✓ Connection {} established", i);
                connections.push(stream);
            }
            Err(e) => {
                return Err(format!("Failed to establish connection {}: {}", i, e).into());
            }
        }
    }

    // Verify all connections are maintained
    println!("✓ All {} connections maintained", connections.len());

    // Close connections
    for (i, stream) in connections.into_iter().enumerate() {
        drop(stream);
        println!("✓ Connection {} closed", i + 1);
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_nfs_connection_lifecycle() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS Connection Lifecycle ===");

    // PROMPT: NFS server for lifecycle testing
    let prompt =
        "listen on port {AVAILABLE_PORT} using nfs stack. Handle connection lifecycle events";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Handle connection lifecycle events"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    let addr = format!("127.0.0.1:{}", server.port);

    // VALIDATION: Test connection lifecycle

    // 1. Connect
    let stream = tokio::net::TcpStream::connect(&addr).await?;
    println!("✓ Connection established");

    // 2. Hold connection
    println!("✓ Connection held");

    // 3. Close gracefully
    drop(stream);
    println!("✓ Connection closed gracefully");

    // 4. Reconnect to verify server still accepting
    let stream2 = tokio::net::TcpStream::connect(&addr).await?;
    println!("✓ Reconnection successful");
    drop(stream2);

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_nfs_port_configuration() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS Port Configuration ===");

    // PROMPT: NFS on custom port
    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Standard NFS v3 service";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Standard NFS v3 service"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    // Verify it's listening
    let addr = format!("127.0.0.1:{}", server.port);

    let stream = tokio::net::TcpStream::connect(&addr).await?;
    println!("✓ Server listening on correct port");
    drop(stream);

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_nfs_server_stop() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS Server Stop ===");

    // PROMPT: NFS server with graceful shutdown
    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Support clean shutdown";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Support clean shutdown"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the NFS server
    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    let addr = format!("127.0.0.1:{}", server.port);

    // Establish connection
    let stream = tokio::net::TcpStream::connect(&addr).await?;
    println!("✓ Connection established");

    // Verify mock expectations BEFORE stopping server
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Stop server
    server.stop().await?;
    println!("✓ Server stopped gracefully");

    // The port must actually be released. This used to print a warning and pass, which is
    // exactly the failure mode `tests/server_stop_releases_port_test.rs` exists to catch.
    // Retry briefly: the listener closes asynchronously.
    let mut released = false;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(&addr).await.is_err() {
            released = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        released,
        "port {addr} still accepted connections 2s after stop_server"
    );
    println!("✓ Port released after server stop");

    drop(stream);
    println!("=== Test passed ===\n");
    Ok(())
}

/// MOUNT the export, GETATTR the root, and LOOKUP a file in it — decoding every reply.
///
/// This replaces three `#[ignore]`d placeholders whose entire bodies were `println!` plus
/// `Ok(())`: they could not fail, and their presence made the gap look covered. The claim
/// they carried — that no Rust NFS client exists — is true of client *libraries*, but the
/// three procedures needed here are small enough to encode directly.
#[tokio::test]
async fn test_nfs_mount_and_lookup() -> E2EResult<()> {
    println!("\n=== E2E Test: NFS MOUNT + GETATTR + LOOKUP ===");

    let prompt = "listen on port {AVAILABLE_PORT} using nfs stack. Export a directory \
        containing readme.txt (fileid 42, 13 bytes).";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // getattr: called once directly, and twice more by LOOKUP for the directory's
            // and the object's post-op attributes. The handler answers all three.
            .on_event("nfs_operation")
            .and_event_data_contains("operation", "getattr")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "nfs_getattr_response",
                    "file_type": "directory",
                    "mode": 0o755,
                    "size": 4096,
                    "uid": 1000,
                    "gid": 1000,
                    "mtime": 1_700_000_000u64
                }
            ]))
            .expect_at_least(1)
            .and()
            .on_event("nfs_operation")
            .and_event_data_contains("operation", "lookup")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "nfs_lookup_response",
                    "fileid": 42
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("nfs")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NFS",
                    "instruction": "Export a directory containing readme.txt with fileid 42"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("NFS server started on port {}", server.port);

    let mut rpc = RpcClient::connect(server.port).await?;

    // 1. MOUNT NULL — no LLM involved, so this isolates the RPC layer itself. A malformed
    //    envelope fails inside `call()`.
    let null = rpc.call(MOUNT_PROGRAM, MOUNT_V3, PROC_NULL, &[]).await?;
    assert!(
        null.is_empty(),
        "MOUNTPROC3_NULL returns void, got {} bytes",
        null.len()
    );
    println!("✓ MOUNT NULL answered with a well-formed RPC reply");

    // 2. MOUNT MNT "/" — returns the root file handle the rest of the session needs.
    let mnt = rpc
        .call(MOUNT_PROGRAM, MOUNT_V3, MOUNTPROC3_MNT, &xdr_opaque(b"/"))
        .await?;
    let mut xdr = Xdr::new(&mnt);
    assert_eq!(
        xdr.u32("mountstat3"),
        0,
        "MNT3_OK expected; the export must be mountable"
    );
    let root_fh = xdr.opaque("root file handle");
    assert!(
        !root_fh.is_empty(),
        "MNT must return a non-empty file handle"
    );
    let auth_count = xdr.u32("auth_flavors count");
    let flavors: Vec<u32> = (0..auth_count).map(|_| xdr.u32("auth_flavor")).collect();
    assert!(
        flavors.contains(&0),
        "the export must offer AUTH_NULL; offered {flavors:?}"
    );
    assert_eq!(xdr.remaining(), 0, "trailing bytes after mountres3");
    println!("✓ MOUNT MNT returned a {}-byte root handle", root_fh.len());

    // 3. GETATTR on the root handle. This is the first operation that reaches the model, so
    //    it is what proves the LLM integration answers at all: the handler's attributes must
    //    come back through the fattr3 on the wire.
    let getattr = rpc
        .call(NFS_PROGRAM, NFS_V3, NFSPROC3_GETATTR, &xdr_opaque(&root_fh))
        .await?;
    let mut xdr = Xdr::new(&getattr);
    assert_eq!(
        xdr.u32("nfsstat3"),
        0,
        "GETATTR must succeed; NFS3ERR here means the handler's action was rejected"
    );
    let attr = read_fattr3(&mut xdr);
    assert_eq!(xdr.remaining(), 0, "trailing bytes after fattr3");

    assert_eq!(attr.ftype, 2, "'directory' must encode as NF3DIR (2)");
    assert_eq!(attr.mode, 0o755, "the handler's mode must reach the client");
    assert_eq!(attr.size, 4096, "the handler's size must reach the client");
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.nlink, 1);
    assert_eq!(
        attr.mtime_seconds, 1_700_000_000,
        "the handler's mtime must reach the client"
    );
    assert_eq!(
        attr.fileid, 1,
        "the root's fileid is fixed at 1 by the server, not taken from the handler"
    );
    println!("✓ GETATTR returned the handler's attributes: {attr:?}");

    // 4. LOOKUP readme.txt in the root. Success carries the new handle plus post-op
    //    attributes for both the object and the directory.
    let mut args = xdr_opaque(&root_fh);
    args.extend_from_slice(&xdr_opaque(b"readme.txt"));
    let lookup = rpc
        .call(NFS_PROGRAM, NFS_V3, NFSPROC3_LOOKUP, &args)
        .await?;
    let mut xdr = Xdr::new(&lookup);
    assert_eq!(
        xdr.u32("nfsstat3"),
        0,
        "LOOKUP must succeed; NFS3ERR_NOENT here means nfs_lookup_response was not accepted"
    );
    let file_fh = xdr.opaque("object file handle");
    assert!(!file_fh.is_empty(), "LOOKUP must return a file handle");
    assert_ne!(
        file_fh, root_fh,
        "the looked-up file must not share the directory's handle"
    );

    assert_eq!(
        xdr.u32("obj_attributes discriminant"),
        1,
        "post-op attributes for the object must be present"
    );
    let obj_attr = read_fattr3(&mut xdr);
    assert_eq!(
        obj_attr.fileid, 42,
        "the fileid the handler chose in nfs_lookup_response must reach the client"
    );

    assert_eq!(
        xdr.u32("dir_attributes discriminant"),
        1,
        "post-op attributes for the directory must be present"
    );
    let dir_attr = read_fattr3(&mut xdr);
    assert_eq!(dir_attr.fileid, 1, "the directory is still the root");
    assert_eq!(xdr.remaining(), 0, "trailing bytes after LOOKUP3resok");

    println!("✓ LOOKUP resolved readme.txt to fileid 42");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
