//! NFSv3 server built on `nfsserve`, with the filesystem supplied entirely by the LLM.
//!
//! `nfsserve` owns RPC, XDR and the MOUNT protocol; `LlmNfsFileSystem` below implements its
//! `NFSFileSystem` trait by raising an `nfs_operation` event for every procedure and reading
//! the answer out of the model's response action. **There is no storage here** - no file
//! table, no directory tree, no attribute cache. Consistency across calls (a file ID meaning
//! the same file twice, a directory listing matching what lookup returns) is the model's
//! responsibility, which is why the server instruction carries so much weight.
//!
//! Two consequences worth knowing before using it:
//!
//! - **One model round-trip per NFS procedure.** A `ls` is several. Real workloads are
//!   impractically slow; script or static handlers are the answer for anything repetitive.
//! - **Text only.** File contents travel as UTF-8 strings in JSON actions because actions must
//!   not carry raw bytes or base64. Outbound data is written verbatim; inbound writes go
//!   through `String::from_utf8_lossy`, so a client writing binary hands the model U+FFFD.
//!   Binary files cannot be served or received faithfully, and there is no encoded fallback.
//!
//! A third thing worth knowing before reading `spawn_with_llm_actions`: **NetGet owns the
//! listening socket, not `nfsserve`.** The crate sizes buffers from a wire-supplied length
//! with no cap, which made a forty-byte unauthenticated MOUNT a whole-process denial of
//! service, and `NFSTcpListener` exposes no seam to fix that inside it. So `nfsserve` runs on
//! a loopback-only ephemeral port and every connection is relayed to it through
//! [`guard::serve_screened`], which refuses over-long RPC records before the crate sees them.
pub mod actions;
pub mod guard;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use async_trait::async_trait;
#[cfg(unix)]
use nfsserve::nfs::{fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3};
#[cfg(unix)]
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::NfsProtocol;
use crate::state::app_state::AppState;
use actions::NFS_OPERATION_EVENT;

/// NFS server that provides LLM-controlled file system
pub struct NfsServer;

impl NfsServer {
    /// Spawn NFS server with integrated LLM actions
    #[cfg(unix)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        use nfsserve::tcp::{NFSTcp, NFSTcpListener};

        Log::new(Some(&status_tx)).info(format!(
            "NFS server (LLM-controlled) starting on {}",
            listen_addr
        ));

        let protocol = Arc::new(NfsProtocol::new());

        // Create LLM-controlled filesystem
        let filesystem = LlmNfsFileSystem::new(
            llm_client,
            app_state.clone(),
            server_id,
            protocol,
            status_tx.clone(),
        );

        // The public listener is ours. `nfsserve` gets a loopback-only ephemeral port and
        // never sees a byte that `guard` has not already sized - see `guard`'s module docs
        // for what the crate does with an unchecked length, and why there is no way to fix
        // it in place.
        let public = tokio::net::TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("Failed to bind NFS listener on {}", listen_addr))?;
        let actual_addr = public
            .local_addr()
            .context("Failed to read the NFS listener's address")?;

        let nfs_listener = NFSTcpListener::bind("127.0.0.1:0", filesystem)
            .await
            .context("Failed to bind the internal NFS backend listener")?;
        let backend_addr: SocketAddr =
            SocketAddr::from(([127, 0, 0, 1], nfs_listener.get_listen_port()));

        Log::new(Some(&status_tx)).info(format!(
            "NFS server listening on {} (record screen in front of nfsserve on {})",
            actual_addr, backend_addr
        ));

        // Spawn server handler
        let backend_status_tx = status_tx.clone();
        let backend_handle = tokio::spawn(async move {
            info!("NFS server handler started");

            // Handle connections forever (nfsserve manages connections internally)
            if let Err(e) = nfs_listener.handle_forever().await {
                Log::new(Some(&backend_status_tx)).error(format!("NFS server error: {}", e));
            }
        });

        // Register the accept loops so stop_server can abort them and release the ports.
        app_state
            .register_server_task(server_id, backend_handle)
            .await;

        let screen_state = app_state.clone();
        let screen_handle = tokio::spawn(async move {
            guard::serve_screened(public, backend_addr, screen_state, server_id, status_tx).await;
        });
        app_state
            .register_server_task(server_id, screen_handle)
            .await;

        Ok(actual_addr)
    }

    /// Spawn NFS server without the nfs feature (fallback)
    #[cfg(not(unix))]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        Log::new(Some(&status_tx)).error("NFS feature not enabled at compile time");
        Err(anyhow::anyhow!("NFS feature not enabled"))
    }
}

/// LLM-controlled NFS filesystem implementation
#[cfg(unix)]
pub struct LlmNfsFileSystem {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    server_id: crate::state::ServerId,
    protocol: Arc<NfsProtocol>,
    status_tx: mpsc::UnboundedSender<String>,
}

#[cfg(unix)]
impl LlmNfsFileSystem {
    /// Create a new LLM-controlled NFS filesystem
    pub fn new(
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: crate::state::ServerId,
        protocol: Arc<NfsProtocol>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Self {
        Self {
            llm_client,
            app_state,
            server_id,
            protocol,
            status_tx,
        }
    }

    /// Consult the LLM for NFS operations
    async fn consult_llm(
        &self,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        Log::new(Some(&self.status_tx)).debug(format!(
            "Consulting LLM for NFS {} operation: {:?}",
            operation, params
        ));

        // Create NFS operation event
        let event = Event::new(
            &NFS_OPERATION_EVENT,
            serde_json::json!({
                "operation": operation,
                "params": params
            }),
        );

        Log::new(Some(&self.status_tx))
            .trace(format!("Calling LLM for NFS {} operation", operation));

        // Call LLM with Event-based approach
        let execution_result = call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            None, // NFS doesn't use connection-specific context
            &event,
            self.protocol.as_ref(),
        )
        .await?;

        // Display messages from LLM
        let log = Log::new(Some(&self.status_tx));
        for message in &execution_result.messages {
            log.info(message);
        }

        debug!(
            "LLM returned {} actions for NFS {}",
            execution_result.raw_actions.len(),
            operation
        );

        // Return raw actions for manual processing
        Ok(execution_result.raw_actions)
    }

    /// Answer the client in NFS's own vocabulary when the LLM backend fails.
    ///
    /// Fail closed, and answer. `nfsserve` turns the returned status into a well-formed reply
    /// - MSG_ACCEPTED / SUCCESS at the RPC layer, carrying the call's own xid, with this
    /// status as the procedure result - so the client sees a failed operation instead of
    /// hanging until its own RPC timeout. Nothing here can fabricate a success.
    ///
    /// The status is deliberately *not* one of the definite ones. Returning NFS3ERR_NOENT
    /// when the server could not even ask the model tells the client "that file does not
    /// exist", which it will cache and act on. RFC 1813 has a status for exactly this
    /// situation: NFS3ERR_SERVERFAULT (10006), "an error occurred on the server which does
    /// not map to any of the legal NFS version 3 protocol error values".
    ///
    /// An overload is retryable and NFSv3 can say so, so `is_overload_error` is answered with
    /// NFS3ERR_JUKEBOX (10008) - "resource temporarily unavailable, try again later" - which
    /// is the NFS equivalent of the 503 + `Retry-After` the HTTP server sends.
    fn llm_failure(&self, operation: &str, e: &anyhow::Error) -> nfsstat3 {
        let log = Log::new(Some(&self.status_tx));
        if crate::llm::is_overload_error(e) {
            log.error(format!(
                "NFS {}: LLM overloaded ({}) - answered NFS3ERR_JUKEBOX, client may retry",
                operation, e
            ));
            nfsstat3::NFS3ERR_JUKEBOX
        } else {
            log.error(format!(
                "NFS {}: LLM call failed ({}) - answered NFS3ERR_SERVERFAULT",
                operation, e
            ));
            nfsstat3::NFS3ERR_SERVERFAULT
        }
    }

    /// The model answered, but with nothing this operation can use.
    ///
    /// Structurally distinct from a model *rejection*: an action carrying `"error"` is the
    /// model saying no, and still maps to the operation's own status (NFS3ERR_NOENT,
    /// NFS3ERR_ACCES, ...). Silence is not a no, and must not be reported to the client as
    /// one, so it lands on NFS3ERR_SERVERFAULT alongside a backend failure.
    fn llm_no_answer(&self, operation: &str, expected: &str) -> nfsstat3 {
        Log::new(Some(&self.status_tx)).error(format!(
            "NFS {}: no {} action in LLM response - answered NFS3ERR_SERVERFAULT",
            operation, expected
        ));
        nfsstat3::NFS3ERR_SERVERFAULT
    }

    /// Parse file type from LLM response
    fn parse_ftype(&self, file_type: &str) -> ftype3 {
        match file_type {
            "regular" | "file" => ftype3::NF3REG,
            "directory" | "dir" => ftype3::NF3DIR,
            "symlink" | "link" => ftype3::NF3LNK,
            "block" => ftype3::NF3BLK,
            "char" => ftype3::NF3CHR,
            "socket" => ftype3::NF3SOCK,
            "fifo" => ftype3::NF3FIFO,
            _ => ftype3::NF3REG, // Default to regular file
        }
    }

    /// Parse NFS timestamp
    fn parse_nfstime(&self, timestamp: Option<u64>) -> nfstime3 {
        let ts = timestamp.unwrap_or_else(|| {
            // unwrap_or_default rather than unwrap: a clock set before 1970 would otherwise
            // panic inside a connection task, where the panic is silent and the server keeps
            // reporting Running.
            crate::utils::clock::SystemTime::now()
                .duration_since(crate::utils::clock::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        nfstime3 {
            seconds: ts as u32,
            nseconds: 0,
        }
    }

    /// Build fattr3 from LLM response
    fn build_fattr3(&self, response: &serde_json::Value) -> Result<fattr3> {
        let file_type = response
            .get("file_type")
            .and_then(|v| v.as_str())
            .unwrap_or("regular");

        let mode = response
            .get("mode")
            .and_then(|v| v.as_u64())
            .unwrap_or(0o644) as u32;

        let size = response.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

        let uid = response.get("uid").and_then(|v| v.as_u64()).unwrap_or(1000) as u32;

        let gid = response.get("gid").and_then(|v| v.as_u64()).unwrap_or(1000) as u32;

        let atime = self.parse_nfstime(response.get("atime").and_then(|v| v.as_u64()));
        let mtime = self.parse_nfstime(response.get("mtime").and_then(|v| v.as_u64()));
        let ctime = self.parse_nfstime(response.get("ctime").and_then(|v| v.as_u64()));

        Ok(fattr3 {
            ftype: self.parse_ftype(file_type),
            mode,
            nlink: 1,
            uid,
            gid,
            size,
            used: size,
            rdev: nfsserve::nfs::specdata3 {
                specdata1: 0,
                specdata2: 0,
            },
            fsid: 0,
            fileid: response.get("fileid").and_then(|v| v.as_u64()).unwrap_or(0),
            atime,
            mtime,
            ctime,
        })
    }
}

#[cfg(unix)]
#[async_trait]
impl NFSFileSystem for LlmNfsFileSystem {
    fn root_dir(&self) -> fileid3 {
        // Root directory is always fileid 1
        1
    }

    fn capabilities(&self) -> nfsserve::vfs::VFSCapabilities {
        // Enable all capabilities since LLM controls everything
        nfsserve::vfs::VFSCapabilities::ReadWrite
    }

    /// Resolve a MOUNT `dirpath` to a file id, bounded at [`guard::MAX_PATH_COMPONENTS`].
    ///
    /// The default implementation in `nfsserve`'s `NFSFileSystem` splits the path on `/` and
    /// calls `lookup()` once per component, with no limit. In this server every `lookup` is
    /// one LLM round-trip, so an **unauthenticated** `MOUNTPROC3_MNT` carrying
    /// `a/a/a/a/...` — two bytes per component — turned one forty-byte call into a sequential
    /// chain of thousands of model calls, saturating `--llm-max-concurrent` for every other
    /// server in the process. That is the amplification half of the `nfsserve` denial of
    /// service; the framing half lives in [`guard`].
    ///
    /// Refuse, do not truncate: resolving the first 32 components of a longer path would hand
    /// back the id of a directory the client did not ask for. `mount_handlers` turns any `Err`
    /// into `MNT3ERR_NOENT`, so the peer gets a definite refusal on the wire and the reason is
    /// in the log under a `decision=` tag.
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3> {
        let components: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();

        if components.len() > guard::MAX_PATH_COMPONENTS {
            Log::new(Some(&self.status_tx)).error(format!(
                "NFS path_to_id: refused a {}-component path decision=fail_closed_path_components \
                 (limit {}) - each component is one LLM call",
                components.len(),
                guard::MAX_PATH_COMPONENTS
            ));
            return Err(nfsstat3::NFS3ERR_NAMETOOLONG);
        }

        let mut fid = self.root_dir();
        for component in components {
            fid = self.lookup(fid, &component.into()).await?;
        }
        Ok(fid)
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        // Convert filename to string
        let filename_str = String::from_utf8_lossy(filename).to_string();

        let params = serde_json::json!({
            "dirid": dirid,
            "filename": filename_str,
        });

        // Call async LLM consultation directly
        let result = self.consult_llm("lookup", params).await;

        match result {
            Ok(actions) => {
                // Find nfs_lookup_response action
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_lookup_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS lookup failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_NOENT);
                        }

                        if let Some(fileid) = action.get("fileid").and_then(|v| v.as_u64()) {
                            debug!("NFS lookup found fileid: {}", fileid);
                            return Ok(fileid);
                        }
                    }
                }
                Err(self.llm_no_answer("lookup", "nfs_lookup_response"))
            }
            Err(e) => Err(self.llm_failure("lookup", &e)),
        }
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let params = serde_json::json!({
            "fileid": id,
        });

        let result = self.consult_llm("getattr", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_getattr_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS getattr failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_NOENT);
                        }

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = id; // Ensure fileid matches request
                                debug!("NFS getattr succeeded for fileid {}", id);
                                return Ok(attrs);
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("getattr", "nfs_getattr_response"))
            }
            Err(e) => Err(self.llm_failure("getattr", &e)),
        }
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        use nfsserve::nfs::{set_gid3, set_mode3, set_size3, set_uid3};

        // Convert NFS optional enums to Option for JSON serialization
        let mode_val = match setattr.mode {
            set_mode3::mode(v) => Some(v as u64),
            set_mode3::Void => None,
        };
        let uid_val = match setattr.uid {
            set_uid3::uid(v) => Some(v as u64),
            set_uid3::Void => None,
        };
        let gid_val = match setattr.gid {
            set_gid3::gid(v) => Some(v as u64),
            set_gid3::Void => None,
        };
        let size_val = match setattr.size {
            set_size3::size(v) => Some(v),
            set_size3::Void => None,
        };

        let params = serde_json::json!({
            "fileid": id,
            "mode": mode_val,
            "uid": uid_val,
            "gid": gid_val,
            "size": size_val,
        });

        let result = self.consult_llm("setattr", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_setattr_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS setattr failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = id;
                                debug!("NFS setattr succeeded for fileid {}", id);
                                return Ok(attrs);
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("setattr", "nfs_setattr_response"))
            }
            Err(e) => Err(self.llm_failure("setattr", &e)),
        }
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let params = serde_json::json!({
            "fileid": id,
            "offset": offset,
            "count": count,
        });

        let result = self.consult_llm("read", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_read_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS read failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        // `data` is declared `required: true`. Defaulting it to "" made a
                        // response that omitted it a *successful* read of an empty file —
                        // the fail-open shape, since a client cannot tell that from a file
                        // that is genuinely empty. `remove` and `rename` already refuse in
                        // this situation; so does this now. A genuinely empty file is still
                        // expressible as `"data": ""`, which is a decision rather than a
                        // silence.
                        let Some(data) = action.get("data").and_then(|v| v.as_str()) else {
                            warn!(
                                "NFS read: nfs_read_response for fileid {} omitted the required \
                                 `data` field (decision=fail_closed_no_data); refusing rather \
                                 than reporting a successful read of an empty file",
                                id
                            );
                            return Err(nfsstat3::NFS3ERR_SERVERFAULT);
                        };
                        let data = data.as_bytes().to_vec();

                        let eof = action.get("eof").and_then(|v| v.as_bool()).unwrap_or(true);

                        debug!(
                            "NFS read {} bytes from fileid {}, eof={}",
                            data.len(),
                            id,
                            eof
                        );
                        return Ok((data, eof));
                    }
                }
                Err(self.llm_no_answer("read", "nfs_read_response"))
            }
            Err(e) => Err(self.llm_failure("read", &e)),
        }
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        // Lossy on purpose - actions carry no binary form. Non-UTF-8 bytes reach the model as
        // U+FFFD and cannot be recovered; see the module docs.
        let data_str = String::from_utf8_lossy(data).to_string();
        let params = serde_json::json!({
            "fileid": id,
            "offset": offset,
            "data": data_str,
            "size": data.len(),
        });

        let result = self.consult_llm("write", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_write_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS write failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = id;
                                debug!("NFS write {} bytes to fileid {}", data.len(), id);
                                return Ok(attrs);
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("write", "nfs_write_response"))
            }
            Err(e) => Err(self.llm_failure("write", &e)),
        }
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        use nfsserve::nfs::{set_gid3, set_mode3, set_uid3};

        let filename_str = String::from_utf8_lossy(filename).to_string();
        let mode_val = match attr.mode {
            set_mode3::mode(v) => Some(v as u64),
            set_mode3::Void => None,
        };
        let uid_val = match attr.uid {
            set_uid3::uid(v) => Some(v as u64),
            set_uid3::Void => None,
        };
        let gid_val = match attr.gid {
            set_gid3::gid(v) => Some(v as u64),
            set_gid3::Void => None,
        };

        let params = serde_json::json!({
            "dirid": dirid,
            "filename": filename_str,
            "mode": mode_val,
            "uid": uid_val,
            "gid": gid_val,
        });

        let result = self.consult_llm("create", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_create_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS create failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        // `fileid` is declared `required: true`. Defaulting it to 0 let a
                        // response that omitted it report a successful CREATE carrying the
                        // one fileid NFS treats as invalid, which a client then caches.
                        let Some(fileid) = action.get("fileid").and_then(|v| v.as_u64()) else {
                            warn!(
                                "NFS create: nfs_create_response for {} omitted the required \
                                 `fileid` (decision=fail_closed_no_fileid); refusing rather \
                                 than reporting success with the invalid fileid 0",
                                filename_str
                            );
                            return Err(nfsstat3::NFS3ERR_SERVERFAULT);
                        };

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = fileid;
                                debug!(
                                    "NFS create succeeded: {} with fileid {}",
                                    filename_str, fileid
                                );
                                return Ok((fileid, attrs));
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("create", "nfs_create_response"))
            }
            Err(e) => Err(self.llm_failure("create", &e)),
        }
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        // Create exclusive is like create but fails if file exists
        let filename_str = String::from_utf8_lossy(filename).to_string();
        let params = serde_json::json!({
            "dirid": dirid,
            "filename": filename_str,
            "exclusive": true,
        });

        let result = self.consult_llm("create", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_create_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS create_exclusive failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_EXIST);
                        }

                        if let Some(fileid) = action.get("fileid").and_then(|v| v.as_u64()) {
                            debug!(
                                "NFS create_exclusive succeeded: {} with fileid {}",
                                filename_str, fileid
                            );
                            return Ok(fileid);
                        }
                    }
                }
                Err(self.llm_no_answer("create", "nfs_create_response"))
            }
            Err(e) => Err(self.llm_failure("create_exclusive", &e)),
        }
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let dirname_str = String::from_utf8_lossy(dirname).to_string();
        let params = serde_json::json!({
            "dirid": dirid,
            "dirname": dirname_str,
        });

        let result = self.consult_llm("mkdir", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_mkdir_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS mkdir failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        // `nfs_mkdir_response` documents `fileid`, and that is what a model
                        // following the action definition sends. This used to read `dirid`
                        // only, so every documented response yielded fileid 0 and the client
                        // got a directory it could not then look into. `dirid` is still
                        // accepted for anything that learned the old shape.
                        let fileid = action
                            .get("fileid")
                            .or_else(|| action.get("dirid"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = fileid;
                                attrs.ftype = ftype3::NF3DIR; // Ensure it's a directory
                                debug!(
                                    "NFS mkdir succeeded: {} with dirid {}",
                                    dirname_str, fileid
                                );
                                return Ok((fileid, attrs));
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("mkdir", "nfs_mkdir_response"))
            }
            Err(e) => Err(self.llm_failure("mkdir", &e)),
        }
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let filename_str = String::from_utf8_lossy(filename).to_string();
        let params = serde_json::json!({
            "dirid": dirid,
            "filename": filename_str,
        });

        let result = self.consult_llm("remove", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_remove_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS remove failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_NOENT);
                        }

                        // `success` is declared `required: true` on this action and was never
                        // read: only a non-empty `error` string produced a failure, so
                        // `{"type": "nfs_remove_response", "success": false}` — the obvious way
                        // for a model to refuse a delete — was reported to the client as a
                        // completed removal. Honour it, and refuse when it is absent rather
                        // than assuming the file went away.
                        match action.get("success").and_then(|v| v.as_bool()) {
                            Some(true) => {
                                debug!("NFS remove succeeded: {}", filename_str);
                                return Ok(());
                            }
                            Some(false) => {
                                debug!(
                                    "NFS remove refused by handler for {} \
                                     (decision=model_reject)",
                                    filename_str
                                );
                                return Err(nfsstat3::NFS3ERR_ACCES);
                            }
                            None => {
                                warn!(
                                    "NFS remove: nfs_remove_response for {} omitted the required \
                                     `success` boolean (decision=fail_closed_no_success); \
                                     refusing rather than assuming the file was removed",
                                    filename_str
                                );
                                return Err(nfsstat3::NFS3ERR_SERVERFAULT);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("remove", "nfs_remove_response"))
            }
            Err(e) => Err(self.llm_failure("remove", &e)),
        }
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let from_name = String::from_utf8_lossy(from_filename).to_string();
        let to_name = String::from_utf8_lossy(to_filename).to_string();
        let params = serde_json::json!({
            "from_dirid": from_dirid,
            "from_filename": from_name,
            "to_dirid": to_dirid,
            "to_filename": to_name,
        });

        let result = self.consult_llm("rename", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_rename_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS rename failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        // Same defect as `remove`: `success` is declared required on
                        // `nfs_rename_response` and was never read, so a model refusing with
                        // `success: false` renamed the file anyway as far as the client knew.
                        match action.get("success").and_then(|v| v.as_bool()) {
                            Some(true) => {
                                debug!("NFS rename succeeded: {} -> {}", from_name, to_name);
                                return Ok(());
                            }
                            Some(false) => {
                                debug!(
                                    "NFS rename refused by handler for {} -> {} \
                                     (decision=model_reject)",
                                    from_name, to_name
                                );
                                return Err(nfsstat3::NFS3ERR_ACCES);
                            }
                            None => {
                                warn!(
                                    "NFS rename: nfs_rename_response for {} -> {} omitted the \
                                     required `success` boolean \
                                     (decision=fail_closed_no_success); refusing rather than \
                                     assuming the rename happened",
                                    from_name, to_name
                                );
                                return Err(nfsstat3::NFS3ERR_SERVERFAULT);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("rename", "nfs_rename_response"))
            }
            Err(e) => Err(self.llm_failure("rename", &e)),
        }
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let params = serde_json::json!({
            "dirid": dirid,
            "start_after": start_after,
            "max_entries": max_entries,
        });

        let result = self.consult_llm("readdir", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_readdir_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS readdir failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_NOTDIR);
                        }

                        // `entries` is declared `required: true`. Defaulting it to an empty
                        // array made a response that omitted it a successful enumeration of
                        // an empty directory — a positive assertion the handler never made.
                        // An actually-empty directory is still expressible as
                        // `"entries": []`.
                        let Some(entries_json) =
                            action.get("entries").and_then(|v| v.as_array()).cloned()
                        else {
                            warn!(
                                "NFS readdir: nfs_readdir_response omitted the required \
                                 `entries` array (decision=fail_closed_no_entries); refusing \
                                 rather than reporting the directory as empty"
                            );
                            return Err(nfsstat3::NFS3ERR_SERVERFAULT);
                        };

                        let mut entries = Vec::new();
                        for entry in entries_json {
                            let fileid = entry.get("fileid").and_then(|v| v.as_u64()).unwrap_or(0);

                            let name = entry
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .as_bytes()
                                .to_vec();

                            // Build attributes, use defaults if LLM didn't provide them
                            let mut attr =
                                match entry.get("attr").and_then(|v| self.build_fattr3(v).ok()) {
                                    Some(a) => a,
                                    None => {
                                        // Provide minimal default attributes
                                        fattr3 {
                                            ftype: ftype3::NF3REG,
                                            mode: 0o644,
                                            nlink: 1,
                                            uid: 1000,
                                            gid: 1000,
                                            size: 0,
                                            used: 0,
                                            rdev: nfsserve::nfs::specdata3 {
                                                specdata1: 0,
                                                specdata2: 0,
                                            },
                                            fsid: 0,
                                            fileid,
                                            atime: self.parse_nfstime(None),
                                            mtime: self.parse_nfstime(None),
                                            ctime: self.parse_nfstime(None),
                                        }
                                    }
                                };
                            attr.fileid = fileid; // Ensure fileid matches

                            entries.push(DirEntry {
                                fileid,
                                name: nfsserve::nfs::nfsstring(name),
                                attr,
                            });
                        }

                        // `nfs_readdir_response` documents `eof`; this used to read `end`
                        // only, so a model following the action definition always got the
                        // default. Both are accepted, documented name first.
                        let end = action
                            .get("eof")
                            .or_else(|| action.get("end"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);

                        debug!(
                            "NFS readdir returned {} entries, end={}",
                            entries.len(),
                            end
                        );
                        return Ok(ReadDirResult { entries, end });
                    }
                }
                Err(self.llm_no_answer("readdir", "nfs_readdir_response"))
            }
            Err(e) => Err(self.llm_failure("readdir", &e)),
        }
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        use nfsserve::nfs::set_mode3;

        let linkname_str = String::from_utf8_lossy(linkname).to_string();
        let target_str = String::from_utf8_lossy(symlink).to_string();
        let mode_val = match attr.mode {
            set_mode3::mode(v) => Some(v as u64),
            set_mode3::Void => None,
        };

        let params = serde_json::json!({
            "dirid": dirid,
            "linkname": linkname_str,
            "target": target_str,
            "mode": mode_val,
        });

        let result = self.consult_llm("symlink", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_create_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS symlink failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_ACCES);
                        }

                        let fileid = action.get("fileid").and_then(|v| v.as_u64()).unwrap_or(0);

                        match self.build_fattr3(&action) {
                            Ok(mut attrs) => {
                                attrs.fileid = fileid;
                                attrs.ftype = ftype3::NF3LNK; // Ensure it's a symlink
                                debug!("NFS symlink succeeded: {} -> {}", linkname_str, target_str);
                                return Ok((fileid, attrs));
                            }
                            Err(e) => {
                                error!("Failed to build fattr3: {}", e);
                                return Err(nfsstat3::NFS3ERR_IO);
                            }
                        }
                    }
                }
                Err(self.llm_no_answer("symlink", "nfs_create_response"))
            }
            Err(e) => Err(self.llm_failure("symlink", &e)),
        }
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let params = serde_json::json!({
            "fileid": id,
        });

        let result = self.consult_llm("readlink", params).await;

        match result {
            Ok(actions) => {
                for action in actions {
                    // Reuse nfs_read_response for readlink (returns target path in data field)
                    if action.get("type").and_then(|v| v.as_str()) == Some("nfs_read_response") {
                        if let Some(error) = action.get("error").and_then(|v| v.as_str()) {
                            debug!("NFS readlink failed: {}", error);
                            return Err(nfsstat3::NFS3ERR_INVAL);
                        }

                        let target_bytes = action
                            .get("data")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .as_bytes()
                            .to_vec();

                        debug!(
                            "NFS readlink for fileid {}: {}",
                            id,
                            String::from_utf8_lossy(&target_bytes)
                        );
                        return Ok(nfsserve::nfs::nfsstring(target_bytes));
                    }
                }
                Err(self.llm_no_answer("readlink", "nfs_read_response"))
            }
            Err(e) => Err(self.llm_failure("readlink", &e)),
        }
    }
}
