//! HDFS: a NameNode (Hadoop IPC version 9, ClientNamenodeProtocol) and a DataNode
//! (DataTransferProtocol version 28) in one server, on two listeners. Rust owns the wire; the
//! model decides which users may connect, what each directory contains (lazily, once per
//! directory, through `src/server/described_tree.rs`), and whether each change may happen.
//! File content is described in `src/server/described_disk.rs`'s vocabulary, cut into blocks of
//! the file's block size, and served by the DataNode with CRC32C chunk checksums; blocks a
//! client writes are verified, held, and committed into the namespace's in-memory overlay when
//! the model allows the completed file.
pub mod actions;
pub mod datanode;
pub mod namenode;
pub mod namespace;
pub mod proto;
pub mod rpc;
pub mod transfer;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::server::described_tree;
use crate::utils::wire_failure::WireFailure;
use anyhow::{ensure, Context, Result};
use namespace::{Namespace, Thrown};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_DATANODE_PORT: u16 = 9866;
pub const DEFAULT_REPLICATION: u16 = 1;
pub const DEFAULT_OWNER: &str = "hdfs";
pub const DEFAULT_GROUP: &str = "supergroup";
/// How long a call waits for a description or decision.
pub const DEFAULT_DECISION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_DECISION_TIMEOUT_SECS: u64 = 600;
/// The connection header (NameNode) or first op (DataNode) must arrive within this long.
pub const HEADER_DEADLINE: Duration = Duration::from_secs(30);
/// The rest of a frame, op or packet once its first byte has arrived.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(60);
/// A connection with no call or op for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Directories one call may have described on its way (a path's depth and a little more).
pub const MAX_DESCRIBES_PER_CALL: usize = described_tree::MAX_TREE_DEPTH + 2;
/// Directories one content summary may have described.
pub const MAX_DESCRIBES_PER_SUMMARY: usize = 256;
/// Bytes of a completed write shown to the model.
pub const DATA_PREVIEW: usize = 512;
/// Users whose admission is remembered.
pub const MAX_REMEMBERED_USERS: usize = 1024;

/// What the server was started with.
#[derive(Clone, Debug)]
pub struct Settings {
    pub datanode_port: Option<u16>,
    pub read_only: bool,
    pub timeout: Duration,
    pub namespace: namespace::Settings,
}

pub fn settings(ctx: &SpawnContext) -> Result<Settings> {
    let params = ctx.startup_params.as_ref();
    let datanode_port = match params
        .map(|p| p.get_optional_u64("datanode_port"))
        .transpose()?
        .flatten()
    {
        Some(p) => Some(u16::try_from(p).context("datanode_port is a port number (0-65535)")?),
        None => None,
    };
    let block_size = match params
        .map(|p| p.get_optional_u64("block_size"))
        .transpose()?
        .flatten()
    {
        Some(b) => namespace::check_block_size(b)?,
        None => namespace::DEFAULT_BLOCK_SIZE,
    };
    let replication = match params
        .map(|p| p.get_optional_u64("replication"))
        .transpose()?
        .flatten()
    {
        Some(r) => namespace::check_replication(r)?,
        None => DEFAULT_REPLICATION,
    };
    let name = |key: &str, default: &str| -> Result<String> {
        let v = params
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| default.to_string());
        ensure!(
            !v.is_empty()
                && v.len() <= namespace::MAX_PRINCIPAL_BYTES
                && !crate::utils::sanitize::has_controls(&v)
                && !v.contains([':', '/']),
            "{key} is a name of 1 to {} bytes without ':', '/' or controls",
            namespace::MAX_PRINCIPAL_BYTES
        );
        Ok(v)
    };
    let owner = name("owner", DEFAULT_OWNER)?;
    let group = name("group", DEFAULT_GROUP)?;
    let read_only = params
        .map(|p| p.get_optional_bool("read_only"))
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let timeout = params
        .map(|p| p.get_optional_u64("decision_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_DECISION_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_DECISION_TIMEOUT_SECS).contains(&timeout),
        "decision_timeout_secs is 1 to {MAX_DECISION_TIMEOUT_SECS}"
    );
    let max_overlay = params
        .map(|p| p.get_optional_u64("max_overlay_bytes"))
        .transpose()?
        .flatten()
        .unwrap_or(described_tree::DEFAULT_MAX_OVERLAY_BYTES);
    ensure!(
        max_overlay <= described_tree::MAX_OVERLAY_LIMIT,
        "max_overlay_bytes is at most {}",
        described_tree::MAX_OVERLAY_LIMIT
    );
    Ok(Settings {
        datanode_port,
        read_only,
        timeout: Duration::from_secs(timeout),
        namespace: namespace::Settings {
            block_size,
            replication,
            owner,
            group,
            max_overlay,
        },
    })
}

/// Whether a remembered user may connect.
#[derive(Clone, Debug)]
pub enum Admission {
    Allowed,
    Denied(&'static str, String),
}

/// Shared by every connection of one server.
pub struct Hdfs {
    pub ctx: Arc<SpawnContext>,
    pub settings: Settings,
    pub ns: Mutex<Namespace>,
    /// One model question at a time: a change is planned, asked about and applied under it,
    /// and a directory is described once however many calls wanted it.
    pub gate: tokio::sync::Mutex<()>,
    pub users: Mutex<HashMap<String, Admission>>,
    pub datanode_port: u16,
    pub datanode_uuid: String,
}

impl Hdfs {
    pub fn ns(&self) -> std::sync::MutexGuard<'_, Namespace> {
        self.ns.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn users(&self) -> std::sync::MutexGuard<'_, HashMap<String, Admission>> {
        self.users.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The DataNode as a client reaches it: at the address it reached the NameNode on.
    pub fn datanode_info(&self, local: SocketAddr) -> proto::hdfs::DatanodeInfoProto {
        let ns = self.ns();
        let used = ns.tree.overlay_bytes() + ns.reserved();
        Namespace::datanode(
            &local.ip().to_string(),
            self.datanode_port,
            &self.datanode_uuid,
            ns.tree.max_overlay(),
            used,
        )
    }

    /// Log how a decision went, in the `decision=` vocabulary every server shares.
    pub fn outcome(&self, who: &str, op: &str, path: &str, decision: &str, detail: &str) {
        let summary = format!(
            "HDFS {who} operation={op} path={} decision={decision} {}",
            crate::utils::sanitize::token(path, 512),
            crate::utils::sanitize::strip_controls(detail)
        );
        let log = Log::new(Some(&self.ctx.status_tx));
        if decision.starts_with("fail_closed_") || decision == "model_silent" {
            log.error(summary);
        } else if decision == "protocol_refusal"
            || decision == "model_reject"
            || decision == "read_only"
        {
            log.info(summary);
        } else {
            log.debug(summary);
        }
    }

    /// One model call that must produce exactly one answer of an allowed type.
    pub async fn ask(
        &self,
        connection: ConnectionId,
        event: &Event,
        allowed: &[&str],
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Value, Failure> {
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        let call = call_llm(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.server_id,
            Some(connection),
            event,
            &actions::HdfsProtocol,
        );
        let result = match tokio::time::timeout_at(deadline, call).await {
            Err(_) => return Err(Failure::Deadline),
            Ok(Err(e)) => return Err(Failure::Llm(WireFailure::classify(&e))),
            Ok(Ok(r)) => r,
        };
        let mut answers = Vec::new();
        let why = result.failure_summary();
        let mut queue = result.protocol_results;
        while let Some(r) = queue.pop() {
            match r {
                ActionResult::Custom { data, .. } => answers.push(data),
                ActionResult::Multiple(items) => queue.extend(items),
                _ => {}
            }
        }
        if answers.is_empty() && result.failures.is_empty() {
            return Err(Failure::Silent);
        }
        if answers.len() != 1 || !result.failures.is_empty() {
            return Err(Failure::Invalid(match why {
                Some(why) => format!("not exactly one valid answer: {why}"),
                None => "not exactly one valid answer".into(),
            }));
        }
        let answer = answers.remove(0);
        let kind = answer["type"].as_str().unwrap_or_default();
        if !allowed.contains(&kind) {
            return Err(Failure::Invalid(format!(
                "{kind} does not answer this event (expected {})",
                allowed.join(" or ")
            )));
        }
        Ok(answer)
    }
}

/// Why a model decision did not produce an answer.
#[derive(Debug)]
pub enum Failure {
    Deadline,
    Llm(WireFailure),
    Silent,
    Invalid(String),
}

impl Failure {
    /// What the client is told: never the error itself.
    pub fn thrown(&self) -> Thrown {
        match self {
            Failure::Llm(WireFailure::Overloaded) => Thrown::new(
                rpc::class::RETRIABLE,
                "The NameNode is busy deciding; retry",
            ),
            Failure::Deadline => {
                Thrown::new(rpc::class::IO, "The NameNode could not decide in time")
            }
            _ => Thrown::new(rpc::class::IO, "The NameNode could not decide"),
        }
    }
    pub fn decision(&self) -> &'static str {
        match self {
            Failure::Deadline => "fail_closed_deadline",
            Failure::Llm(_) => "fail_closed_llm_error",
            Failure::Silent => "model_silent",
            Failure::Invalid(_) => "fail_closed_invalid_reply",
        }
    }
    pub fn detail(&self) -> String {
        match self {
            Failure::Deadline => "no answer before decision_timeout_secs".into(),
            Failure::Llm(_) => "the model backend failed".into(),
            Failure::Silent => "no answer".into(),
            Failure::Invalid(why) => why.clone(),
        }
    }
}

async fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let settings = settings(&ctx)?;
    let listener = bind(ctx.legacy_listen_addr())
        .await
        .with_context(|| format!("binding the NameNode port {}", ctx.legacy_listen_addr()))?;
    let local = listener.local_addr()?;
    let log = Log::new(Some(&ctx.status_tx));
    let dn_addr = |port: u16| SocketAddr::new(local.ip(), port);
    let dn_listener = match settings.datanode_port {
        Some(p) => bind(dn_addr(p))
            .await
            .with_context(|| format!("binding the DataNode port {}", dn_addr(p)))?,
        None => match bind(dn_addr(DEFAULT_DATANODE_PORT)).await {
            Ok(l) => l,
            Err(e) => {
                log.info(format!(
                    "HDFS DataNode: the default port {DEFAULT_DATANODE_PORT} is unavailable ({e}); using an OS-assigned port, which every block location names"
                ));
                bind(dn_addr(0)).await.context("binding the DataNode")?
            }
        },
    };
    let dn_local = dn_listener.local_addr()?;
    let uuid = uuid::Uuid::new_v4().to_string();
    let born = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pool_id = format!("BP-netget-{}-{}", local.ip(), born);
    let hdfs = Arc::new(Hdfs {
        ctx: Arc::new(ctx.clone()),
        ns: Mutex::new(Namespace::new(settings.namespace.clone(), pool_id)),
        settings,
        gate: tokio::sync::Mutex::new(()),
        users: Mutex::new(HashMap::new()),
        datanode_port: dn_local.port(),
        datanode_uuid: uuid,
    });
    log.info(format!("HDFS NameNode on {local}, DataNode on {dn_local}"));
    let nn = tokio::spawn(namenode::accept_loop(listener, hdfs.clone()));
    ctx.state.register_server_task(ctx.server_id, nn).await;
    let dn = tokio::spawn(datanode::accept_loop(dn_listener, hdfs.clone()));
    ctx.state.register_server_task(ctx.server_id, dn).await;
    Ok(local)
}

/// The first bytes of a completed write as text when they are text, else as hex, never raw.
pub fn preview(data: &[u8], total: u64) -> (String, &'static str, bool) {
    let cut = &data[..data.len().min(DATA_PREVIEW)];
    let text = match std::str::from_utf8(cut) {
        Ok(s) => Some(s),
        // A character cut in half at the end of the preview is still text.
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&cut[..e.valid_up_to()]).ok(),
        Err(_) => None,
    };
    match text {
        Some(s) if crate::utils::sanitize::multiline(s) == s => {
            (s.to_string(), "utf8", total > s.len() as u64)
        }
        _ => {
            let n = cut.len().min(DATA_PREVIEW / 2);
            (hex::encode(&cut[..n]), "hex", total > n as u64)
        }
    }
}
