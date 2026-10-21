//! HDFS client. `connect()` opens a Hadoop IPC connection to the NameNode as the configured user
//! and raises `hdfs_connected` with the server's defaults; the model then lists, stats, reads,
//! writes and changes paths, one action at a time. Each result is raised as an event the model
//! (or a handler) answers, the chain bounded at [`MAX_FOLLOWUP_DEPTH`]. A NameNode exception
//! reaches the model as `hdfs_error` with its Java class and message.
pub mod actions;
pub mod blocks;
pub mod namenode;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::hdfs::proto::hdfs::{
    hdfs_file_status_proto::FileType, AddBlockRequestProto, AddBlockResponseProto,
    CompleteRequestProto, CompleteResponseProto, CreateFlagProto, CreateRequestProto,
    CreateResponseProto, DeleteRequestProto, DeleteResponseProto, ExtendedBlockProto,
    FsPermissionProto, GetBlockLocationsRequestProto, GetBlockLocationsResponseProto,
    GetFileInfoRequestProto, GetFileInfoResponseProto, GetListingRequestProto,
    GetListingResponseProto, GetServerDefaultsRequestProto, GetServerDefaultsResponseProto,
    HdfsFileStatusProto, MkdirsRequestProto, MkdirsResponseProto, Rename2RequestProto,
    Rename2ResponseProto, SetPermissionRequestProto, SetPermissionResponseProto,
};
pub use actions::HdfsClientProtocol;
use anyhow::{Context, Result};
use namenode::{CallError, NameNode};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// A handler chain (result → event → action …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 16;
pub const DEFAULT_USER: &str = "netget";
pub const DEFAULT_BLOCK_SIZE: u64 = 128 << 20;
/// Times `complete` is asked before the write is called failed (the NameNode answers false
/// until every block has reached its minimum replication).
pub const COMPLETE_ATTEMPTS: usize = 10;

async fn resolve(remote: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(remote)
        .await
        .with_context(|| format!("resolving {remote}"))?
        .next()
        .with_context(|| format!("{remote} resolves to no address"))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let user = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string("user"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| DEFAULT_USER.into());
    anyhow::ensure!(
        !user.is_empty()
            && user.len() <= 256
            && !crate::utils::sanitize::has_controls(&user)
            && !user.contains([':', '/']),
        "user is a name of 1 to 256 bytes without ':', '/' or controls"
    );
    let addr = resolve(&ctx.remote_addr).await?;
    let mut nn = NameNode::connect(addr, &user).await?;
    let defaults: GetServerDefaultsResponseProto = nn
        .call("getServerDefaults", &GetServerDefaultsRequestProto {})
        .await
        .map_err(|e| anyhow::anyhow!("the NameNode refused the first call: {e}"))?;
    let d = defaults.server_defaults;
    let checksum = crate::server::hdfs::transfer::Checksum::from_proto(d.checksum_type.unwrap_or(1))
        .map(|c| c.name())
        .unwrap_or("unknown");
    ctx.state
        .update_client_status(ctx.client_id, crate::state::ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, event_rx) = mpsc::channel::<(Event, usize)>(32);
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "remote_addr": addr.to_string(),
                "user": user,
                "server_defaults": {
                    "block_size": d.block_size,
                    "bytes_per_checksum": d.bytes_per_checksum,
                    "replication": d.replication,
                    "checksum_type": checksum,
                    "write_packet_size": d.write_packet_size,
                },
            }),
        ),
        0,
    ))?;
    let dispatcher = spawn_dispatcher(&ctx, event_rx, internal_tx).await;
    let run_ctx = ctx.clone();
    let client_name = format!(
        "NetGet_DFSClient_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let task = tokio::spawn(async move {
        let mut c = HdfsClient {
            ctx: &run_ctx,
            addr,
            user,
            client_name,
            nn: Some(nn),
            default_block_size: if d.block_size > 0 {
                d.block_size
            } else {
                DEFAULT_BLOCK_SIZE
            },
        };
        let result = c.run(external, internal_rx, event_tx).await;
        if let Some(mut nn) = c.nn.take() {
            nn.close().await;
        }
        dispatcher.abort();
        let status = match result {
            Ok(()) => crate::state::ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&run_ctx.status_tx)).warn(format!("HDFS client ended: {e:#}"));
                crate::state::ClientStatus::Error(e.to_string())
            }
        };
        run_ctx
            .state
            .update_client_status(run_ctx.client_id, status)
            .await;
        run_ctx.state.remove_client_handle(run_ctx.client_id).await;
        let _ = run_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(addr)
}

/// Events in, the model (or a handler) asked, its actions out with the depth they were
/// produced at. A failed call sends nothing: fail closed.
async fn spawn_dispatcher(
    ctx: &ConnectContext,
    mut events: mpsc::Receiver<(Event, usize)>,
    actions_tx: mpsc::Sender<(Value, usize)>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            let protocol = HdfsClientProtocol;
            while let Some((event, depth)) = events.recv().await {
                let instruction = ctx
                    .state
                    .get_instruction_for_client(ctx.client_id)
                    .await
                    .unwrap_or_default();
                let memory = ctx
                    .state
                    .get_memory_for_client(ctx.client_id)
                    .await
                    .unwrap_or_default();
                match call_llm_for_client(
                    &ctx.llm_client,
                    &ctx.state,
                    ctx.client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    &protocol,
                    &ctx.status_tx,
                )
                .await
                {
                    Ok(result) => {
                        if let Some(memory) = result.memory_updates {
                            ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                        }
                        for action in result.actions {
                            if actions_tx.send((action, depth + 1)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                        "HDFS client handler failed (nothing sent): decision=fail_closed_llm_error {e}"
                    )),
                }
            }
        }
    });
    let abort = task.abort_handle();
    ctx.state.register_client_task(ctx.client_id, task).await;
    abort
}

struct HdfsClient<'a> {
    ctx: &'a ConnectContext,
    addr: SocketAddr,
    user: String,
    client_name: String,
    nn: Option<NameNode>,
    default_block_size: u64,
}

/// A file status as the model reads it.
fn status_json(s: &HdfsFileStatusProto, name: &str) -> Value {
    let kind = match FileType::try_from(s.file_type) {
        Ok(FileType::IsDir) => "dir",
        Ok(FileType::IsSymlink) => "symlink",
        _ => "file",
    };
    let mut v = json!({
        "name": crate::utils::sanitize::line_field(name),
        "kind": kind,
        "length": s.length,
        "mode": s.permission.perm & 0o7777,
        "owner": crate::utils::sanitize::line_field(&s.owner),
        "group": crate::utils::sanitize::line_field(&s.group),
        "modification_time": s.modification_time,
        "access_time": s.access_time,
    });
    if kind == "file" {
        v["replication"] = json!(s.block_replication.unwrap_or(0));
        v["block_size"] = json!(s.blocksize.unwrap_or(0));
    }
    if let Some(t) = &s.symlink {
        v["symlink_target"] = json!(crate::utils::sanitize::line_field(&String::from_utf8_lossy(t)));
    }
    v
}

/// Read data as the model reads it: text when it is text, hex otherwise or when asked.
pub fn render(bytes: &[u8], want_hex: bool) -> (String, &'static str) {
    if !want_hex {
        if let Ok(text) = std::str::from_utf8(bytes) {
            if crate::utils::sanitize::multiline(text) == text {
                return (text.to_string(), "utf8");
            }
        }
    }
    (hex::encode(bytes), "hex")
}

impl HdfsClient<'_> {
    async fn run(
        &mut self,
        mut external: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        events: mpsc::Sender<(Event, usize)>,
    ) -> Result<()> {
        use crate::state::client_handles::ClientSendOutcome;
        let log = Log::new(Some(&self.ctx.status_tx));
        let protocol = HdfsClientProtocol;
        loop {
            let (action, depth, mut injected) = tokio::select! {
                command = external.recv() => match command {
                    Some(c) => (c.action.clone(), 0, Some(c)),
                    None => return Ok(()),
                },
                action = internal.recv() => match action {
                    Some((a, depth)) => (a, depth, None),
                    None => return Ok(()),
                },
            };
            let reply = |injected: &mut Option<crate::state::client_handles::ClientCommand>,
                         outcome: Result<ClientSendOutcome>| {
                if let Some(command) = injected.take() {
                    crate::client::command_support::reply(command, outcome);
                }
            };
            match protocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(&mut injected, Ok(ClientSendOutcome::Disconnected));
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("HDFS client action refused: {e:#}"));
                    reply(
                        &mut injected,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                    continue;
                }
            }
            if depth > MAX_FOLLOWUP_DEPTH {
                log.warn(format!(
                    "HDFS client: decision=followup_depth handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            if injected.is_some() {
                self.ctx
                    .state
                    .record_access_log(
                        crate::state::AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                        "HDFS",
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
            }
            let (event, data) = self.execute(&action).await;
            reply(
                &mut injected,
                Ok(ClientSendOutcome::Executed {
                    detail: data.to_string(),
                }),
            );
            anyhow::ensure!(
                events.try_send((Event::new(event, data), depth)).is_ok(),
                "HDFS event queue full; consumer stalled"
            );
        }
    }

    /// The NameNode connection, opened again if an earlier failure dropped it.
    async fn nn(&mut self) -> Result<&mut NameNode> {
        if self.nn.is_none() {
            self.nn = Some(NameNode::connect(self.addr, &self.user).await?);
        }
        Ok(self.nn.as_mut().expect("just opened"))
    }

    async fn call<Req: prost::Message, Resp: prost::Message + Default>(
        &mut self,
        method: &str,
        request: &Req,
    ) -> std::result::Result<Resp, CallError> {
        let nn = self.nn().await.map_err(CallError::Transport)?;
        let r = nn.call(method, request).await;
        if matches!(&r, Err(CallError::Transport(_)) | Err(CallError::Remote { fatal: true, .. })) {
            self.nn = None;
        }
        r
    }

    /// Run one action; the event to raise and its data.
    async fn execute(&mut self, action: &Value) -> (&'static EventType, Value) {
        let kind = action["type"].as_str().unwrap_or_default();
        let path = action["path"].as_str().unwrap_or_default().to_string();
        let operation = kind.trim_start_matches("hdfs_").to_string();
        let result = match kind {
            actions::LIST => self.list(&path, action).await,
            actions::STAT => self.stat(&path).await,
            actions::READ => self.read(&path, action).await,
            actions::WRITE => self.write(&path, action).await,
            _ => self.mutate(kind, &path, action).await,
        };
        match result {
            Ok(v) => v,
            Err(e) => {
                let (class, message) = match &e {
                    CallError::Remote { class, message, .. } => (class.clone(), message.clone()),
                    CallError::Transport(e) => (String::new(), format!("{e:#}")),
                };
                Log::new(Some(&self.ctx.status_tx)).info(format!(
                    "HDFS client {operation} {path}: {}",
                    crate::utils::sanitize::strip_controls(&format!("{class} {message}"))
                ));
                (
                    &actions::ERROR_EVENT,
                    json!({
                        "operation": operation,
                        "path": path,
                        "exception_class": crate::utils::sanitize::token(&class, 256),
                        "message": crate::utils::sanitize::multiline(&crate::utils::truncate::truncate_for_log(&message, 2048)),
                    }),
                )
            }
        }
    }

    async fn list(&mut self, path: &str, action: &Value) -> std::result::Result<(&'static EventType, Value), CallError> {
        let start_after = action["start_after"].as_str().unwrap_or_default();
        let r: GetListingResponseProto = self
            .call(
                "getListing",
                &GetListingRequestProto {
                    src: path.into(),
                    start_after: start_after.as_bytes().to_vec(),
                    need_location: false,
                },
            )
            .await?;
        let Some(list) = r.dir_list else {
            return Err(CallError::Remote {
                class: "java.io.FileNotFoundException".into(),
                message: format!("File {path} does not exist."),
                fatal: false,
            });
        };
        let shown: Vec<Value> = list
            .partial_listing
            .iter()
            .take(actions::MAX_LISTED)
            .map(|s| status_json(s, &String::from_utf8_lossy(&s.path)))
            .collect();
        let remaining = list.remaining_entries as usize
            + list.partial_listing.len().saturating_sub(shown.len());
        Ok((
            &actions::LISTING_EVENT,
            json!({"path": path, "entries": shown, "remaining": remaining}),
        ))
    }

    async fn stat(&mut self, path: &str) -> std::result::Result<(&'static EventType, Value), CallError> {
        let r: GetFileInfoResponseProto = self
            .call("getFileInfo", &GetFileInfoRequestProto { src: path.into() })
            .await?;
        let name = path.rsplit('/').next().unwrap_or_default();
        Ok((
            &actions::STATUS_EVENT,
            match r.fs {
                Some(s) => json!({"path": path, "exists": true, "status": status_json(&s, name)}),
                None => json!({"path": path, "exists": false}),
            },
        ))
    }

    async fn read(&mut self, path: &str, action: &Value) -> std::result::Result<(&'static EventType, Value), CallError> {
        let offset = action["offset"].as_u64().unwrap_or(0);
        let length = action["length"].as_u64().unwrap_or(actions::DEFAULT_READ);
        let r: GetBlockLocationsResponseProto = self
            .call(
                "getBlockLocations",
                &GetBlockLocationsRequestProto {
                    src: path.into(),
                    offset,
                    length,
                },
            )
            .await?;
        let located = r.locations.ok_or_else(|| CallError::Remote {
            class: "java.io.FileNotFoundException".into(),
            message: format!("File does not exist: {path}"),
            fatal: false,
        })?;
        let file_length = located.file_length;
        let end = offset.saturating_add(length).min(file_length);
        let mut data = Vec::new();
        let mut datanodes = Vec::new();
        let mut pos = offset;
        for b in &located.blocks {
            if pos >= end {
                break;
            }
            let block_len = b.b.num_bytes.unwrap_or(0);
            let (start, stop) = (b.offset, b.offset + block_len);
            if stop <= pos || start > pos {
                continue;
            }
            let dn = b.locs.first().ok_or_else(|| {
                CallError::Transport(anyhow::anyhow!("block {} has no location", b.b.block_id))
            })?;
            let addr = blocks::datanode_addr(dn, self.addr).map_err(CallError::Transport)?;
            let take = end.min(stop) - pos;
            let bytes = blocks::read(addr, b, &self.client_name, pos - start, take)
                .await
                .map_err(CallError::Transport)?;
            data.extend_from_slice(&bytes);
            datanodes.push(addr.to_string());
            pos += take;
        }
        if pos < end {
            return Err(CallError::Transport(anyhow::anyhow!(
                "the NameNode located no block for bytes {pos}..{end}"
            )));
        }
        let (text, encoding) = render(&data, action["encoding"] == "hex");
        Ok((
            &actions::READ_EVENT,
            json!({
                "path": path, "offset": offset, "bytes": data.len(), "data": text,
                "encoding": encoding, "file_length": file_length, "eof": end >= file_length,
                "datanodes": datanodes,
            }),
        ))
    }

    async fn write(&mut self, path: &str, action: &Value) -> std::result::Result<(&'static EventType, Value), CallError> {
        let data = actions::write_data(action).map_err(CallError::Transport)?;
        let overwrite = action["overwrite"].as_bool().unwrap_or(false);
        let mode = action["mode"].as_u64().unwrap_or(0o644) as u32;
        let replication = action["replication"].as_u64().unwrap_or(1) as u32;
        let block_size = action["block_size"].as_u64().unwrap_or(self.default_block_size);
        let mut flag = CreateFlagProto::Create as u32;
        if overwrite {
            flag |= CreateFlagProto::Overwrite as u32;
        }
        let created: CreateResponseProto = self
            .call(
                "create",
                &CreateRequestProto {
                    src: path.into(),
                    masked: FsPermissionProto { perm: mode },
                    client_name: self.client_name.clone(),
                    create_flag: flag,
                    create_parent: true,
                    replication,
                    block_size,
                    ..Default::default()
                },
            )
            .await?;
        let file_id = created.fs.as_ref().and_then(|s| s.file_id);
        let mut previous: Option<ExtendedBlockProto> = None;
        let mut datanodes = Vec::new();
        let mut written_blocks = 0usize;
        for piece in data.chunks(block_size.max(512) as usize) {
            let added: AddBlockResponseProto = self
                .call(
                    "addBlock",
                    &AddBlockRequestProto {
                        src: path.into(),
                        client_name: self.client_name.clone(),
                        previous: previous.clone(),
                        exclude_nodes: vec![],
                        file_id,
                        favored_nodes: vec![],
                        flags: vec![],
                    },
                )
                .await?;
            let (b, dn) = blocks::write(self.addr, &added.block, &self.client_name, piece)
                .await
                .map_err(CallError::Transport)?;
            datanodes.push(dn.to_string());
            previous = Some(b);
            written_blocks += 1;
        }
        let mut done = false;
        for attempt in 0..COMPLETE_ATTEMPTS {
            let c: CompleteResponseProto = self
                .call(
                    "complete",
                    &CompleteRequestProto {
                        src: path.into(),
                        client_name: self.client_name.clone(),
                        last: previous.clone(),
                        file_id,
                    },
                )
                .await?;
            if c.result {
                done = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100 << attempt.min(5))).await;
        }
        if !done {
            return Err(CallError::Transport(anyhow::anyhow!(
                "the NameNode did not complete {path} after {COMPLETE_ATTEMPTS} attempts"
            )));
        }
        Ok((
            &actions::WRITE_EVENT,
            json!({"path": path, "bytes": data.len(), "blocks": written_blocks, "datanodes": datanodes}),
        ))
    }

    async fn mutate(&mut self, kind: &str, path: &str, action: &Value) -> std::result::Result<(&'static EventType, Value), CallError> {
        let operation = kind.trim_start_matches("hdfs_");
        let mut data = json!({"operation": operation, "path": path});
        let result = match kind {
            actions::MKDIR => {
                let r: MkdirsResponseProto = self
                    .call(
                        "mkdirs",
                        &MkdirsRequestProto {
                            src: path.into(),
                            masked: FsPermissionProto {
                                perm: action["mode"].as_u64().unwrap_or(0o755) as u32,
                            },
                            create_parent: action["create_parent"].as_bool().unwrap_or(true),
                            unmasked: None,
                        },
                    )
                    .await?;
                r.result
            }
            actions::DELETE => {
                let r: DeleteResponseProto = self
                    .call(
                        "delete",
                        &DeleteRequestProto {
                            src: path.into(),
                            recursive: action["recursive"].as_bool().unwrap_or(false),
                        },
                    )
                    .await?;
                r.result
            }
            actions::RENAME => {
                let destination = action["destination"].as_str().unwrap_or_default();
                data["destination"] = json!(destination);
                let _: Rename2ResponseProto = self
                    .call(
                        "rename2",
                        &Rename2RequestProto {
                            src: path.into(),
                            dst: destination.into(),
                            overwrite_dest: action["overwrite"].as_bool().unwrap_or(false),
                            move_to_trash: Some(false),
                        },
                    )
                    .await?;
                true
            }
            actions::SET_PERMISSION => {
                let _: SetPermissionResponseProto = self
                    .call(
                        "setPermission",
                        &SetPermissionRequestProto {
                            src: path.into(),
                            permission: FsPermissionProto {
                                perm: action["mode"].as_u64().unwrap_or(0) as u32,
                            },
                        },
                    )
                    .await?;
                true
            }
            other => {
                return Err(CallError::Transport(anyhow::anyhow!(
                    "unknown operation {other}"
                )))
            }
        };
        data["result"] = json!(result);
        Ok((&actions::MUTATION_EVENT, data))
    }
}
