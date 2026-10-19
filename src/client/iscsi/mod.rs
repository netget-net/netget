//! iSCSI initiator client. The model decides what to discover, which target to log in to and
//! which SCSI commands to run; [`initiator`] runs the sessions. Each result is raised as an
//! event the model (or a handler) answers, the chain bounded at [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;
pub mod initiator;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::iscsi::chap::Credential;
use crate::server::iscsi::pdu::login_status;
use crate::server::iscsi::text::DigestPreference;
use crate::server::scsi_common::{self as scsi, status};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::IscsiClientProtocol;
use anyhow::{bail, Context, Result};
use initiator::{CommandOutcome, Kind, LoginConfig, Session};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// A handler chain (result → event → command …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 16;
pub const DEFAULT_INITIATOR_NAME: &str = "iqn.2026-10.net.netget:initiator";
pub const DEFAULT_DIGESTS: &str = "either";

/// The target portal's address, resolved once.
async fn resolve(remote: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(remote)
        .await
        .with_context(|| format!("resolving {remote}"))?
        .next()
        .with_context(|| format!("{remote} resolves to no address"))
}

fn credential(
    params: Option<&crate::protocol::StartupParams>,
    name_key: &str,
    secret_key: &str,
) -> Result<Option<Credential>> {
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    match (get(name_key)?, get(secret_key)?) {
        (Some(name), Some(secret)) => Ok(Some(Credential { name, secret })),
        (None, None) => Ok(None),
        (None, Some(secret)) if name_key == "target_chap_name" => Ok(Some(Credential {
            name: String::new(),
            secret,
        })),
        _ => bail!("{name_key} and {secret_key} go together"),
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let initiator_name = get("initiator_name")?.unwrap_or_else(|| DEFAULT_INITIATOR_NAME.into());
    anyhow::ensure!(
        crate::server::iscsi::actions::valid_name(&initiator_name),
        "initiator_name is an iSCSI name (iqn.…)"
    );
    let target_name = get("target_name")?;
    if let Some(t) = &target_name {
        anyhow::ensure!(
            crate::server::iscsi::actions::valid_name(t),
            "target_name is an iSCSI name (iqn.…)"
        );
    }
    let digests = match get("digests")? {
        None => DigestPreference::Either,
        Some(d) => DigestPreference::parse(&d).context("digests is either, crc32c or none")?,
    };
    let config = LoginConfig {
        initiator_name: initiator_name.clone(),
        chap: credential(params, "chap_name", "chap_secret")?,
        mutual: credential(params, "target_chap_name", "target_chap_secret")?,
        digests,
    };
    anyhow::ensure!(
        config.mutual.is_none() || config.chap.is_some(),
        "mutual CHAP (target_chap_secret) needs chap_name and chap_secret too"
    );
    let addr = resolve(&ctx.remote_addr).await?;

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
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
                "initiator_name": initiator_name,
                "target_name": target_name,
                "chap": config.chap.is_some(),
            }),
        ),
        0,
    ))?;
    let dispatcher = spawn_dispatcher(&ctx, event_rx, internal_tx).await;
    let run_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut c = Initiator {
            ctx: &run_ctx,
            addr,
            config,
            default_target: target_name,
            session: None,
            block_sizes: HashMap::new(),
        };
        let result = c.run(external, internal_rx, event_tx).await;
        if let Some(mut s) = c.session.take() {
            let _ = s.logout().await;
        }
        dispatcher.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&run_ctx.status_tx)).warn(format!("iSCSI client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
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
    // No connection is open until the model logs in, so there is no local address to report.
    Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
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
            let protocol = IscsiClientProtocol;
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
                        "iSCSI client handler failed (nothing sent): {e}"
                    )),
                }
            }
        }
    });
    let abort = task.abort_handle();
    ctx.state.register_client_task(ctx.client_id, task).await;
    abort
}

struct Initiator<'a> {
    ctx: &'a ConnectContext,
    addr: SocketAddr,
    config: LoginConfig,
    default_target: Option<String>,
    session: Option<Session>,
    /// Block sizes learned from READ CAPACITY, per LUN of the current session.
    block_sizes: HashMap<u16, u32>,
}

/// The next PDU an idle session sends, or never when there is no session.
async fn unsolicited(
    session: &mut Option<Session>,
) -> Option<std::result::Result<crate::server::iscsi::pdu::Pdu, String>> {
    match session.as_mut() {
        Some(s) => s.unsolicited().await,
        None => std::future::pending().await,
    }
}

fn status_text(code: u16) -> String {
    format!("0x{code:04x}")
}

/// Status and sense of a command, as event fields.
fn status_fields(o: &CommandOutcome, data: &mut Value) {
    data["status"] = json!(scsi::status_name(o.status));
    if let Some(s) = o.sense {
        data["sense"] = json!(s.describe());
    }
}

/// Read data for the model: the text when it is text (trailing zero bytes counted), hex
/// otherwise or when asked.
pub fn render_data(bytes: &[u8], want_hex: bool) -> (String, &'static str, usize) {
    if !want_hex {
        let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        if let Ok(text) = std::str::from_utf8(&bytes[..end]) {
            // Text only when showing it changes nothing: no escapes, no controls but \n and \t.
            if crate::utils::sanitize::multiline(text) == text {
                return (text.to_string(), "utf8", bytes.len() - end);
            }
        }
    }
    (hex::encode(bytes), "hex", 0)
}

impl Initiator<'_> {
    async fn run(
        &mut self,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        events: mpsc::Sender<(Event, usize)>,
    ) -> Result<()> {
        let log = Log::new(Some(&self.ctx.status_tx));
        let protocol = IscsiClientProtocol;
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
                item = unsolicited(&mut self.session) => {
                    let ended = match item {
                        Some(Ok(p)) => match self.session.as_mut() {
                            Some(s) => s.handle_unsolicited(p).await.err().map(|e| format!("{e:#}")),
                            None => None,
                        },
                        Some(Err(e)) => Some(e),
                        None => Some("the target closed the connection".into()),
                    };
                    if let Some(reason) = ended {
                        if let Some(s) = self.session.take() {
                            self.block_sizes.clear();
                            self.raise(&events, &actions::LOGGED_OUT_EVENT, json!({"target_name": s.target, "reason": reason}), 0)?;
                        }
                    }
                    continue;
                }
            };
            let reply = |injected: &mut Option<ClientCommand>,
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
                    log.warn(format!("iSCSI client action refused: {e:#}"));
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
                    "iSCSI client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            if injected.is_some() {
                self.ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                        "iSCSI",
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
            self.raise(&events, event, data, depth)?;
        }
    }

    fn raise(
        &self,
        events: &mpsc::Sender<(Event, usize)>,
        event: &'static EventType,
        data: Value,
        depth: usize,
    ) -> Result<()> {
        anyhow::ensure!(
            events.try_send((Event::new(event, data), depth)).is_ok(),
            "iSCSI event queue full; consumer stalled"
        );
        Ok(())
    }

    /// Run one action; the event to raise and its data.
    async fn execute(&mut self, action: &Value) -> (&'static EventType, Value) {
        let kind = action["type"].as_str().unwrap_or_default();
        match kind {
            actions::DISCOVER => {
                let data = match self.discover().await {
                    Ok(targets) => json!({"targets": targets
                        .into_iter()
                        .map(|(name, addresses)| json!({"name": name, "addresses": addresses}))
                        .collect::<Vec<_>>()}),
                    Err(e) => json!({"targets": [], "error": format!("{e:#}")}),
                };
                (&actions::TARGETS_EVENT, data)
            }
            actions::LOGIN => (&actions::LOGIN_RESULT_EVENT, self.login(action).await),
            actions::LOGOUT => {
                let Some(mut s) = self.session.take() else {
                    return (
                        &actions::LOGGED_OUT_EVENT,
                        json!({"target_name": "", "reason": "not logged in"}),
                    );
                };
                self.block_sizes.clear();
                let reason = match s.logout().await {
                    Ok(0) => "logged out".to_string(),
                    Ok(code) => format!("the target answered logout with response {code}"),
                    Err(e) => format!("logout failed: {e:#}"),
                };
                (
                    &actions::LOGGED_OUT_EVENT,
                    json!({"target_name": s.target, "reason": reason}),
                )
            }
            _ => {
                let operation = kind.trim_start_matches("iscsi_").to_string();
                let lun = actions::lun_of(action).unwrap_or(0);
                let mut data = json!({"operation": operation, "lun": lun});
                if let Err(e) = self.scsi(kind, lun, action, &mut data).await {
                    data["error"] = json!(format!("{e:#}"));
                }
                (&actions::COMMAND_RESULT_EVENT, data)
            }
        }
    }

    async fn discover(&mut self) -> Result<Vec<(String, Vec<String>)>> {
        let (outcome, session) = Session::login(self.addr, Kind::Discovery, "", &self.config).await?;
        let Some(mut s) = session else {
            bail!(
                "the portal refused the discovery login: {} ({})",
                status_text(outcome.status),
                login_status::describe(outcome.status)
            );
        };
        if let Some(t) = s.reader_task.take() {
            self.ctx
                .state
                .register_client_task(self.ctx.client_id, t)
                .await;
        }
        let targets = s.send_targets("All").await;
        let _ = s.logout().await;
        targets
    }

    async fn login(&mut self, action: &Value) -> Value {
        let target = action["target_name"]
            .as_str()
            .map(str::to_string)
            .or_else(|| self.default_target.clone());
        let Some(target) = target else {
            return json!({"target_name": "", "logged_in": false,
                "error": "no target_name: name one, or discover the targets first"});
        };
        if let Some(s) = &self.session {
            return json!({"target_name": target, "logged_in": false,
                "error": format!("already logged in to {}; log out first", s.target)});
        }
        match Session::login(self.addr, Kind::Normal, &target, &self.config).await {
            Ok((outcome, Some(mut s))) => {
                if let Some(t) = s.reader_task.take() {
                    self.ctx
                        .state
                        .register_client_task(self.ctx.client_id, t)
                        .await;
                }
                let p = &s.params;
                let data = json!({
                    "target_name": target,
                    "logged_in": true,
                    "tsih": outcome.tsih,
                    "status": status_text(outcome.status),
                    "status_meaning": login_status::describe(outcome.status),
                    "alias": s.alias,
                    "negotiated": {
                        "header_digest": if p.header_digest { "CRC32C" } else { "None" },
                        "data_digest": if p.data_digest { "CRC32C" } else { "None" },
                        "target_max_recv_data_segment_length": p.peer_max_recv_data_segment,
                        "max_burst_length": p.max_burst,
                        "first_burst_length": p.first_burst,
                        "immediate_data": p.immediate_data,
                        "initial_r2t": p.initial_r2t,
                    },
                });
                self.block_sizes.clear();
                self.session = Some(s);
                data
            }
            Ok((outcome, None)) => json!({
                "target_name": target,
                "logged_in": false,
                "status": status_text(outcome.status),
                "status_meaning": login_status::describe(outcome.status),
            }),
            Err(e) => json!({"target_name": target, "logged_in": false, "error": format!("{e:#}")}),
        }
    }

    /// Run one command on the session. A transport or protocol failure ends the session: at
    /// error recovery level 0 nothing on that connection can be trusted afterwards.
    async fn cmd(
        &mut self,
        lun: u16,
        cdb: [u8; 16],
        read_len: usize,
        write: Option<&[u8]>,
    ) -> Result<CommandOutcome> {
        let s = self.session.as_mut().context("not logged in: run iscsi_login first")?;
        match s.command(lun, cdb, read_len, write).await {
            Ok(o) => Ok(o),
            Err(e) => {
                self.session = None;
                self.block_sizes.clear();
                Err(e.context("the session ended"))
            }
        }
    }

    /// The block size of a LUN, from READ CAPACITY when not yet known.
    async fn block_size(&mut self, lun: u16) -> Result<u32> {
        if let Some(b) = self.block_sizes.get(&lun) {
            return Ok(*b);
        }
        let (_, bs, o) = self.capacity(lun).await?;
        if o.status != status::GOOD {
            bail!(
                "READ CAPACITY failed: {}",
                o.sense.map(|s| s.describe()).unwrap_or_else(|| scsi::status_name(o.status).into())
            );
        }
        Ok(bs)
    }

    /// READ CAPACITY(10), then (16) when the last LBA does not fit: (blocks, block size).
    async fn capacity(&mut self, lun: u16) -> Result<(u64, u32, CommandOutcome)> {
        let o = self.cmd(lun, scsi::read_capacity_10_cdb(), 8, None).await?;
        if o.status != status::GOOD {
            return Ok((0, 0, o));
        }
        let (mut last, mut bs) = scsi::parse_read_capacity(&o.data).context("short READ CAPACITY data")?;
        let mut o = o;
        if last == u32::MAX as u64 {
            o = self.cmd(lun, scsi::read_capacity_16_cdb(), 32, None).await?;
            if o.status != status::GOOD {
                return Ok((0, 0, o));
            }
            (last, bs) = scsi::parse_read_capacity(&o.data).context("short READ CAPACITY(16) data")?;
        }
        anyhow::ensure!(
            bs.is_power_of_two() && (512..=65536).contains(&bs),
            "the target reports a block size of {bs}"
        );
        self.block_sizes.insert(lun, bs);
        Ok((last + 1, bs, o))
    }

    async fn scsi(&mut self, kind: &str, lun: u16, action: &Value, data: &mut Value) -> Result<()> {
        anyhow::ensure!(self.session.is_some(), "not logged in: run iscsi_login first");
        match kind {
            actions::REPORT_LUNS => {
                let o = self.cmd(0, scsi::report_luns_cdb(16 * 1024), 16 * 1024, None).await?;
                status_fields(&o, data);
                if o.status == status::GOOD {
                    data["luns"] = json!(scsi::parse_report_luns(&o.data)
                        .into_iter()
                        .map(|l| match l {
                            Ok(n) => json!(n),
                            Err(h) => json!(h),
                        })
                        .collect::<Vec<_>>());
                }
            }
            actions::INQUIRY => {
                let page = action["page"].as_str().unwrap_or("standard");
                let code = match page {
                    "supported_pages" => Some(0x00),
                    "serial" => Some(0x80),
                    "device_identification" => Some(0x83),
                    _ => None,
                };
                let o = self.cmd(lun, scsi::inquiry_cdb(code, 255), 255, None).await?;
                status_fields(&o, data);
                if o.status == status::GOOD {
                    data["inquiry"] = match code {
                        None => {
                            let i = scsi::parse_inquiry(&o.data).context("short INQUIRY data")?;
                            json!({
                                "vendor": i.vendor,
                                "product": i.product,
                                "revision": i.revision,
                                "device_type": scsi::device_type_name(i.device_type),
                                "lun_present": i.qualifier == 0,
                                "removable": i.removable,
                            })
                        }
                        Some(c) => {
                            let (_, body) = scsi::parse_vpd(&o.data).context("short VPD page")?;
                            match c {
                                0x00 => json!({"pages": body.iter().map(|p| format!("0x{p:02x}")).collect::<Vec<_>>()}),
                                0x80 => json!({"serial": crate::utils::sanitize::line_field(&String::from_utf8_lossy(body)).trim().to_string()}),
                                _ => json!({"designators": scsi::parse_designators(body)}),
                            }
                        }
                    };
                }
            }
            actions::READ_CAPACITY => {
                let (blocks, bs, o) = self.capacity(lun).await?;
                status_fields(&o, data);
                if o.status == status::GOOD {
                    data["capacity"] = json!({"blocks": blocks, "block_size": bs, "size_bytes": blocks * bs as u64});
                }
            }
            actions::TEST_UNIT_READY => {
                let o = self.cmd(lun, scsi::test_unit_ready_cdb(), 0, None).await?;
                status_fields(&o, data);
            }
            actions::READ => {
                let bs = self.block_size(lun).await?;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let blocks = action["blocks"].as_u64().unwrap_or(1) as usize;
                let len = blocks * bs as usize;
                anyhow::ensure!(
                    len <= actions::MAX_TRANSFER,
                    "{blocks} blocks of {bs} bytes is more than {} bytes",
                    actions::MAX_TRANSFER
                );
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let o = self.cmd(lun, scsi::read_cdb(lba, blocks as u32), len, None).await?;
                status_fields(&o, data);
                if o.status == status::GOOD {
                    let (text, encoding, zeros) =
                        render_data(&o.data, action["encoding"] == "hex");
                    data["data"] = json!(text);
                    data["encoding"] = json!(encoding);
                    data["bytes"] = json!(o.data.len());
                    if encoding == "utf8" {
                        data["trailing_zero_bytes"] = json!(zeros);
                    }
                }
            }
            actions::WRITE => {
                let bs = self.block_size(lun).await? as usize;
                let lba = action["lba"].as_u64().unwrap_or(0);
                let mut bytes = actions::write_data(action)?;
                bytes.resize(bytes.len().div_ceil(bs) * bs, 0);
                anyhow::ensure!(
                    bytes.len() <= actions::MAX_TRANSFER,
                    "the padded write is more than {} bytes",
                    actions::MAX_TRANSFER
                );
                let blocks = (bytes.len() / bs) as u32;
                data["lba"] = json!(lba);
                data["blocks"] = json!(blocks);
                let o = self.cmd(lun, scsi::write_cdb(lba, blocks), 0, Some(&bytes)).await?;
                status_fields(&o, data);
                if o.status == status::GOOD {
                    data["bytes"] = json!(bytes.len());
                }
            }
            other => bail!("unknown operation {other}"),
        }
        Ok(())
    }
}
