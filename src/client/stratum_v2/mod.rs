//! Stratum V2 mining device (client role): the Noise NX handshake with the pool's certificate
//! checked against its authority key, SetupConnection, a channel opened on connect, the pool's
//! work tracked, and shares mined and submitted as the handler directs. Shares are built and
//! hashed with the same code the pool role verifies them with.
pub mod actions;
pub mod job_declarator;
pub mod template_client;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::stratum_v2::noise;
use crate::server::stratum_v2::wire::{self, Message};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::StratumV2ClientProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{io::WriteHalf, net::TcpStream, sync::mpsc};

/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;
/// Shares awaiting the pool's answer at once.
pub const MAX_PENDING: usize = 64;
/// Jobs remembered per channel, active and future together.
pub const MAX_JOBS: usize = 16;
/// Channels one connection may hold.
pub const MAX_CHANNELS: usize = 16;
/// The largest frame payload the pool may send: a NewExtendedMiningJob with two full coinbase
/// halves and a 255-deep merkle path is about 136 KiB.
pub const MAX_INBOUND_PAYLOAD: usize = 256 * 1024;
/// The pool has this long to answer the handshake and SetupConnection.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
/// A pool may stay quiet this long between messages.
pub const READ_IDLE: Duration = Duration::from_secs(3600);

fn param(ctx: &ConnectContext, key: &str) -> Result<Option<String>> {
    Ok(ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string(key))
        .transpose()?
        .flatten())
}

/// An extended job's coinbase prefix, suffix and merkle path (deepest first).
type Coinbase = (Vec<u8>, Vec<u8>, Vec<[u8; 32]>);

#[derive(Clone)]
struct Job {
    id: u32,
    version: u32,
    /// Standard jobs carry their root; extended ones the coinbase halves and path.
    merkle_root: [u8; 32],
    coinbase: Option<Coinbase>,
    /// None until it is active.
    ntime: Option<u32>,
}

#[derive(Clone, Copy)]
struct PrevHash {
    hash: [u8; 32],
    ntime: u32,
    nbits: u32,
}

struct Channel {
    id: u32,
    user: String,
    extranonce_size: Option<u16>,
    extranonce_prefix: Vec<u8>,
    target: [u8; 32],
    jobs: VecDeque<Job>,
    prev: Option<PrevHash>,
    active: Option<u32>,
    extranonce: u64,
}

impl Channel {
    fn kind(&self) -> &'static str {
        if self.extranonce_size.is_some() {
            "extended"
        } else {
            "standard"
        }
    }

    fn extranonce_bytes(&self, n: u64) -> Vec<u8> {
        let mut b = n.to_le_bytes().to_vec();
        b.resize(usize::from(self.extranonce_size.unwrap_or(0)), 0);
        b
    }

    /// The job's merkle root for an extranonce (ignored on a standard channel).
    fn root(&self, job: &Job, extranonce: &[u8]) -> [u8; 32] {
        match &job.coinbase {
            None => job.merkle_root,
            Some((prefix, suffix, path)) => {
                let coinbase = [
                    &prefix[..],
                    &self.extranonce_prefix,
                    extranonce,
                    &suffix[..],
                ]
                .concat();
                wire::merkle_root(&coinbase, path)
            }
        }
    }

    fn remember(&mut self, job: Job) {
        self.jobs.retain(|j| j.id != job.id);
        if self.jobs.len() >= MAX_JOBS {
            self.jobs.pop_front();
        }
        self.jobs.push_back(job);
    }

    fn job_event(&self, job: &Job) -> Value {
        let prev = self.prev.unwrap_or(PrevHash {
            hash: [0; 32],
            ntime: 0,
            nbits: 0,
        });
        let mut data = json!({"channel_id": self.id, "job_id": job.id, "channel_kind": self.kind(), "user_identity": self.user,
            "prev_hash": wire::display_hex(&prev.hash), "ntime": job.ntime.unwrap_or(prev.ntime),
            "nbits": format!("{:08x}", prev.nbits), "version": job.version,
            "difficulty": wire::target_difficulty(&self.target)});
        if let Some((_, _, path)) = &job.coinbase {
            data["merkle_path_len"] = json!(path.len());
        }
        data
    }
}

enum Pending {
    Open {
        request_id: u32,
        user: String,
        extended: bool,
    },
    Share {
        channel_id: u32,
        sequence_number: u32,
        depth: usize,
        info: Value,
    },
}

struct Device {
    writer: wire::FrameWriter<WriteHalf<TcpStream>>,
    channels: BTreeMap<u32, Channel>,
    pending: Vec<(Pending, Option<ClientCommand>)>,
    next_request: u32,
    next_sequence: u32,
    default_extended: bool,
    events: mpsc::Sender<(Event, usize)>,
}

impl Device {
    fn emit(
        &self,
        event: &'static crate::protocol::EventType,
        data: Value,
        depth: usize,
    ) -> Result<()> {
        self.events
            .try_send((Event::new(event, data), depth))
            .context("Stratum V2 event queue full; consumer stalled")
    }

    fn channel_id(&self, action: &Value) -> Option<u32> {
        match action["channel_id"].as_u64() {
            Some(id) => Some(id as u32),
            None => self.channels.keys().next().copied(),
        }
    }

    fn track(&mut self, what: Pending, caller: Option<ClientCommand>) -> Result<()> {
        if self.pending.len() >= MAX_PENDING {
            bail!("too many requests awaiting the pool");
        }
        self.pending.push((what, caller));
        Ok(())
    }

    async fn open(
        &mut self,
        user: &str,
        rate: f32,
        extended: bool,
        caller: Option<ClientCommand>,
    ) -> Result<()> {
        if self.channels.len() >= MAX_CHANNELS {
            bail!("{MAX_CHANNELS} channels are already open");
        }
        self.next_request = self.next_request.wrapping_add(1);
        let request_id = self.next_request;
        let message = if extended {
            Message::OpenExtendedMiningChannel {
                request_id,
                user_identity: user.as_bytes().to_vec(),
                nominal_hash_rate: rate,
                max_target: [0xff; 32],
                min_extranonce_size: 8,
            }
        } else {
            Message::OpenStandardMiningChannel {
                request_id,
                user_identity: user.as_bytes().to_vec(),
                nominal_hash_rate: rate,
                max_target: [0xff; 32],
            }
        };
        self.track(
            Pending::Open {
                request_id,
                user: user.to_string(),
                extended,
            },
            caller,
        )?;
        self.writer.send(&message).await?;
        Ok(())
    }

    /// Submit (job, extranonce, ntime, version, nonce); the pool's answer arrives as an event.
    #[allow(clippy::too_many_arguments)]
    async fn submit(
        &mut self,
        channel_id: u32,
        job: &Job,
        extranonce: u64,
        ntime: u32,
        version: u32,
        nonce: u32,
        depth: usize,
        caller: Option<ClientCommand>,
    ) -> Result<()> {
        let ch = self.channels.get(&channel_id).context("no such channel")?;
        let prev = ch.prev.context("the channel has no prev hash yet")?;
        let en = ch.extranonce_bytes(extranonce);
        let root = ch.root(job, &en);
        let hash = wire::sha256d(&wire::header(
            version, &prev.hash, &root, ntime, prev.nbits, nonce,
        ));
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let sequence_number = self.next_sequence;
        let message = match ch.extranonce_size {
            None => Message::SubmitSharesStandard {
                channel_id,
                sequence_number,
                job_id: job.id,
                nonce,
                ntime,
                version,
            },
            Some(_) => Message::SubmitSharesExtended {
                channel_id,
                sequence_number,
                job_id: job.id,
                nonce,
                ntime,
                version,
                extranonce: en,
            },
        };
        let info = json!({"channel_id": channel_id, "sequence_number": sequence_number, "job_id": job.id,
            "nonce": nonce, "ntime": ntime, "hash": wire::display_hex(&hash),
            "share_difficulty": wire::difficulty(&hash)});
        self.track(
            Pending::Share {
                channel_id,
                sequence_number,
                depth,
                info,
            },
            caller,
        )?;
        self.writer.send(&message).await?;
        Ok(())
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    match param(&ctx, "role")?
        .as_deref()
        .unwrap_or(actions::DEFAULT_ROLE)
    {
        "mining" => {}
        "job_declarator" => return job_declarator::connect(ctx).await,
        "template_client" => return template_client::connect(ctx).await,
        other => bail!("role must be mining, job_declarator or template_client, not {other:?}"),
    }
    let authority_text = param(&ctx, "authority_public_key")?
        .context("authority_public_key is required: the pool's base58check authority key")?;
    let authority = noise::decode_authority_key(&authority_text)
        .context("authority_public_key is not a base58check authority key")?;
    let user = param(&ctx, "user_identity")?.unwrap_or_else(|| actions::DEFAULT_USER.into());
    anyhow::ensure!(user.len() <= 255, "user_identity must be at most 255 bytes");
    let rate = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_f64("nominal_hash_rate"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_NOMINAL_HASH_RATE);
    anyhow::ensure!(
        rate.is_finite() && (0.0..=1e21).contains(&rate),
        "nominal_hash_rate must be between 0 and 1e21"
    );
    let extended = match param(&ctx, "channel_kind")?.as_deref() {
        None | Some("standard") => false,
        Some("extended") => true,
        Some(other) => bail!("channel_kind must be standard or extended, not {other:?}"),
    };
    let target = ctx
        .remote_addr
        .trim_start_matches("stratum2+tcp://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let mut stream = tokio::time::timeout(wire::IO_TIMEOUT, TcpStream::connect(&target))
        .await
        .context("Stratum V2 connect deadline")??;
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    let (noise_session, cert) = wire::connect_handshake(&mut stream, &authority, SETUP_TIMEOUT)
        .await
        .context("Noise handshake with the pool failed")?;
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "Stratum V2 client: {peer} proved its key with a certificate from the configured authority, valid {}..{}",
        cert.valid_from, cert.not_valid_after
    ));
    let (r, w) = tokio::io::split(stream);
    let (mut reader, mut writer) = wire::transport(r, w, noise_session, MAX_INBOUND_PAYLOAD);
    writer
        .send(&Message::SetupConnection {
            protocol: wire::MINING_PROTOCOL,
            min_version: wire::PROTOCOL_VERSION,
            max_version: wire::PROTOCOL_VERSION,
            flags: if extended {
                0
            } else {
                wire::REQUIRES_STANDARD_JOBS
            },
            endpoint_host: peer.ip().to_string().into_bytes(),
            endpoint_port: peer.port(),
            vendor: b"NetGet".to_vec(),
            hardware_version: b"NetGet CPU miner".to_vec(),
            firmware: concat!("netget-", env!("CARGO_PKG_VERSION"))
                .as_bytes()
                .to_vec(),
            device_id: Vec::new(),
        })
        .await?;
    let answer = reader
        .next(SETUP_TIMEOUT)
        .await?
        .context("the pool closed the connection after SetupConnection")?;
    match Message::decode(&answer)? {
        Message::SetupConnectionSuccess {
            used_version,
            flags,
        } => log.info(format!(
            "Stratum V2 client: SetupConnection accepted (version {used_version}, flags {flags:#x})"
        )),
        Message::SetupConnectionError { flags, error_code } => bail!(
            "the pool refused SetupConnection: {} (flags {flags:#x})",
            wire::text(&error_code)
        ),
        other => bail!("the pool answered SetupConnection with {}", other.name()),
    }

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (msg_tx, msg_rx) = mpsc::channel::<Result<Message>>(64);
    let reader_task = tokio::spawn(async move {
        loop {
            let item = match reader.next(READ_IDLE).await {
                Ok(Some(frame)) if frame.extension() != 0 => continue,
                Ok(Some(frame)) => Message::decode(&frame),
                Ok(None) => Err(anyhow::anyhow!("pool closed the connection")),
                Err(e) => Err(e),
            };
            let end = item.is_err();
            if msg_tx.send(item).await.is_err() || end {
                return;
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;

    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(64);
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        while let Some((event, depth)) = event_rx.recv().await {
            events_ctx
                .state
                .record_access_log(
                    AccessLogOwner::Client(events_ctx.client_id.as_u32()),
                    "Stratum V2",
                    None,
                    event.id(),
                    event.data.clone(),
                    vec![],
                )
                .await;
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                &StratumV2ClientProtocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("Stratum V2 client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut device = Device {
            writer,
            channels: BTreeMap::new(),
            pending: Vec::new(),
            next_request: 0,
            next_sequence: 0,
            default_extended: extended,
            events: event_tx,
        };
        let result = async {
            device.open(&user, rate as f32, extended, None).await?;
            session(&session_ctx, &mut device, msg_rx, external, internal_rx).await
        }
        .await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx))
                    .warn(format!("Stratum V2 client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        device.writer.shutdown().await;
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

/// Hash up to `max` nonces: the first meeting `target`, else the best.
fn mine(header: [u8; 80], target: [u8; 32], max: u64) -> (u32, [u8; 32], u64) {
    let mut header = header;
    let (mut best_nonce, mut best_hash, mut best) = (0u32, [0xffu8; 32], 0f64);
    let mut tried = 0u64;
    for nonce in 0..=u32::MAX {
        if tried >= max {
            break;
        }
        tried += 1;
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let hash = wire::sha256d(&header);
        if wire::meets(&hash, &target) {
            return (nonce, hash, tried);
        }
        let d = wire::difficulty(&hash);
        if d > best {
            best = d;
            best_nonce = nonce;
            best_hash = hash;
        }
    }
    (best_nonce, best_hash, tried)
}

fn reply(caller: &mut Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = caller.take() {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

async fn session(
    ctx: &ConnectContext,
    device: &mut Device,
    mut messages: mpsc::Receiver<Result<Message>>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            item = messages.recv() => {
                let Some(item) = item else { return Ok(()) };
                on_message(device, item?, &log)?;
                continue;
            }
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return Ok(()),
            },
            action = internal.recv() => match action {
                Some((a, depth)) => (a, depth, None),
                None => return Ok(()),
            },
        };
        let refuse = |injected: &mut Option<ClientCommand>, error: String| {
            log.warn(format!("Stratum V2 client action refused: {error}"));
            reply(injected, ClientSendOutcome::Rejected { error });
        };
        match StratumV2ClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(&mut injected, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                refuse(&mut injected, e.to_string());
                continue;
            }
        }
        if depth > MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "Stratum V2 client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
            ));
            continue;
        }
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Stratum V2",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![],
                )
                .await;
        }
        match action["type"].as_str().unwrap_or_default() {
            actions::MINE => {
                let channel_id = device.channel_id(&action);
                let work = channel_id
                    .and_then(|id| device.channels.get(&id))
                    .and_then(|ch| {
                        let job = ch.jobs.iter().find(|j| Some(j.id) == ch.active)?.clone();
                        Some((ch.id, job, ch.prev?, ch.target))
                    });
                let Some((channel_id, job, prev, target)) = work else {
                    let difficulty = channel_id
                        .and_then(|id| device.channels.get(&id))
                        .map(|c| wire::target_difficulty(&c.target))
                        .unwrap_or(0.0);
                    let reason = if channel_id.is_none() {
                        "no channel is open"
                    } else {
                        "no job yet"
                    };
                    let data = json!({"channel_id": channel_id, "hashes": 0, "best_difficulty": 0,
                                      "difficulty": difficulty, "reason": reason});
                    reply(
                        &mut injected,
                        ClientSendOutcome::Executed {
                            detail: data.to_string(),
                        },
                    );
                    device.emit(&actions::MINED_EVENT, data, depth)?;
                    continue;
                };
                let max = action["max_hashes"]
                    .as_u64()
                    .unwrap_or(actions::DEFAULT_MINE_HASHES);
                let submit_best = action["submit_best"].as_bool().unwrap_or(false);
                let ch = device
                    .channels
                    .get_mut(&channel_id)
                    .context("channel vanished")?;
                ch.extranonce = ch.extranonce.wrapping_add(1);
                let extranonce = ch.extranonce;
                let root = ch.root(&job, &ch.extranonce_bytes(extranonce));
                let ntime = job.ntime.unwrap_or(prev.ntime);
                let header = wire::header(job.version, &prev.hash, &root, ntime, prev.nbits, 0);
                let (nonce, hash, tried) =
                    tokio::task::spawn_blocking(move || mine(header, target, max))
                        .await
                        .context("mining stopped")?;
                let found = wire::meets(&hash, &target);
                log.info(format!(
                    "Stratum V2 client mined {tried} hashes on job {}: best difficulty {:.6} (channel asks {:.6})",
                    job.id,
                    wire::difficulty(&hash),
                    wire::target_difficulty(&target)
                ));
                if found || submit_best {
                    device
                        .submit(
                            channel_id,
                            &job,
                            extranonce,
                            ntime,
                            job.version,
                            nonce,
                            depth,
                            injected.take(),
                        )
                        .await?;
                } else {
                    let data = json!({"channel_id": channel_id, "hashes": tried,
                        "best_difficulty": wire::difficulty(&hash),
                        "difficulty": wire::target_difficulty(&target), "reason": "nothing met the target"});
                    reply(
                        &mut injected,
                        ClientSendOutcome::Executed {
                            detail: data.to_string(),
                        },
                    );
                    device.emit(&actions::MINED_EVENT, data, depth)?;
                }
            }
            actions::SUBMIT => {
                let Some(channel_id) = device.channel_id(&action) else {
                    refuse(&mut injected, "no channel is open".into());
                    continue;
                };
                let job = device.channels.get(&channel_id).and_then(|ch| {
                    let id = action["job_id"].as_u64().map(|n| n as u32).or(ch.active)?;
                    let prev = ch.prev?;
                    ch.jobs
                        .iter()
                        .find(|j| j.id == id)
                        .map(|j| (j.clone(), prev))
                });
                let Some((job, prev)) = job else {
                    refuse(&mut injected, "no such job".into());
                    continue;
                };
                let field = |k: &str| action[k].as_u64().map(|n| n as u32);
                device
                    .submit(
                        channel_id,
                        &job,
                        action["extranonce"].as_u64().unwrap_or(0),
                        field("ntime").unwrap_or(job.ntime.unwrap_or(prev.ntime)),
                        field("version").unwrap_or(job.version),
                        field("nonce").unwrap_or(0),
                        depth,
                        injected.take(),
                    )
                    .await?;
            }
            actions::OPEN_CHANNEL => {
                let user = action["user_identity"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let rate = action["nominal_hash_rate"]
                    .as_f64()
                    .unwrap_or(actions::DEFAULT_NOMINAL_HASH_RATE)
                    as f32;
                let extended = match action["channel_kind"].as_str() {
                    Some(k) => k == "extended",
                    None => device.default_extended,
                };
                if let Err(e) = device.open(&user, rate, extended, injected.take()).await {
                    log.warn(format!("Stratum V2 client: {e}"));
                }
            }
            actions::UPDATE_CHANNEL => {
                let Some(channel_id) = device.channel_id(&action) else {
                    refuse(&mut injected, "no channel is open".into());
                    continue;
                };
                let max_target = action["min_difficulty"]
                    .as_f64()
                    .map(wire::target_for)
                    .unwrap_or([0xff; 32]);
                let rate = action["nominal_hash_rate"].as_f64().unwrap_or(0.0) as f32;
                device
                    .writer
                    .send(&Message::UpdateChannel {
                        channel_id,
                        nominal_hash_rate: rate,
                        max_target,
                    })
                    .await?;
                reply(
                    &mut injected,
                    ClientSendOutcome::Executed {
                        detail: format!("UpdateChannel sent for channel {channel_id}"),
                    },
                );
            }
            actions::CLOSE_CHANNEL => {
                let Some(channel_id) = device.channel_id(&action) else {
                    refuse(&mut injected, "no channel is open".into());
                    continue;
                };
                device.channels.remove(&channel_id);
                device
                    .writer
                    .send(&Message::CloseChannel {
                        channel_id,
                        reason_code: action["reason_code"]
                            .as_str()
                            .unwrap_or("closed")
                            .as_bytes()
                            .to_vec(),
                    })
                    .await?;
                reply(
                    &mut injected,
                    ClientSendOutcome::Executed {
                        detail: format!("channel {channel_id} closed"),
                    },
                );
            }
            other => refuse(
                &mut injected,
                format!("{other} is a job declarator action; this client mines"),
            ),
        }
    }
}

/// Track one message from the pool, raising the event it calls for.
fn on_message(device: &mut Device, message: Message, log: &Log) -> Result<()> {
    match message {
        Message::OpenStandardMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_prefix,
            ..
        } => opened(device, request_id, channel_id, target, extranonce_prefix, None),
        Message::OpenExtendedMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_size,
            extranonce_prefix,
            ..
        } => {
            if usize::from(extranonce_size) > wire::MAX_EXTRANONCE {
                bail!("the pool assigned a {extranonce_size}-byte extranonce, more than 32");
            }
            opened(
                device,
                request_id,
                channel_id,
                target,
                extranonce_prefix,
                Some(extranonce_size),
            )
        }
        Message::OpenMiningChannelError {
            request_id,
            error_code,
        } => {
            let Some(at) = device.pending.iter().position(
                |(p, _)| matches!(p, Pending::Open { request_id: r, .. } if *r == request_id),
            ) else {
                return Ok(());
            };
            let (_, mut caller) = device.pending.remove(at);
            let data = json!({"ok": false, "request_id": request_id, "error_code": wire::text(&error_code)});
            reply(&mut caller, ClientSendOutcome::Executed { detail: data.to_string() });
            device.emit(&actions::CHANNEL_EVENT, data, 0)
        }
        Message::NewMiningJob {
            channel_id,
            job_id,
            min_ntime,
            version,
            merkle_root,
        } => new_job(
            device,
            channel_id,
            Job {
                id: job_id,
                version,
                merkle_root,
                coinbase: None,
                ntime: min_ntime,
            },
        ),
        Message::NewExtendedMiningJob {
            channel_id,
            job_id,
            min_ntime,
            version,
            merkle_path,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            ..
        } => new_job(
            device,
            channel_id,
            Job {
                id: job_id,
                version,
                merkle_root: [0; 32],
                coinbase: Some((coinbase_tx_prefix, coinbase_tx_suffix, merkle_path)),
                ntime: min_ntime,
            },
        ),
        Message::SetNewPrevHash {
            channel_id,
            job_id,
            prev_hash,
            min_ntime,
            nbits,
        } => {
            let Some(ch) = device.channels.get_mut(&channel_id) else {
                return Ok(());
            };
            ch.prev = Some(PrevHash {
                hash: prev_hash,
                ntime: min_ntime,
                nbits,
            });
            // Only the job it names stays valid.
            ch.jobs.retain(|j| j.id == job_id);
            let Some(job) = ch.jobs.iter_mut().find(|j| j.id == job_id) else {
                ch.active = None;
                return Ok(());
            };
            job.ntime = Some(min_ntime);
            let job = job.clone();
            ch.active = Some(job_id);
            let data = ch.job_event(&job);
            device.emit(&actions::JOB_EVENT, data, 0)
        }
        Message::SetTarget {
            channel_id,
            maximum_target,
        } => {
            if let Some(ch) = device.channels.get_mut(&channel_id) {
                ch.target = maximum_target;
                log.info(format!(
                    "Stratum V2 client: channel {channel_id} difficulty is now {:.6}",
                    wire::target_difficulty(&maximum_target)
                ));
            }
            Ok(())
        }
        Message::SubmitSharesSuccess {
            channel_id,
            last_sequence_number,
            new_submits_accepted_count,
            new_shares_sum,
        } => {
            let mut last: Option<(usize, Value, Option<ClientCommand>)> = None;
            let mut kept = Vec::new();
            for (p, caller) in device.pending.drain(..) {
                match p {
                    Pending::Share {
                        channel_id: c,
                        sequence_number,
                        depth,
                        info,
                    } if c == channel_id && sequence_number <= last_sequence_number => {
                        if let Some((_, _, mut older)) = last.take() {
                            reply(&mut older, ClientSendOutcome::Executed {
                                detail: "accepted".into(),
                            });
                        }
                        last = Some((depth, info, caller));
                    }
                    other => kept.push((other, caller)),
                }
            }
            device.pending = kept;
            let (depth, mut info, mut caller) = last.unwrap_or((
                0,
                json!({"channel_id": channel_id, "sequence_number": last_sequence_number}),
                None,
            ));
            info["accepted"] = json!(true);
            info["new_submits_accepted_count"] = json!(new_submits_accepted_count);
            info["new_shares_sum"] = json!(new_shares_sum);
            reply(&mut caller, ClientSendOutcome::Executed { detail: info.to_string() });
            device.emit(&actions::SHARE_RESULT_EVENT, info, depth)
        }
        Message::SubmitSharesError {
            channel_id,
            sequence_number,
            error_code,
        } => {
            let at = device.pending.iter().position(|(p, _)| {
                matches!(p, Pending::Share { channel_id: c, sequence_number: s, .. } if *c == channel_id && *s == sequence_number)
            });
            let (depth, mut info, mut caller) = match at.map(|i| device.pending.remove(i)) {
                Some((Pending::Share { depth, info, .. }, caller)) => (depth, info, caller),
                _ => (
                    0,
                    json!({"channel_id": channel_id, "sequence_number": sequence_number}),
                    None,
                ),
            };
            info["accepted"] = json!(false);
            info["error_code"] = json!(wire::text(&error_code));
            reply(&mut caller, ClientSendOutcome::Executed { detail: info.to_string() });
            device.emit(&actions::SHARE_RESULT_EVENT, info, depth)
        }
        Message::SetExtranoncePrefix {
            channel_id,
            extranonce_prefix,
        } => {
            if let Some(ch) = device.channels.get_mut(&channel_id) {
                ch.extranonce_prefix = extranonce_prefix.clone();
            }
            device.emit(
                &actions::MESSAGE_EVENT,
                json!({"message": "SetExtranoncePrefix", "fields": {"channel_id": channel_id, "extranonce_prefix_len": extranonce_prefix.len()}}),
                0,
            )
        }
        Message::CloseChannel {
            channel_id,
            reason_code,
        } => {
            device.channels.remove(&channel_id);
            device.emit(
                &actions::MESSAGE_EVENT,
                json!({"message": "CloseChannel", "fields": {"channel_id": channel_id, "reason_code": wire::text(&reason_code)}}),
                0,
            )
        }
        Message::UpdateChannelError {
            channel_id,
            error_code,
        } => device.emit(
            &actions::MESSAGE_EVENT,
            json!({"message": "UpdateChannel.Error", "fields": {"channel_id": channel_id, "error_code": wire::text(&error_code)}}),
            0,
        ),
        Message::Reconnect { new_host, new_port } => device.emit(
            &actions::MESSAGE_EVENT,
            json!({"message": "Reconnect", "fields": {"new_host": wire::text(&new_host), "new_port": new_port}}),
            0,
        ),
        Message::SetGroupChannel {
            group_channel_id,
            channel_ids,
        } => device.emit(
            &actions::MESSAGE_EVENT,
            json!({"message": "SetGroupChannel", "fields": {"group_channel_id": group_channel_id, "channels": channel_ids.len()}}),
            0,
        ),
        Message::ChannelEndpointChanged { channel_id } => device.emit(
            &actions::MESSAGE_EVENT,
            json!({"message": "ChannelEndpointChanged", "fields": {"channel_id": channel_id}}),
            0,
        ),
        other => bail!("the pool sent {}, which a pool does not send", other.name()),
    }
}

fn opened(
    device: &mut Device,
    request_id: u32,
    channel_id: u32,
    target: [u8; 32],
    extranonce_prefix: Vec<u8>,
    extranonce_size: Option<u16>,
) -> Result<()> {
    let Some(at) = device
        .pending
        .iter()
        .position(|(p, _)| matches!(p, Pending::Open { request_id: r, .. } if *r == request_id))
    else {
        bail!(
            "the pool opened channel {channel_id} for request {request_id}, which was never sent"
        );
    };
    let (Pending::Open { user, extended, .. }, mut caller) = device.pending.remove(at) else {
        unreachable!("position matched an Open");
    };
    if extended != extranonce_size.is_some() {
        bail!(
            "the pool answered a {} channel request with the other kind",
            if extended { "extended" } else { "standard" }
        );
    }
    if extranonce_size.is_none() && extranonce_prefix.len() > wire::MAX_EXTRANONCE {
        bail!("extranonce prefix is longer than 32 bytes");
    }
    let channel = Channel {
        id: channel_id,
        user: user.clone(),
        extranonce_size,
        extranonce_prefix,
        target,
        jobs: VecDeque::new(),
        prev: None,
        active: None,
        extranonce: 0,
    };
    let mut data = json!({"ok": true, "request_id": request_id, "channel_id": channel_id,
        "channel_kind": channel.kind(), "user_identity": user,
        "difficulty": wire::target_difficulty(&target)});
    if let Some(n) = extranonce_size {
        data["extranonce_size"] = json!(n);
    }
    device.channels.insert(channel_id, channel);
    reply(
        &mut caller,
        ClientSendOutcome::Executed {
            detail: data.to_string(),
        },
    );
    device.emit(&actions::CHANNEL_EVENT, data, 0)
}

fn new_job(device: &mut Device, channel_id: u32, job: Job) -> Result<()> {
    let Some(ch) = device.channels.get_mut(&channel_id) else {
        return Ok(());
    };
    let active = job.ntime.is_some() && ch.prev.is_some();
    ch.remember(job.clone());
    if !active {
        return Ok(());
    }
    ch.active = Some(job.id);
    let data = ch.job_event(&job);
    device.emit(&actions::JOB_EVENT, data, 0)
}
