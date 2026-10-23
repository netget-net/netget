//! Job Declarator Client role (`role: job_declarator`): NetGet declares the block it wants to
//! mine to a Job Declaration Server (sv2-spec §6) — the model chooses the job, Rust writes it.
//!
//! After the Noise handshake (the JDS's certificate checked against its authority key) and
//! SetupConnection for the Job Declaration Protocol, one token is requested at once. The model
//! hears of every token and decides what to declare: the height, the coinbase value and the
//! transactions, structured as the template provider's are. Rust builds the coinbase the way
//! SRI's JDS reads one (a segwit serialisation whose scriptSig is the BIP 34 height, an
//! optional message and the extranonce space), pays the outputs the token requires with the
//! coinbase value on the first, as SRI's jd_client does, adds the witness commitment, and sends
//! DeclareMiningJob with the transactions' wtxids. ProvideMissingTransactions is answered from
//! the declaration in Rust. An accepted job can be mined and its solution pushed (PushSolution).
use super::actions::{self, StratumV2ClientProtocol};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::stratum_v2::bitcoin::{self as btc, Network, Tx, TxIn, TxOut};
use crate::server::stratum_v2::noise;
use crate::server::stratum_v2::wire::{self, Message};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use tokio::{io::WriteHalf, net::TcpStream, sync::mpsc};

/// The largest frame a JDS may send: ProvideMissingTransactions names at most 65535 positions.
pub const MAX_INBOUND_PAYLOAD: usize = 256 * 1024;
/// Tokens held at once; the oldest unused one is dropped past this.
pub const MAX_TOKENS: usize = 16;
/// Outputs a token may require the coinbase to pay.
pub const MAX_TOKEN_OUTPUTS: usize = 16;
/// Declarations remembered at once.
pub const MAX_DECLARED: usize = 16;
/// Bytes of extranonce a declared coinbase leaves for mining.
pub const EXTRANONCE_LEN: usize = 8;
/// A declared coinbase's message, in bytes.
pub const MAX_MESSAGE: usize = 32;

struct Token {
    value: Vec<u8>,
    outputs: Vec<TxOut>,
}

struct Declared {
    request_id: u32,
    /// How deep in a handler chain the declaration was made; its answer continues the chain.
    depth: usize,
    height: u32,
    version: u32,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    txs: Vec<Tx>,
    accepted: Option<bool>,
}

struct Jdc {
    writer: wire::FrameWriter<WriteHalf<TcpStream>>,
    tokens: VecDeque<Token>,
    declared: VecDeque<Declared>,
    /// Token requests awaiting an answer, with the chain depth that made them.
    token_requests: VecDeque<(u32, usize)>,
    next_request: u32,
    network: Network,
    user: String,
    events: mpsc::Sender<(Event, usize)>,
    /// What the job declarator sent, by message, for the summary logged when the session ends.
    received: BTreeMap<&'static str, u64>,
}

impl Jdc {
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

    async fn request_token(&mut self, user: &str, depth: usize) -> Result<u32> {
        self.next_request = self.next_request.wrapping_add(1);
        let request_id = self.next_request;
        if self.token_requests.len() >= MAX_TOKENS {
            self.token_requests.pop_front();
        }
        self.token_requests.push_back((request_id, depth));
        self.writer
            .send(&Message::AllocateMiningJobToken {
                user_identifier: user.as_bytes().to_vec(),
                request_id,
            })
            .await?;
        Ok(request_id)
    }
}

/// The coinbase a declaration carries, split around its extranonce: SRI's layout, a segwit
/// serialisation (marker and flag after the version) with the 32-byte witness reserved value.
pub fn declared_coinbase(
    height: u32,
    message: &[u8],
    outputs: &[TxOut],
    extranonce_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut script = btc::bip34_height_script(height);
    if !message.is_empty() {
        script.push(message.len() as u8);
        script.extend_from_slice(message);
    }
    script.push(extranonce_len as u8);
    let head_len = script.len();
    script.extend(std::iter::repeat_n(0u8, extranonce_len));
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            prev_txid: [0u8; 32],
            vout: u32::MAX,
            script_sig: script,
            sequence: u32::MAX,
            witness: vec![vec![0u8; 32]],
        }],
        outputs: outputs.to_vec(),
        locktime: 0,
    };
    let bytes = tx.serialize(true);
    // version, marker+flag, input count, outpoint, scriptSig length, then the script's head.
    let cut = 4 + 2 + 1 + 36 + 1 + head_len;
    (
        bytes[..cut].to_vec(),
        bytes[cut + extranonce_len..].to_vec(),
    )
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let param = |key: &str| -> Result<Option<String>> {
        Ok(ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten())
    };
    let authority_text = param("authority_public_key")?
        .context("authority_public_key is required: the JDS's base58check authority key")?;
    let authority = noise::decode_authority_key(&authority_text)
        .context("authority_public_key is not a base58check authority key")?;
    let user = param("user_identity")?.unwrap_or_else(|| actions::DEFAULT_USER.into());
    ensure!(user.len() <= 255, "user_identity must be at most 255 bytes");
    let network =
        Network::parse(&param("network")?.unwrap_or_else(|| actions::DEFAULT_NETWORK.into()))?;
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
    let (noise_session, cert) =
        wire::connect_handshake(&mut stream, &authority, super::SETUP_TIMEOUT)
            .await
            .context("Noise handshake with the job declarator failed")?;
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "Stratum V2 job declarator client: {peer} proved its key with a certificate from the configured authority, valid {}..{}",
        cert.valid_from, cert.not_valid_after
    ));
    let (r, w) = tokio::io::split(stream);
    let (mut reader, mut writer) = wire::transport(r, w, noise_session, MAX_INBOUND_PAYLOAD);
    writer
        .send(&Message::SetupConnection {
            protocol: wire::JOB_DECLARATION_PROTOCOL,
            min_version: wire::PROTOCOL_VERSION,
            max_version: wire::PROTOCOL_VERSION,
            flags: wire::DECLARE_TX_DATA,
            endpoint_host: peer.ip().to_string().into_bytes(),
            endpoint_port: peer.port(),
            vendor: b"NetGet".to_vec(),
            hardware_version: b"NetGet job declarator".to_vec(),
            firmware: concat!("netget-", env!("CARGO_PKG_VERSION"))
                .as_bytes()
                .to_vec(),
            device_id: Vec::new(),
        })
        .await?;
    let answer = reader
        .next(super::SETUP_TIMEOUT)
        .await?
        .context("the job declarator closed the connection after SetupConnection")?;
    match Message::decode(&answer)? {
        Message::SetupConnectionSuccess { used_version, flags } => log.info(format!(
            "Stratum V2 job declarator client: SetupConnection accepted (version {used_version}, flags {flags:#x})"
        )),
        Message::SetupConnectionError { flags, error_code } => bail!(
            "the job declarator refused SetupConnection: {} (flags {flags:#x})",
            wire::text(&error_code)
        ),
        other => bail!("the job declarator answered SetupConnection with {}", other.name()),
    }

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (msg_tx, msg_rx) = mpsc::channel::<Result<Message>>(64);
    let reader_task = tokio::spawn(async move {
        loop {
            let item = match reader.next(super::READ_IDLE).await {
                Ok(Some(frame)) if frame.extension() != 0 => continue,
                Ok(Some(frame)) => Message::decode(&frame),
                Ok(None) => Err(anyhow::anyhow!("the job declarator closed the connection")),
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
                    .warn(format!("Stratum V2 job declarator client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut jdc = Jdc {
            writer,
            tokens: VecDeque::new(),
            declared: VecDeque::new(),
            token_requests: VecDeque::new(),
            next_request: 0,
            network,
            user: user.clone(),
            events: event_tx,
            received: BTreeMap::new(),
        };
        let result = async {
            jdc.request_token(&user, 0).await?;
            session(&session_ctx, &mut jdc, msg_rx, external, internal_rx).await
        }
        .await;
        dispatcher_abort.abort();
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "Stratum V2 job declarator client received: {}",
            crate::server::stratum_v2::template_provider::summary(&jdc.received)
        ));
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx))
                    .warn(format!("Stratum V2 job declarator client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        jdc.writer.shutdown().await;
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

fn reply(caller: &mut Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = caller.take() {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

/// Build and send the declaration a `stratum_v2_declare_job` describes; the request id comes back.
async fn declare(jdc: &mut Jdc, a: &Value, depth: usize) -> Result<Value> {
    let height = a["height"].as_u64().context("height is required")? as u32;
    let (txs, fees) = btc::txs_from_json(&a["transactions"])?;
    let max_value = jdc.network.subsidy(height) + fees;
    let value = a["coinbase_value_sats"].as_u64().unwrap_or(max_value);
    ensure!(
        value <= max_value,
        "coinbase_value_sats {value} is more than the subsidy at height {height} plus fees ({max_value})"
    );
    let token = jdc
        .tokens
        .pop_front()
        .context("no mining job token is held; ask for one with stratum_v2_request_token")?;
    let mut outputs = token.outputs.clone();
    match outputs.first_mut() {
        Some(first) => first.value = value,
        None => outputs.push(TxOut {
            value,
            script: vec![0x51],
        }),
    }
    let wtxids: Vec<[u8; 32]> = txs.iter().map(Tx::wtxid).collect();
    outputs.push(btc::witness_commitment(&wtxids, &[0u8; 32]));
    let message = a["message"]
        .as_str()
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    let (prefix, suffix) = declared_coinbase(height, &message, &outputs, EXTRANONCE_LEN);
    let version = a["version"]
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(crate::server::stratum_v2::template_provider::DEFAULT_VERSION);
    jdc.next_request = jdc.next_request.wrapping_add(1);
    let request_id = jdc.next_request;
    jdc.writer
        .send(&Message::DeclareMiningJob {
            request_id,
            mining_job_token: token.value,
            version,
            coinbase_tx_prefix: prefix.clone(),
            coinbase_tx_suffix: suffix.clone(),
            wtxid_list: wtxids,
            excess_data: Vec::new(),
        })
        .await?;
    if jdc.declared.len() >= MAX_DECLARED {
        jdc.declared.pop_front();
    }
    let n = txs.len();
    jdc.declared.push_back(Declared {
        request_id,
        depth,
        height,
        version,
        prefix,
        suffix,
        txs,
        accepted: None,
    });
    Ok(
        json!({"request_id": request_id, "height": height, "transactions": n,
              "coinbase_value_sats": value}),
    )
}

/// Mine an accepted declaration on the given tip and push the first header that meets nbits.
async fn push_solution(jdc: &mut Jdc, a: &Value, log: &Log<'_>) -> Result<Value> {
    let prev_hash = btc::parse_txid(a["prev_hash"].as_str().context("prev_hash is required")?)?;
    let nbits = actions::nbits(a)?.context("nbits is required")?;
    let target = btc::check_bits(jdc.network, nbits)?;
    let job = match a["request_id"].as_u64() {
        Some(id) => jdc.declared.iter().find(|d| u64::from(d.request_id) == id),
        None => jdc.declared.iter().rev().find(|d| d.accepted == Some(true)),
    }
    .context("no such declared job")?;
    ensure!(
        job.accepted == Some(true),
        "declaration {} has not been accepted",
        job.request_id
    );
    let ntime = a["ntime"]
        .as_u64()
        .map(|t| t as u32)
        .unwrap_or_else(wire::now_secs);
    let max = a["max_hashes"]
        .as_u64()
        .unwrap_or(actions::DEFAULT_MINE_HASHES);
    let extranonce: [u8; EXTRANONCE_LEN] = rand::random();
    let coinbase = [&job.prefix[..], &extranonce, &job.suffix[..]].concat();
    let txid = Tx::parse(&coinbase)
        .context("the declared coinbase does not parse")?
        .txid();
    let txids: Vec<[u8; 32]> = job.txs.iter().map(Tx::txid).collect();
    let root = btc::fold_path(txid, &btc::coinbase_merkle_path(&txids));
    let header = wire::header(job.version, &prev_hash, &root, ntime, nbits, 0);
    let (request_id, version, height) = (job.request_id, job.version, job.height);
    let (nonce, hash, tried) =
        tokio::task::spawn_blocking(move || super::mine(header, target, max))
            .await
            .context("mining stopped")?;
    let found = wire::meets(&hash, &target);
    log.info(format!(
        "Stratum V2 job declarator client mined {tried} hashes on declaration {request_id}: {}",
        if found {
            "found a block"
        } else {
            "nothing met nbits"
        }
    ));
    if found {
        jdc.writer
            .send(&Message::PushSolution {
                extranonce: extranonce.to_vec(),
                prev_hash,
                nonce,
                ntime,
                nbits,
                version,
            })
            .await?;
    }
    Ok(
        json!({"request_id": request_id, "height": height, "found": found, "pushed": found,
              "hash": wire::display_hex(&hash), "hashes": tried, "nonce": nonce, "ntime": ntime}),
    )
}

async fn session(
    ctx: &ConnectContext,
    jdc: &mut Jdc,
    mut messages: mpsc::Receiver<Result<Message>>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            item = messages.recv() => {
                let Some(item) = item else { return Ok(()) };
                on_message(jdc, item?, &log).await?;
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
            log.warn(format!(
                "Stratum V2 job declarator client action refused: {error}"
            ));
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
        if depth > super::MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "Stratum V2 job declarator client: handler chain stopped after {} follow-ups",
                super::MAX_FOLLOWUP_DEPTH
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
        let result = match action["type"].as_str().unwrap_or_default() {
            actions::REQUEST_TOKEN => {
                let user = action["user_identifier"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| jdc.user.clone());
                jdc.request_token(&user, depth)
                    .await
                    .map(|id| json!({"request_id": id}))
            }
            actions::DECLARE_JOB => declare(jdc, &action, depth).await,
            actions::PUSH_SOLUTION => match push_solution(jdc, &action, &log).await {
                Ok(data) => {
                    jdc.emit(&actions::JD_SOLUTION_EVENT, data.clone(), depth)?;
                    Ok(data)
                }
                Err(e) => Err(e),
            },
            other => Err(anyhow::anyhow!(
                "{other} is a mining-device action; this client declares jobs"
            )),
        };
        match result {
            Ok(data) => reply(
                &mut injected,
                ClientSendOutcome::Executed {
                    detail: data.to_string(),
                },
            ),
            Err(e) => refuse(&mut injected, format!("{e:#}")),
        }
    }
}

async fn on_message(jdc: &mut Jdc, message: Message, log: &Log<'_>) -> Result<()> {
    *jdc.received.entry(message.name()).or_default() += 1;
    match message {
        Message::AllocateMiningJobTokenSuccess {
            request_id,
            mining_job_token,
            coinbase_outputs,
        } => {
            let outputs = match btc::parse_output_vector(&coinbase_outputs, MAX_TOKEN_OUTPUTS) {
                Ok(o) => o,
                Err(e) => {
                    log.warn(format!(
                        "Stratum V2 job declarator client: token for request {request_id} dropped: its coinbase outputs do not parse: {e:#}"
                    ));
                    return Ok(());
                }
            };
            let described: Vec<Value> = outputs.iter().map(btc::describe_output).collect();
            let depth = match jdc
                .token_requests
                .iter()
                .position(|(r, _)| *r == request_id)
            {
                Some(i) => jdc.token_requests.remove(i).map(|(_, d)| d).unwrap_or(0),
                None => 0,
            };
            if jdc.tokens.len() >= MAX_TOKENS {
                jdc.tokens.pop_front();
            }
            jdc.tokens.push_back(Token {
                value: mining_job_token,
                outputs,
            });
            jdc.emit(
                &actions::JD_TOKEN_EVENT,
                json!({"request_id": request_id, "coinbase_outputs": described,
                       "tokens_held": jdc.tokens.len()}),
                depth,
            )
        }
        Message::ProvideMissingTransactions {
            request_id,
            unknown_tx_position_list,
        } => {
            let Some(job) = jdc.declared.iter().find(|d| d.request_id == request_id) else {
                log.warn(format!(
                    "Stratum V2 job declarator client: ProvideMissingTransactions for request {request_id}, which was never declared"
                ));
                return Ok(());
            };
            let mut list = Vec::new();
            for position in &unknown_tx_position_list {
                match job.txs.get(usize::from(*position)) {
                    Some(tx) => list.push(tx.serialize(true)),
                    None => bail!(
                        "the job declarator asked for transaction {position} of declaration {request_id}, which has {}",
                        job.txs.len()
                    ),
                }
            }
            log.info(format!(
                "Stratum V2 job declarator client: providing {} transactions for declaration {request_id}",
                list.len()
            ));
            jdc.writer
                .send(&Message::ProvideMissingTransactionsSuccess {
                    request_id,
                    transaction_list: list,
                })
                .await?;
            Ok(())
        }
        Message::DeclareMiningJobSuccess {
            request_id,
            new_mining_job_token,
        } => {
            let Some(job) = jdc.declared.iter_mut().find(|d| d.request_id == request_id) else {
                return Ok(());
            };
            job.accepted = Some(true);
            let data = json!({"request_id": request_id, "accepted": true, "height": job.height,
                              "transactions": job.txs.len(),
                              "new_token_bytes": new_mining_job_token.len()});
            let depth = job.depth;
            jdc.emit(&actions::JD_DECLARE_RESULT_EVENT, data, depth)
        }
        Message::DeclareMiningJobError {
            request_id,
            error_code,
            ..
        } => {
            let Some(job) = jdc.declared.iter_mut().find(|d| d.request_id == request_id) else {
                return Ok(());
            };
            job.accepted = Some(false);
            let data = json!({"request_id": request_id, "accepted": false, "height": job.height,
                              "transactions": job.txs.len(), "error_code": wire::text(&error_code)});
            let depth = job.depth;
            jdc.emit(&actions::JD_DECLARE_RESULT_EVENT, data, depth)
        }
        other => bail!(
            "the job declarator sent {}, which a Job Declaration Server does not send",
            other.name()
        ),
    }
}
