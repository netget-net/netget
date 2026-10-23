//! Job Declarator Server role (`role: job_declarator`): the Job Declaration Protocol server a
//! miner's Job Declarator Client declares its own block templates to (sv2-spec §6).
//!
//! The model decides whether a client is given a mining job token and whether a declared job
//! is accepted, with the error code it chooses. Rust keeps what the protocol needs kept: the
//! token table (bounded per connection, oldest evicted, a token usable once and only by the
//! connection it was issued to), a mempool of the transactions clients have supplied, keyed by
//! wtxid and bounded in count and bytes, the positions it asks a client to fill with
//! ProvideMissingTransactions, and the jobs it accepted so a PushSolution can be rebuilt into
//! its block and checked. Every count a client declares is bounded before anything is
//! allocated for it, and a declaration is only shown to the model once its coinbase parses,
//! its transactions match the wtxids it named and its witness commitment is right.
//!
//! There is no AllocateMiningJobToken.Error in the protocol (job_declaration_sv2 10.0, which
//! sv2-apps v0.8.0 speaks), so a refused allocation ends the connection.
use super::bitcoin::{self as btc, Tx, TxOut};
use super::wire::{self, FrameReader, FrameWriter, Message};
use super::{actions, consult, outcome, Consult, Pool};
use crate::logging::emit::{Log, Sink};
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use anyhow::{ensure, Result};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// The largest frame a Job Declarator Client may send: a ProvideMissingTransactions.Success
/// carrying a block's worth of transactions.
pub const MAX_INBOUND_PAYLOAD: usize = 4 * 1024 * 1024;
/// Tokens one connection may hold, allocated and active together; the oldest is evicted.
pub const MAX_TOKENS: usize = 64;
/// Transactions one DeclareMiningJob may name.
pub const MAX_DECLARED_TXS: usize = 8192;
/// Declarations waiting on ProvideMissingTransactions per connection.
pub const MAX_PENDING: usize = 16;
/// Accepted jobs remembered per connection for PushSolution.
pub const MAX_JOBS: usize = 16;
/// The shared mempool: at most this many transactions and bytes, oldest evicted.
pub const MAX_MEMPOOL_TXS: usize = 16_384;
pub const MAX_MEMPOOL_BYTES: usize = 32 * 1024 * 1024;
/// SRI's full-extranonce bound: PushSolution carries it as a B0_32.
pub const MAX_EXTRANONCE: usize = 32;
/// Outputs the model may require in AllocateMiningJobToken.Success.
pub const MAX_ALLOCATE_OUTPUTS: usize = 4;

/// Transactions clients have supplied, by wtxid, shared by every connection of one server.
#[derive(Default)]
pub(crate) struct Mempool {
    txs: HashMap<[u8; 32], (Vec<u8>, Tx)>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}

impl Mempool {
    pub(crate) fn contains(&self, wtxid: &[u8; 32]) -> bool {
        self.txs.contains_key(wtxid)
    }
    pub(crate) fn get(&self, wtxid: &[u8; 32]) -> Option<Tx> {
        self.txs.get(wtxid).map(|(_, tx)| tx.clone())
    }
    pub(crate) fn insert(&mut self, wtxid: [u8; 32], raw: Vec<u8>, tx: Tx) {
        if self.txs.contains_key(&wtxid) {
            return;
        }
        while !self.order.is_empty()
            && (self.txs.len() >= MAX_MEMPOOL_TXS || self.bytes + raw.len() > MAX_MEMPOOL_BYTES)
        {
            if let Some(old) = self.order.pop_front() {
                if let Some((raw, _)) = self.txs.remove(&old) {
                    self.bytes -= raw.len();
                }
            }
        }
        self.bytes += raw.len();
        self.order.push_back(wtxid);
        self.txs.insert(wtxid, (raw, tx));
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokenState {
    Allocated,
    Active,
}

struct Token {
    value: [u8; 8],
    state: TokenState,
    outputs: Vec<TxOut>,
}

/// A declaration whose coinbase has been split back into prefix, extranonce space and suffix.
#[derive(Clone)]
struct Declared {
    request_id: u32,
    token: [u8; 8],
    version: u32,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    extranonce_len: usize,
    coinbase: Tx,
    wtxids: Vec<[u8; 32]>,
    /// Filled once every transaction is known.
    txs: Vec<Tx>,
    missing: Vec<u16>,
}

pub(crate) struct Conn {
    setup: bool,
    tokens: VecDeque<Token>,
    pending: VecDeque<Declared>,
    jobs: VecDeque<Declared>,
    received: BTreeMap<&'static str, u64>,
}

impl Conn {
    fn new() -> Self {
        Self {
            setup: false,
            tokens: VecDeque::new(),
            pending: VecDeque::new(),
            jobs: VecDeque::new(),
            received: BTreeMap::new(),
        }
    }

    /// Issue a fresh token, evicting the oldest when the table is full.
    fn issue(&mut self, state: TokenState, outputs: Vec<TxOut>) -> [u8; 8] {
        if self.tokens.len() >= MAX_TOKENS {
            self.tokens.pop_front();
        }
        let value: [u8; 8] = rand::random();
        self.tokens.push_back(Token {
            value,
            state,
            outputs,
        });
        value
    }

    fn take_allocated(&mut self, token: &[u8]) -> Option<Token> {
        let at = self
            .tokens
            .iter()
            .position(|t| t.value[..] == *token && t.state == TokenState::Allocated)?;
        self.tokens.remove(at)
    }
}

/// Split a declared coinbase the way SRI's JDS does: the prefix runs to the end of the
/// scriptSig bytes the client wrote, the full extranonce fills the rest of the scriptSig, and
/// the suffix follows. Both the segwit layout SRI's jd_client writes and a legacy one parse.
fn split_coinbase(prefix: &[u8], suffix: &[u8]) -> Result<(Tx, usize)> {
    let segwit = prefix.get(4..6) == Some(&[0x00, 0x01][..]);
    let script_len_at = if segwit { 43 } else { 41 };
    ensure!(
        prefix.len() > script_len_at,
        "the coinbase prefix ends before its scriptSig length"
    );
    let mut c = btc::Cursor::new(&prefix[script_len_at..]);
    let script_len = c.varint()? as usize;
    ensure!(
        script_len <= btc::MAX_COINBASE_SCRIPT_SIG,
        "a {script_len}-byte coinbase scriptSig (at most 100)"
    );
    let in_prefix = prefix.len() - script_len_at - c.pos;
    ensure!(
        in_prefix <= script_len,
        "the coinbase prefix runs past its scriptSig"
    );
    let extranonce_len = script_len - in_prefix;
    ensure!(
        extranonce_len <= MAX_EXTRANONCE,
        "a {extranonce_len}-byte extranonce (at most {MAX_EXTRANONCE})"
    );
    let bytes = [prefix, &vec![0u8; extranonce_len], suffix].concat();
    Ok((Tx::parse(&bytes)?, extranonce_len))
}

fn error(request_id: u32, code: &str) -> Message {
    Message::DeclareMiningJobError {
        request_id,
        error_code: code.as_bytes().to_vec(),
        error_details: Vec::new(),
    }
}

/// The checks a complete declaration must pass before the model sees it.
fn complete(job: &Declared) -> std::result::Result<(), &'static str> {
    if btc::bip34_height(&job.coinbase.inputs[0].script_sig).is_none() {
        return Err("invalid-coinbase-tx");
    }
    if job.coinbase.has_witness() {
        let input = &job.coinbase.inputs[0];
        let Some(reserved) = (input.witness.len() == 1)
            .then(|| <[u8; 32]>::try_from(input.witness[0].as_slice()).ok())
            .flatten()
        else {
            return Err("invalid-coinbase-tx");
        };
        let expected = btc::witness_commitment(&job.wtxids, &reserved);
        if btc::find_witness_commitment(&job.coinbase.outputs) != Some(&expected) {
            return Err("invalid-job");
        }
    }
    Ok(())
}

pub(super) async fn run<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    ctx: &SpawnContext,
    pool: &Pool,
    id: ConnectionId,
    peer: SocketAddr,
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    idle: Duration,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    let mut conn = Conn::new();
    let result = async {
        while let Some(frame) = reader.next(idle).await? {
            ctx.state
                .update_connection_stats(ctx.server_id, id, None, None, Some(1), None)
                .await;
            if frame.extension() != 0 {
                continue;
            }
            let message = Message::decode(&frame)?;
            *conn.received.entry(message.name()).or_default() += 1;
            let (out, close) = handle(ctx, pool, &mut conn, id, peer, message).await;
            let mut sent = 0;
            for m in &out {
                sent += writer.send(m).await?;
            }
            if !out.is_empty() {
                ctx.state
                    .update_connection_stats(
                        ctx.server_id,
                        id,
                        None,
                        Some(sent as u64),
                        None,
                        Some(out.len() as u64),
                    )
                    .await;
            }
            if close {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    log.info(format!(
        "Stratum V2 job declarator connection {id} received: {}",
        super::template_provider::summary(&conn.received)
    ));
    result
}

fn mempool(pool: &Pool) -> std::sync::MutexGuard<'_, Mempool> {
    pool.mempool.lock().unwrap_or_else(|e| e.into_inner())
}

/// The model's verdict on a declaration whose transactions are all known.
async fn evaluate(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    mut job: Declared,
    outputs: Vec<TxOut>,
) -> Message {
    let log = Log::new(Some(&ctx.status_tx));
    {
        let mp = mempool(pool);
        job.txs = job.wtxids.iter().filter_map(|w| mp.get(w)).collect();
    }
    if job.txs.len() != job.wtxids.len() {
        return error(job.request_id, "missing-txs");
    }
    if let Err(code) = complete(&job) {
        log.info(format!(
            "Stratum V2 job declarator connection {id}: declaration {} refused: {code}",
            job.request_id
        ));
        outcome(ctx, id, "jd_declare_mining_job", "refused_invalid_job");
        return error(job.request_id, code);
    }
    let coinbase = &job.coinbase;
    let pays_pool = outputs
        .iter()
        .all(|required| coinbase.outputs.iter().any(|o| o.script == required.script));
    let weight: u64 = job.txs.iter().map(Tx::weight).sum::<u64>() + coinbase.weight();
    let event = Event::new(
        &actions::JD_DECLARE_EVENT,
        json!({"request_id": job.request_id, "version": job.version,
               "height": btc::bip34_height(&coinbase.inputs[0].script_sig),
               "coinbase_outputs": coinbase.outputs.iter().map(btc::describe_output).collect::<Vec<_>>(),
               "coinbase_value_sats": coinbase.outputs.iter().map(|o| o.value).sum::<u64>(),
               "pays_required_outputs": pays_pool, "transactions": job.txs.len(),
               "weight": weight, "extranonce_size": job.extranonce_len,
               "remote_addr": peer.to_string()}),
    );
    match consult(ctx, id, event, "jd_declare_mining_job").await {
        Consult::Answer {
            verdict: Some(Ok(())),
            ..
        } => {
            let new_token = conn.issue(TokenState::Active, outputs);
            job.token = new_token;
            if conn.jobs.len() >= MAX_JOBS {
                conn.jobs.pop_front();
            }
            let request_id = job.request_id;
            conn.jobs.push_back(job);
            Message::DeclareMiningJobSuccess {
                request_id,
                new_mining_job_token: new_token.to_vec(),
            }
        }
        Consult::Answer {
            verdict: Some(Err(code)),
            ..
        } => error(job.request_id, &code),
        // Silence and failure both refuse: a job is never accepted without the model's yes.
        Consult::Answer { verdict: None, .. } => error(job.request_id, "service-unavailable"),
        Consult::Fail(code) => error(job.request_id, code),
    }
}

async fn handle(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    message: Message,
) -> (Vec<Message>, bool) {
    let log = Log::new(Some(&ctx.status_tx));
    if !conn.setup && !matches!(message, Message::SetupConnection { .. }) {
        log.warn(format!(
            "Stratum V2 job declarator connection {id} refused: {} before SetupConnection",
            message.name()
        ));
        return (Vec::new(), true);
    }
    match message {
        Message::SetupConnection {
            protocol,
            min_version,
            max_version,
            flags,
            endpoint_host,
            endpoint_port,
            vendor,
            hardware_version,
            firmware,
            device_id,
        } => {
            if conn.setup {
                return (Vec::new(), true);
            }
            let refuse = |flags: u32, code: &str| {
                log.info(format!(
                    "Stratum V2 job declarator connection {id} setup refused: {code}"
                ));
                (
                    vec![Message::SetupConnectionError {
                        flags,
                        error_code: code.as_bytes().to_vec(),
                    }],
                    true,
                )
            };
            if protocol != wire::JOB_DECLARATION_PROTOCOL {
                return refuse(0, "unsupported-protocol");
            }
            if min_version > wire::PROTOCOL_VERSION || max_version < wire::PROTOCOL_VERSION {
                return refuse(0, "protocol-version-mismatch");
            }
            if flags & !wire::DECLARE_TX_DATA != 0 {
                return refuse(flags & !wire::DECLARE_TX_DATA, "unsupported-feature-flags");
            }
            let event = Event::new(
                &actions::JD_SETUP_EVENT,
                json!({"vendor": wire::text(&vendor), "hardware_version": wire::text(&hardware_version),
                       "firmware": wire::text(&firmware), "device_id": wire::text(&device_id),
                       "endpoint_host": wire::text(&endpoint_host), "endpoint_port": endpoint_port,
                       "declare_tx_data": flags & wire::DECLARE_TX_DATA != 0,
                       "remote_addr": peer.to_string()}),
            );
            match consult(ctx, id, event, "jd_setup_connection").await {
                Consult::Answer {
                    verdict: Some(Ok(())),
                    ..
                } => {
                    conn.setup = true;
                    (
                        vec![Message::SetupConnectionSuccess {
                            used_version: wire::PROTOCOL_VERSION,
                            flags: flags & wire::DECLARE_TX_DATA,
                        }],
                        false,
                    )
                }
                Consult::Answer {
                    verdict: Some(Err(code)),
                    ..
                } => refuse(0, &code),
                Consult::Answer { verdict: None, .. } => refuse(0, "service-unavailable"),
                Consult::Fail(code) => refuse(0, code),
            }
        }
        Message::AllocateMiningJobToken {
            user_identifier,
            request_id,
        } => {
            let event = Event::new(
                &actions::JD_ALLOCATE_EVENT,
                json!({"user_identifier": wire::text(&user_identifier), "request_id": request_id,
                       "tokens_held": conn.tokens.len(), "max_tokens": MAX_TOKENS,
                       "remote_addr": peer.to_string()}),
            );
            let allocation = match consult(ctx, id, event, "jd_allocate_mining_job_token").await {
                Consult::Answer {
                    verdict: Some(Ok(())),
                    extras,
                } => extras
                    .into_iter()
                    .find(|a| a["type"] == actions::ALLOCATE_TOKEN)
                    .unwrap_or_else(|| json!({"type": actions::ALLOCATE_TOKEN})),
                Consult::Answer { verdict, .. } => {
                    log.info(format!(
                        "Stratum V2 job declarator connection {id}: no token for request {request_id} ({}); the protocol has no AllocateMiningJobToken.Error, so the connection ends",
                        match verdict {
                            Some(Err(code)) => code,
                            _ => "the model gave no answer".into(),
                        }
                    ));
                    return (Vec::new(), true);
                }
                Consult::Fail(code) => {
                    log.info(format!(
                        "Stratum V2 job declarator connection {id}: no token for request {request_id} ({code}); the connection ends"
                    ));
                    return (Vec::new(), true);
                }
            };
            let outputs = match actions::allocation_outputs(&allocation) {
                Ok(o) => o,
                Err(e) => {
                    log.warn(format!(
                        "Stratum V2 job declarator connection {id}: the model's allocation was refused: {e:#}; the connection ends"
                    ));
                    return (Vec::new(), true);
                }
            };
            let token = conn.issue(TokenState::Allocated, outputs.clone());
            log.info(format!(
                "Stratum V2 job declarator connection {id}: token {} allocated for request {request_id} ({} held)",
                hex::encode(token),
                conn.tokens.len()
            ));
            (
                vec![Message::AllocateMiningJobTokenSuccess {
                    request_id,
                    mining_job_token: token.to_vec(),
                    coinbase_outputs: btc::output_vector_bytes(&outputs),
                }],
                false,
            )
        }
        Message::DeclareMiningJob {
            request_id,
            mining_job_token,
            version,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            wtxid_list,
            ..
        } => {
            let refuse = |code: &str, why: String| {
                log.info(format!(
                    "Stratum V2 job declarator connection {id}: declaration {request_id} refused: {code} ({why})"
                ));
                (vec![error(request_id, code)], false)
            };
            if wtxid_list.len() > MAX_DECLARED_TXS {
                return refuse(
                    "invalid-job",
                    format!(
                        "{} transactions declared, at most {MAX_DECLARED_TXS}",
                        wtxid_list.len()
                    ),
                );
            }
            if conn.pending.len() >= MAX_PENDING {
                return refuse(
                    "invalid-job",
                    format!("{MAX_PENDING} declarations are already waiting"),
                );
            }
            let Some(token) = conn.take_allocated(&mining_job_token) else {
                return refuse(
                    "invalid-mining-job-token",
                    "not a token this connection holds unused".into(),
                );
            };
            let (coinbase, extranonce_len) =
                match split_coinbase(&coinbase_tx_prefix, &coinbase_tx_suffix) {
                    Ok(v) => v,
                    Err(e) => return refuse("invalid-coinbase-tx", format!("{e:#}")),
                };
            if !coinbase.is_coinbase() {
                return refuse(
                    "invalid-coinbase-tx-input",
                    "the coinbase must have exactly one input spending the null outpoint".into(),
                );
            }
            let missing: Vec<u16> = {
                let mp = mempool(pool);
                wtxid_list
                    .iter()
                    .enumerate()
                    .filter(|(_, w)| !mp.contains(w))
                    .map(|(i, _)| i as u16)
                    .collect()
            };
            let job = Declared {
                request_id,
                token: token.value,
                version,
                prefix: coinbase_tx_prefix,
                suffix: coinbase_tx_suffix,
                extranonce_len,
                coinbase,
                wtxids: wtxid_list,
                txs: Vec::new(),
                missing: missing.clone(),
            };
            if !missing.is_empty() {
                log.info(format!(
                    "Stratum V2 job declarator connection {id}: declaration {request_id} names {} transactions this server does not have; asking for them",
                    missing.len()
                ));
                // The token stays spent: it is restored only if the declaration is refused.
                conn.tokens.push_back(Token {
                    state: TokenState::Active,
                    ..token
                });
                conn.pending.push_back(job);
                return (
                    vec![Message::ProvideMissingTransactions {
                        request_id,
                        unknown_tx_position_list: missing,
                    }],
                    false,
                );
            }
            (
                vec![evaluate(ctx, pool, conn, id, peer, job, token.outputs).await],
                false,
            )
        }
        Message::ProvideMissingTransactionsSuccess {
            request_id,
            transaction_list,
        } => {
            let Some(at) = conn.pending.iter().position(|p| p.request_id == request_id) else {
                log.warn(format!(
                    "Stratum V2 job declarator connection {id}: ProvideMissingTransactions.Success for request {request_id}, which is not waiting"
                ));
                return (Vec::new(), false);
            };
            let job = conn.pending.remove(at).expect("position found it");
            // The token was parked as active while the declaration waited; take it back out.
            let outputs = match conn.tokens.iter().position(|t| t.value == job.token) {
                Some(i) => conn.tokens.remove(i).map(|t| t.outputs).unwrap_or_default(),
                None => {
                    return (vec![error(request_id, "invalid-mining-job-token")], false);
                }
            };
            if transaction_list.len() != job.missing.len() {
                log.info(format!(
                    "Stratum V2 job declarator connection {id}: declaration {request_id} asked for {} transactions and got {}",
                    job.missing.len(),
                    transaction_list.len()
                ));
                return (vec![error(request_id, "missing-txs")], false);
            }
            for (position, raw) in job.missing.iter().zip(transaction_list) {
                let declared = job.wtxids[usize::from(*position)];
                let tx = match Tx::parse(&raw) {
                    Ok(tx) => tx,
                    Err(e) => {
                        log.info(format!(
                            "Stratum V2 job declarator connection {id}: declaration {request_id} transaction {position} does not parse: {e:#}"
                        ));
                        return (vec![error(request_id, "invalid-job")], false);
                    }
                };
                if tx.wtxid() != declared {
                    log.info(format!(
                        "Stratum V2 job declarator connection {id}: declaration {request_id} transaction {position} is not the one its wtxid named"
                    ));
                    return (vec![error(request_id, "invalid-job")], false);
                }
                mempool(pool).insert(declared, raw, tx);
            }
            (
                vec![evaluate(ctx, pool, conn, id, peer, job, outputs).await],
                false,
            )
        }
        Message::PushSolution {
            extranonce,
            prev_hash,
            nonce,
            ntime,
            nbits,
            version,
        } => {
            let target = match btc::check_bits(pool.network, nbits) {
                Ok(t) => t,
                Err(e) => {
                    log.warn(format!(
                        "Stratum V2 job declarator connection {id}: PushSolution refused: {e:#}"
                    ));
                    outcome(ctx, id, "jd_push_solution", "refused_invalid_solution");
                    return (Vec::new(), false);
                }
            };
            // The message names no job: the one whose coinbase, with this extranonce, hashes
            // below the target is the one solved.
            let found = conn.jobs.iter().rev().find_map(|job| {
                if job.extranonce_len != extranonce.len() {
                    return None;
                }
                let coinbase = [&job.prefix[..], &extranonce, &job.suffix[..]].concat();
                let cb = Tx::parse(&coinbase).ok()?;
                let txids: Vec<[u8; 32]> = job.txs.iter().map(Tx::txid).collect();
                let root = btc::fold_path(cb.txid(), &btc::coinbase_merkle_path(&txids));
                let header = wire::header(version, &prev_hash, &root, ntime, nbits, nonce);
                let hash = wire::sha256d(&header);
                wire::meets(&hash, &target).then(|| {
                    (
                        job.request_id,
                        hash,
                        btc::bip34_height(&cb.inputs[0].script_sig),
                        btc::block_bytes(&header, &coinbase, &job.txs),
                    )
                })
            });
            let Some((request_id, hash, height, block)) = found else {
                log.warn(format!(
                    "Stratum V2 job declarator connection {id}: PushSolution matches no accepted job with a hash below nbits {nbits:08x}"
                ));
                outcome(ctx, id, "jd_push_solution", "refused_invalid_solution");
                return (Vec::new(), false);
            };
            let hash = wire::display_hex(&hash);
            log.info(format!(
                "Stratum V2 job declarator connection {id}: block {hash} solves declaration {request_id} ({} bytes)",
                block.len()
            ));
            // A declared block can be megabytes; it goes to the file log only.
            log.info_to(
                Sink::FileOnly,
                format!(
                    "Stratum V2 job declarator block {hash}: {}",
                    hex::encode(&block)
                ),
            );
            let event = Event::new(
                &actions::JD_SOLUTION_EVENT,
                json!({"request_id": request_id, "hash": hash, "height": height,
                       "prev_hash": wire::display_hex(&prev_hash), "nbits": format!("{nbits:08x}"),
                       "ntime": ntime, "nonce": nonce, "version": version,
                       "block_size": block.len(), "remote_addr": peer.to_string()}),
            );
            // PushSolution has no reply; the model is told, and what it answers changes nothing.
            let _ = consult(ctx, id, event, "jd_push_solution").await;
            (Vec::new(), false)
        }
        other => {
            log.warn(format!(
                "Stratum V2 job declarator connection {id} refused: {} is not a message a Job Declarator Client sends",
                other.name()
            ));
            (Vec::new(), true)
        }
    }
}
