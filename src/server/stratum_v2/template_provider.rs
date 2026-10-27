//! Template Provider role (`role: template_provider`): the Template Distribution Protocol
//! server a pool or Job Declarator Client takes its work from (sv2-spec §7).
//!
//! The model decides every template — the chain tip it builds on (prev hash, height, nbits,
//! timestamp), the block version, the coinbase value and the transactions — and Rust makes the
//! template self-consistent: it serialises the transactions, computes their txids and the
//! coinbase's merkle path, the BIP 141 witness commitment the coinbase must carry, the BIP 34
//! height push the coinbase scriptSig starts with, and refuses a template whose height, nbits,
//! value or weight no node would accept. SetNewPrevHash follows a template on a new tip, as
//! Bitcoin Core does. RequestTransactionData is answered from what was sent, and every
//! SubmitSolution is rebuilt into its block and its header hash checked against the template's
//! target before the model hears of it; the block is logged so it can be relayed.
use super::bitcoin::{self as btc, Network, Tx, TxOut};
use super::wire::{self, FrameReader, FrameWriter, Message};
use super::{actions, consult, outcome, Consult, Pool};
use crate::logging::emit::{Log, Sink};
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// The largest frame a Template Distribution client may send: SubmitSolution carries the
/// coinbase as a B0_64K, so 64 KiB and its few fixed fields.
pub const MAX_INBOUND_PAYLOAD: usize = 66 * 1024;
/// Templates one connection remembers for RequestTransactionData and SubmitSolution.
pub const MAX_TEMPLATES: usize = 32;
/// Templates one answer of the model may send.
pub const MAX_TEMPLATES_PER_ANSWER: usize = 4;
/// Solutions remembered per connection, so a repeat is not reported twice.
pub const MAX_SEEN_SOLUTIONS: usize = 1024;
pub const COINBASE_TX_VERSION: u32 = 2;
pub const COINBASE_SEQUENCE: u32 = u32::MAX;
pub const COINBASE_LOCKTIME: u32 = 0;
pub const DEFAULT_VERSION: u32 = 0x2000_0000;
/// No chain is anywhere near this tall; a height past it is a mistake.
pub const MAX_HEIGHT: u32 = 10_000_000;
/// What a coinbase and the header take from the block weight before any transaction.
const BASE_WEIGHT: u64 = 80 * 4 + 1000 * 4;

#[derive(Clone)]
pub(crate) struct Template {
    pub id: u64,
    pub prev_hash: [u8; 32],
    pub height: u32,
    pub nbits: u32,
    pub target: [u8; 32],
    pub ntime: u32,
    pub version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_value: u64,
    pub coinbase_outputs: Vec<TxOut>,
    pub txs: Vec<Tx>,
    pub merkle_path: Vec<[u8; 32]>,
    /// Whether a solution of it has been logged in full to the operator already.
    pub announced: bool,
}

impl Template {
    fn message(&self, future: bool) -> Message {
        Message::NewTemplate {
            template_id: self.id,
            future_template: future,
            version: self.version,
            coinbase_tx_version: COINBASE_TX_VERSION,
            coinbase_prefix: self.coinbase_prefix.clone(),
            coinbase_tx_input_sequence: COINBASE_SEQUENCE,
            coinbase_tx_value_remaining: self.coinbase_value,
            coinbase_tx_outputs_count: self.coinbase_outputs.len() as u32,
            coinbase_tx_outputs: btc::outputs_bytes(&self.coinbase_outputs),
            coinbase_tx_locktime: COINBASE_LOCKTIME,
            merkle_path: self.merkle_path.clone(),
        }
    }
}

#[derive(Clone, Copy)]
struct Tip {
    prev_hash: [u8; 32],
    height: u32,
    nbits: u32,
    ntime: u32,
}

pub(crate) struct Conn {
    setup: bool,
    constraints: Option<(u32, u16)>,
    templates: VecDeque<Template>,
    tip: Option<Tip>,
    next_id: u64,
    solved: VecDeque<[u8; 32]>,
    received: BTreeMap<&'static str, u64>,
}

impl Conn {
    pub(crate) fn new() -> Self {
        Self {
            setup: false,
            constraints: None,
            templates: VecDeque::new(),
            tip: None,
            next_id: 1,
            solved: VecDeque::new(),
            received: BTreeMap::new(),
        }
    }
}

/// An unsigned number from a JSON number or a hex string ("207fffff", as RPC shows nbits).
fn number_or_hex(v: &Value, key: &str) -> Result<Option<u32>> {
    match &v[key] {
        Value::Null => Ok(None),
        Value::Number(n) => {
            let n = n
                .as_u64()
                .with_context(|| format!("{key} must be unsigned"))?;
            ensure!(n <= u64::from(u32::MAX), "{key} must fit 32 bits");
            Ok(Some(n as u32))
        }
        Value::String(s) => Ok(Some(
            u32::from_str_radix(s.trim_start_matches("0x"), 16)
                .with_context(|| format!("{key} {s:?} is not hex"))?,
        )),
        _ => bail!("{key} must be a number or hex text"),
    }
}

/// Everything about a `stratum_v2_new_template` that does not depend on the connection.
pub fn check_action(v: &Value) -> Result<()> {
    if let Some(h) = v["prev_hash"].as_str() {
        btc::parse_txid(h).context("prev_hash")?;
    }
    if let Some(h) = v["height"].as_u64() {
        ensure!(
            (1..=u64::from(MAX_HEIGHT)).contains(&h),
            "height must be 1..={MAX_HEIGHT}"
        );
    }
    if let Some(bits) = number_or_hex(v, "nbits")? {
        btc::compact_to_target(bits)?;
    }
    number_or_hex(v, "version")?;
    if let Some(t) = v.get("ntime").filter(|t| !t.is_null()) {
        ensure!(
            t.as_u64().is_some_and(|t| t <= u64::from(u32::MAX)),
            "ntime must be a 32-bit unix time"
        );
    }
    if let Some(c) = v.get("coinbase_value_sats").filter(|c| !c.is_null()) {
        ensure!(
            c.as_u64().is_some_and(|c| c <= btc::MAX_MONEY),
            "coinbase_value_sats must be 0..=21M BTC in sats"
        );
    }
    btc::txs_from_json(&v["transactions"])?;
    Ok(())
}

/// Build the template a `stratum_v2_new_template` describes on this connection, and the
/// messages announcing it: NewTemplate, plus SetNewPrevHash when it moves the tip.
pub(crate) fn build(
    conn: &mut Conn,
    network: Network,
    a: &Value,
    now: u32,
) -> Result<(Template, Vec<Message>)> {
    check_action(a)?;
    let (txs, fees) = btc::txs_from_json(&a["transactions"])?;
    let prev = a["prev_hash"].as_str().map(btc::parse_txid).transpose()?;
    let new_tip = match (prev, conn.tip) {
        (Some(p), Some(tip)) => p != tip.prev_hash,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => bail!("the first template must name prev_hash and height"),
    };
    let height = a["height"].as_u64().map(|h| h as u32);
    let bits = number_or_hex(a, "nbits")?;
    let tip = if new_tip {
        let height = height.context("a template on a new prev_hash must give its height")?;
        let nbits = bits.unwrap_or(network.pow_limit_bits());
        let ntime = a["ntime"].as_u64().map(|t| t as u32).unwrap_or(now);
        Tip {
            prev_hash: prev.expect("new_tip implies prev_hash"),
            height,
            nbits,
            ntime,
        }
    } else {
        let tip = conn.tip.expect("not new_tip implies a tip");
        ensure!(
            height.is_none_or(|h| h == tip.height),
            "height {} differs from the current tip's {}; a new height needs a new prev_hash",
            height.unwrap_or_default(),
            tip.height
        );
        ensure!(
            bits.is_none_or(|b| b == tip.nbits),
            "nbits can only change with a new prev_hash"
        );
        tip
    };
    let target = btc::check_bits(network, tip.nbits)?;
    let version = number_or_hex(a, "version")?.unwrap_or(DEFAULT_VERSION);
    ensure!(
        version >= 4,
        "version {version} is below 4, which nodes refuse since BIP 65 (bad-version)"
    );
    let max_value = network.subsidy(tip.height) + fees;
    let coinbase_value = match a["coinbase_value_sats"].as_u64() {
        Some(v) => {
            ensure!(
                v <= max_value,
                "coinbase_value_sats {v} is more than the subsidy at height {} plus fees ({max_value})",
                tip.height
            );
            v
        }
        None => max_value,
    };
    let weight: u64 = BASE_WEIGHT
        + txs.iter().map(Tx::weight).sum::<u64>()
        + u64::from(conn.constraints.map(|c| c.0).unwrap_or(0)) * 4;
    ensure!(
        weight <= btc::MAX_BLOCK_WEIGHT,
        "the template weighs {weight}, more than a block may"
    );
    let txids: Vec<[u8; 32]> = txs.iter().map(Tx::txid).collect();
    let wtxids: Vec<[u8; 32]> = txs.iter().map(Tx::wtxid).collect();
    let template = Template {
        id: conn.next_id,
        prev_hash: tip.prev_hash,
        height: tip.height,
        nbits: tip.nbits,
        target,
        ntime: tip.ntime,
        version,
        coinbase_prefix: btc::bip34_height_script(tip.height),
        coinbase_value,
        // The coinbase's witness reserved value is 32 zero bytes, as SRI's pool writes it.
        coinbase_outputs: vec![btc::witness_commitment(&wtxids, &[0u8; 32])],
        merkle_path: btc::coinbase_merkle_path(&txids),
        txs,
        announced: false,
    };
    conn.next_id += 1;
    let mut out = vec![template.message(new_tip)];
    if new_tip {
        out.push(Message::TemplateSetNewPrevHash {
            template_id: template.id,
            prev_hash: tip.prev_hash,
            header_timestamp: tip.ntime,
            nbits: tip.nbits,
            target,
        });
        conn.tip = Some(tip);
    }
    if conn.templates.len() >= MAX_TEMPLATES {
        conn.templates.pop_front();
    }
    conn.templates.push_back(template.clone());
    Ok((template, out))
}

/// A verified solution: its hash, the block it completes, and the coinbase it was mined with.
pub(crate) struct Solved {
    pub hash: [u8; 32],
    pub block: Vec<u8>,
    pub coinbase: Tx,
}

/// Rebuild a SubmitSolution into its block and check it against its template. The error is
/// the reason, in the vocabulary Bitcoin Core's block checks use where one exists.
pub(crate) fn verify(
    t: &Template,
    version: u32,
    ntime: u32,
    nonce: u32,
    coinbase_bytes: &[u8],
    now: u32,
) -> std::result::Result<Solved, String> {
    let coinbase = Tx::parse(coinbase_bytes).map_err(|e| format!("bad-cb-malformed: {e:#}"))?;
    if !coinbase.is_coinbase() {
        return Err("bad-cb-missing: the transaction does not spend the null outpoint".into());
    }
    let input = &coinbase.inputs[0];
    if !(2..=btc::MAX_COINBASE_SCRIPT_SIG).contains(&input.script_sig.len()) {
        return Err("bad-cb-length".into());
    }
    if !input.script_sig.starts_with(&t.coinbase_prefix) {
        return Err(
            "bad-cb-height: the scriptSig does not start with the template's height".into(),
        );
    }
    if coinbase.version != COINBASE_TX_VERSION
        || input.sequence != COINBASE_SEQUENCE
        || coinbase.locktime != COINBASE_LOCKTIME
    {
        return Err(
            "coinbase-mismatch: version, sequence or locktime differ from the template".into(),
        );
    }
    if !coinbase.outputs.ends_with(&t.coinbase_outputs) {
        return Err("coinbase-mismatch: the template's outputs are not the coinbase's last".into());
    }
    let paid: u64 = coinbase.outputs.iter().map(|o| o.value).sum();
    let allowed = t.coinbase_value + t.coinbase_outputs.iter().map(|o| o.value).sum::<u64>();
    if paid > allowed {
        return Err(format!(
            "bad-cb-amount: pays {paid}, the template allows {allowed}"
        ));
    }
    if coinbase.has_witness() && (input.witness.len() != 1 || input.witness[0] != [0u8; 32]) {
        return Err("bad-witness-nonce-size".into());
    }
    if !wire::version_allowed(t.version, version, true) {
        return Err(format!(
            "bad-version: 0x{version:08x} rolls bits outside BIP 320's against 0x{:08x}",
            t.version
        ));
    }
    if ntime < t.ntime || ntime > now.saturating_add(wire::MAX_FUTURE_NTIME) {
        return Err(format!(
            "time-invalid: {ntime} is before the tip's {} or over two hours ahead",
            t.ntime
        ));
    }
    let root = btc::fold_path(coinbase.txid(), &t.merkle_path);
    let header = wire::header(version, &t.prev_hash, &root, ntime, t.nbits, nonce);
    let hash = wire::sha256d(&header);
    if !wire::meets(&hash, &t.target) {
        return Err(format!(
            "high-hash: {} does not meet nbits {:08x}",
            wire::display_hex(&hash),
            t.nbits
        ));
    }
    Ok(Solved {
        hash,
        block: btc::block_bytes(&header, coinbase_bytes, &t.txs),
        coinbase,
    })
}

fn template_event(conn: &Conn) -> Value {
    match conn.tip {
        Some(tip) => json!({"prev_hash": wire::display_hex(&tip.prev_hash), "height": tip.height,
            "nbits": format!("{:08x}", tip.nbits), "ntime": tip.ntime}),
        None => Value::Null,
    }
}

/// Send the templates in the model's answer; an invalid one is logged and skipped.
fn apply_templates(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    extras: &[Value],
) -> Vec<Message> {
    let log = Log::new(Some(&ctx.status_tx));
    let mut out = Vec::new();
    let mut sent = 0;
    for a in extras {
        if a["type"] != actions::NEW_TEMPLATE {
            continue;
        }
        if sent >= MAX_TEMPLATES_PER_ANSWER {
            log.warn(format!(
                "Stratum V2 template provider connection {id}: more than {MAX_TEMPLATES_PER_ANSWER} templates in one answer; the rest are dropped"
            ));
            break;
        }
        match build(conn, pool.network, a, wire::now_secs()) {
            Ok((t, messages)) => {
                sent += 1;
                log.info(format!(
                    "Stratum V2 template provider connection {id}: template {} at height {} on {} with {} transactions, coinbase {} sats",
                    t.id,
                    t.height,
                    wire::display_hex(&t.prev_hash),
                    t.txs.len(),
                    t.coinbase_value
                ));
                out.extend(messages);
            }
            Err(e) => log.warn(format!(
                "Stratum V2 template provider connection {id}: the model's template was refused: {e:#}"
            )),
        }
    }
    out
}

/// One TDP connection, after the handshake.
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
        "Stratum V2 template provider connection {id} received: {}",
        summary(&conn.received)
    ));
    result
}

pub(crate) fn summary(received: &BTreeMap<&'static str, u64>) -> String {
    if received.is_empty() {
        return "nothing".into();
    }
    received
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
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
            "Stratum V2 template provider connection {id} refused: {} before SetupConnection",
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
            let error = |flags: u32, code: &str| {
                log.info(format!(
                    "Stratum V2 template provider connection {id} setup refused: {code}"
                ));
                (
                    vec![Message::SetupConnectionError {
                        flags,
                        error_code: code.as_bytes().to_vec(),
                    }],
                    true,
                )
            };
            if protocol != wire::TEMPLATE_DISTRIBUTION_PROTOCOL {
                return error(0, "unsupported-protocol");
            }
            if min_version > wire::PROTOCOL_VERSION || max_version < wire::PROTOCOL_VERSION {
                return error(0, "protocol-version-mismatch");
            }
            // The Template Distribution Protocol defines no flags.
            if flags != 0 {
                return error(flags, "unsupported-feature-flags");
            }
            let event = Event::new(
                &actions::TP_SETUP_EVENT,
                json!({"vendor": wire::text(&vendor), "hardware_version": wire::text(&hardware_version),
                       "firmware": wire::text(&firmware), "device_id": wire::text(&device_id),
                       "endpoint_host": wire::text(&endpoint_host), "endpoint_port": endpoint_port,
                       "remote_addr": peer.to_string()}),
            );
            match consult(ctx, id, event, "tp_setup_connection").await {
                Consult::Answer {
                    verdict: Some(Ok(())),
                    ..
                } => {
                    conn.setup = true;
                    (
                        vec![Message::SetupConnectionSuccess {
                            used_version: wire::PROTOCOL_VERSION,
                            flags: 0,
                        }],
                        false,
                    )
                }
                Consult::Answer {
                    verdict: Some(Err(code)),
                    ..
                } => error(0, &code),
                Consult::Answer { verdict: None, .. } => error(0, "service-unavailable"),
                Consult::Fail(code) => error(0, code),
            }
        }
        Message::CoinbaseOutputConstraints {
            max_additional_size,
            max_additional_sigops,
        } => {
            conn.constraints = Some((max_additional_size, max_additional_sigops));
            let event = Event::new(
                &actions::TP_CONSTRAINTS_EVENT,
                json!({"max_additional_size": max_additional_size,
                       "max_additional_sigops": max_additional_sigops,
                       "tip": template_event(conn), "templates_sent": conn.next_id - 1,
                       "network": pool.network.name(), "remote_addr": peer.to_string()}),
            );
            match consult(ctx, id, event, "tp_coinbase_output_constraints").await {
                Consult::Answer { extras, .. } => {
                    (apply_templates(ctx, pool, conn, id, &extras), false)
                }
                // Failing closed here is sending no work: there is no error to send, and a
                // template the model did not choose would be NetGet inventing a block.
                Consult::Fail(_) => (Vec::new(), false),
            }
        }
        Message::RequestTransactionData { template_id } => {
            let tip = conn.tip.map(|t| t.prev_hash);
            let reply = match conn.templates.iter().find(|t| t.id == template_id) {
                Some(t) if Some(t.prev_hash) == tip => Message::RequestTransactionDataSuccess {
                    template_id,
                    excess_data: Vec::new(),
                    transaction_list: t.txs.iter().map(|tx| tx.serialize(true)).collect(),
                },
                Some(_) => Message::RequestTransactionDataError {
                    template_id,
                    error_code: b"stale-template-id".to_vec(),
                },
                None => Message::RequestTransactionDataError {
                    template_id,
                    error_code: b"template-id-not-found".to_vec(),
                },
            };
            log.info(format!(
                "Stratum V2 template provider connection {id}: RequestTransactionData for template {template_id} answered with {}",
                reply.name()
            ));
            (vec![reply], false)
        }
        Message::SubmitSolution {
            template_id,
            version,
            header_timestamp,
            header_nonce,
            coinbase_tx,
        } => {
            let Some(t) = conn.templates.iter().find(|t| t.id == template_id).cloned() else {
                outcome(ctx, id, "tp_submit_solution", "refused_unknown_template");
                return (Vec::new(), false);
            };
            let solved = match verify(
                &t,
                version,
                header_timestamp,
                header_nonce,
                &coinbase_tx,
                wire::now_secs(),
            ) {
                Ok(s) => s,
                Err(reason) => {
                    log.warn(format!(
                        "Stratum V2 template provider connection {id}: SubmitSolution for template {template_id} refused: {reason}"
                    ));
                    outcome(ctx, id, "tp_submit_solution", "refused_invalid_solution");
                    return (Vec::new(), false);
                }
            };
            if conn.solved.contains(&solved.hash) {
                outcome(ctx, id, "tp_submit_solution", "refused_duplicate_solution");
                return (Vec::new(), false);
            }
            if conn.solved.len() >= MAX_SEEN_SOLUTIONS {
                conn.solved.pop_front();
            }
            conn.solved.push_back(solved.hash);
            let hash = wire::display_hex(&solved.hash);
            // The block is what a template provider exists to relay: to the configured node if
            // there is one, and logged in full either way — to the operator for the first
            // solution of a template (a template's size is bounded by the model's), to the file
            // for the rest.
            let first = conn
                .templates
                .iter_mut()
                .find(|x| x.id == template_id)
                .is_some_and(|x| !std::mem::replace(&mut x.announced, true));
            log.info_to(
                if first { Sink::Both } else { Sink::FileOnly },
                format!(
                    "Stratum V2 template provider connection {id}: block {hash} at height {} solved template {template_id}; {} bytes: {}",
                    t.height,
                    solved.block.len(),
                    hex::encode(&solved.block)
                ),
            );
            let relay = super::relay(ctx, pool, id, &hash, &solved.block).await;
            let stale = conn.tip.map(|tip| tip.prev_hash) != Some(t.prev_hash);
            let event = Event::new(
                &actions::TP_SOLUTION_EVENT,
                json!({"template_id": template_id, "hash": hash, "height": t.height, "relay": relay,
                       "prev_hash": wire::display_hex(&t.prev_hash), "version": version,
                       "ntime": header_timestamp, "nonce": header_nonce,
                       "nbits": format!("{:08x}", t.nbits), "transaction_count": t.txs.len(),
                       "block_size": solved.block.len(), "stale": stale,
                       "coinbase_outputs": solved.coinbase.outputs.iter().map(btc::describe_output).collect::<Vec<_>>(),
                       "remote_addr": peer.to_string()}),
            );
            match consult(ctx, id, event, "tp_submit_solution").await {
                Consult::Answer { extras, .. } => {
                    (apply_templates(ctx, pool, conn, id, &extras), false)
                }
                Consult::Fail(_) => (Vec::new(), false),
            }
        }
        other => {
            log.warn(format!(
                "Stratum V2 template provider connection {id} refused: {} is not a message a Template Distribution client sends",
                other.name()
            ));
            (Vec::new(), true)
        }
    }
}
