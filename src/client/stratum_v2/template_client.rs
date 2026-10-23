//! Template Distribution client role (`role: template_client`): NetGet takes block templates
//! from a Template Provider (sv2-spec §7) — what a pool or Job Declarator Client does — and the
//! model decides what to do with them.
//!
//! After the Noise handshake (the provider's certificate checked against its authority key)
//! and SetupConnection for the Template Distribution Protocol, Rust sends
//! CoinbaseOutputConstraints sized for the one output NetGet's coinbase adds. Every NewTemplate
//! and SetNewPrevHash is tracked and reported. When the model asks for a template's
//! transactions, Rust parses each one and checks that the provider's merkle path and witness
//! commitment are the ones those transactions give — a provider whose template does not add up
//! is reported as such. When the model asks to mine a template, Rust builds the coinbase the
//! template describes (its prefix, NetGet's extranonce, NetGet's output for the remaining
//! value, the template's outputs, the witness reserved value), hashes headers on the template's
//! tip until one meets its target, and sends SubmitSolution.
use super::actions::{self, StratumV2ClientProtocol};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::stratum_v2::bitcoin::{self as btc, Tx, TxIn, TxOut};
use crate::server::stratum_v2::noise;
use crate::server::stratum_v2::wire::{self, Message};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use tokio::{io::WriteHalf, net::TcpStream, sync::mpsc};

/// The largest frame a provider may send: RequestTransactionData.Success with a full block.
pub const MAX_INBOUND_PAYLOAD: usize = 8 * 1024 * 1024;
/// Templates remembered at once.
pub const MAX_TEMPLATES: usize = 16;
/// Outputs a template's coinbase may carry.
pub const MAX_TEMPLATE_OUTPUTS: usize = 64;
/// Bytes of extranonce NetGet's coinbase carries.
pub const EXTRANONCE_LEN: usize = 8;

#[derive(Clone)]
struct Template {
    id: u64,
    future: bool,
    version: u32,
    coinbase_tx_version: u32,
    coinbase_prefix: Vec<u8>,
    sequence: u32,
    value: u64,
    outputs: Vec<TxOut>,
    locktime: u32,
    merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Copy)]
struct Tip {
    prev_hash: [u8; 32],
    ntime: u32,
    nbits: u32,
    target: [u8; 32],
}

struct Receiver {
    writer: wire::FrameWriter<WriteHalf<TcpStream>>,
    templates: VecDeque<Template>,
    /// Future templates SetNewPrevHash has activated.
    activated: VecDeque<u64>,
    tip: Option<Tip>,
    /// Transaction-data requests awaiting an answer, with the chain depth that made them.
    requests: VecDeque<(u64, usize)>,
    events: mpsc::Sender<(Event, usize)>,
    received: BTreeMap<&'static str, u64>,
}

impl Receiver {
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

    /// The template and the tip it is mined on, if it can be mined now.
    fn minable(&self, id: Option<u64>) -> Result<(Template, Tip)> {
        let t = match id {
            Some(id) => self.templates.iter().find(|t| t.id == id),
            None => self
                .templates
                .iter()
                .rev()
                .find(|t| !t.future || self.activated.contains(&t.id)),
        }
        .context("no such template")?
        .clone();
        let tip = self.tip.context("no SetNewPrevHash yet")?;
        ensure!(
            !t.future || self.activated.contains(&t.id),
            "template {} is a future template no SetNewPrevHash has activated",
            t.id
        );
        Ok((t, tip))
    }
}

/// The coinbase NetGet mines a template with.
fn coinbase(t: &Template, payout: &[u8], message: &[u8], extranonce: &[u8]) -> Tx {
    let mut script = t.coinbase_prefix.clone();
    if !message.is_empty() {
        script.push(message.len() as u8);
        script.extend_from_slice(message);
    }
    script.push(extranonce.len() as u8);
    script.extend_from_slice(extranonce);
    let mut outputs = vec![TxOut {
        value: t.value,
        script: payout.to_vec(),
    }];
    outputs.extend(t.outputs.iter().cloned());
    let witness = if btc::find_witness_commitment(&t.outputs).is_some() {
        vec![vec![0u8; 32]]
    } else {
        Vec::new()
    };
    Tx {
        version: t.coinbase_tx_version,
        inputs: vec![TxIn {
            prev_txid: [0u8; 32],
            vout: u32::MAX,
            script_sig: script,
            sequence: t.sequence,
            witness,
        }],
        outputs,
        locktime: t.locktime,
    }
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
    let authority_text = param("authority_public_key")?.context(
        "authority_public_key is required: the template provider's base58check authority key",
    )?;
    let authority = noise::decode_authority_key(&authority_text)
        .context("authority_public_key is not a base58check authority key")?;
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
            .context("Noise handshake with the template provider failed")?;
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "Stratum V2 template client: {peer} proved its key with a certificate from the configured authority, valid {}..{}",
        cert.valid_from, cert.not_valid_after
    ));
    let (r, w) = tokio::io::split(stream);
    let (mut reader, mut writer) = wire::transport(r, w, noise_session, MAX_INBOUND_PAYLOAD);
    writer
        .send(&Message::SetupConnection {
            protocol: wire::TEMPLATE_DISTRIBUTION_PROTOCOL,
            min_version: wire::PROTOCOL_VERSION,
            max_version: wire::PROTOCOL_VERSION,
            flags: 0,
            endpoint_host: peer.ip().to_string().into_bytes(),
            endpoint_port: peer.port(),
            vendor: b"NetGet".to_vec(),
            hardware_version: b"NetGet template client".to_vec(),
            firmware: concat!("netget-", env!("CARGO_PKG_VERSION"))
                .as_bytes()
                .to_vec(),
            device_id: Vec::new(),
        })
        .await?;
    let answer = reader
        .next(super::SETUP_TIMEOUT)
        .await?
        .context("the template provider closed the connection after SetupConnection")?;
    match Message::decode(&answer)? {
        Message::SetupConnectionSuccess { used_version, flags } => log.info(format!(
            "Stratum V2 template client: SetupConnection accepted (version {used_version}, flags {flags:#x})"
        )),
        Message::SetupConnectionError { flags, error_code } => bail!(
            "the template provider refused SetupConnection: {} (flags {flags:#x})",
            wire::text(&error_code)
        ),
        other => bail!(
            "the template provider answered SetupConnection with {}",
            other.name()
        ),
    }
    // NetGet's coinbase adds one output: 8 bytes of value, a length byte and the script.
    let payout = btc::output_script(&json!({"pay_to": "op_true"}))?;
    writer
        .send(&Message::CoinbaseOutputConstraints {
            max_additional_size: (9 + payout.len()) as u32,
            max_additional_sigops: 0,
        })
        .await?;

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
                Ok(None) => Err(anyhow::anyhow!(
                    "the template provider closed the connection"
                )),
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
                    .warn(format!("Stratum V2 template client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut rx = Receiver {
            writer,
            templates: VecDeque::new(),
            activated: VecDeque::new(),
            tip: None,
            requests: VecDeque::new(),
            events: event_tx,
            received: BTreeMap::new(),
        };
        let result = session(&session_ctx, &mut rx, payout, msg_rx, external, internal_rx).await;
        dispatcher_abort.abort();
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "Stratum V2 template client received: {}",
            crate::server::stratum_v2::template_provider::summary(&rx.received)
        ));
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx))
                    .warn(format!("Stratum V2 template client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        rx.writer.shutdown().await;
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

/// Mine a template on its tip and submit the first header that meets the target.
async fn mine(rx: &mut Receiver, payout: &[u8], a: &Value, log: &Log<'_>) -> Result<Value> {
    let (t, tip) = rx.minable(a["template_id"].as_u64())?;
    let max = a["max_hashes"]
        .as_u64()
        .unwrap_or(actions::DEFAULT_MINE_HASHES);
    let message = a["message"]
        .as_str()
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    let extranonce: [u8; EXTRANONCE_LEN] = rand::random();
    let cb = coinbase(&t, payout, &message, &extranonce);
    ensure!(
        (2..=btc::MAX_COINBASE_SCRIPT_SIG).contains(&cb.inputs[0].script_sig.len()),
        "the coinbase scriptSig would be {} bytes; at most 100",
        cb.inputs[0].script_sig.len()
    );
    let root = btc::fold_path(cb.txid(), &t.merkle_path);
    let header = wire::header(t.version, &tip.prev_hash, &root, tip.ntime, tip.nbits, 0);
    let target = tip.target;
    let (nonce, hash, tried) =
        tokio::task::spawn_blocking(move || super::mine(header, target, max))
            .await
            .context("mining stopped")?;
    let found = wire::meets(&hash, &target);
    log.info(format!(
        "Stratum V2 template client mined {tried} hashes on template {}: {}",
        t.id,
        if found {
            "found a block"
        } else {
            "nothing met the target"
        }
    ));
    if found {
        rx.writer
            .send(&Message::SubmitSolution {
                template_id: t.id,
                version: t.version,
                header_timestamp: tip.ntime,
                header_nonce: nonce,
                coinbase_tx: cb.serialize(true),
            })
            .await?;
    }
    Ok(
        json!({"template_id": t.id, "height": btc::bip34_height(&t.coinbase_prefix),
              "found": found, "submitted": found, "hash": wire::display_hex(&hash),
              "hashes": tried, "nonce": nonce}),
    )
}

async fn session(
    ctx: &ConnectContext,
    rx: &mut Receiver,
    payout: Vec<u8>,
    mut messages: mpsc::Receiver<Result<Message>>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            item = messages.recv() => {
                let Some(item) = item else { return Ok(()) };
                on_message(rx, item?)?;
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
                "Stratum V2 template client action refused: {error}"
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
                "Stratum V2 template client: handler chain stopped after {} follow-ups",
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
            actions::REQUEST_TRANSACTIONS => {
                let id = match action["template_id"].as_u64() {
                    Some(id) => Some(id),
                    None => rx.templates.back().map(|t| t.id),
                };
                match id {
                    Some(template_id) => {
                        if rx.requests.len() >= MAX_TEMPLATES {
                            rx.requests.pop_front();
                        }
                        rx.requests.push_back((template_id, depth));
                        rx.writer
                            .send(&Message::RequestTransactionData { template_id })
                            .await
                            .map(|_| json!({"template_id": template_id}))
                    }
                    None => Err(anyhow::anyhow!("no template yet")),
                }
            }
            actions::MINE_TEMPLATE => match mine(rx, &payout, &action, &log).await {
                Ok(data) => {
                    rx.emit(&actions::TEMPLATE_SOLUTION_EVENT, data.clone(), depth)?;
                    Ok(data)
                }
                Err(e) => Err(e),
            },
            actions::SET_CONSTRAINTS => {
                let size = action["max_additional_size"].as_u64().unwrap_or(0) as u32;
                let sigops = action["max_additional_sigops"].as_u64().unwrap_or(0) as u16;
                rx.writer
                    .send(&Message::CoinbaseOutputConstraints {
                        max_additional_size: size,
                        max_additional_sigops: sigops,
                    })
                    .await
                    .map(|_| json!({"max_additional_size": size, "max_additional_sigops": sigops}))
            }
            other => Err(anyhow::anyhow!(
                "{other} is not an action of a template client"
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

fn on_message(rx: &mut Receiver, message: Message) -> Result<()> {
    *rx.received.entry(message.name()).or_default() += 1;
    match message {
        Message::NewTemplate {
            template_id,
            future_template,
            version,
            coinbase_tx_version,
            coinbase_prefix,
            coinbase_tx_input_sequence,
            coinbase_tx_value_remaining,
            coinbase_tx_outputs_count,
            coinbase_tx_outputs,
            coinbase_tx_locktime,
            merkle_path,
        } => {
            ensure!(
                coinbase_prefix.len() <= btc::MAX_COINBASE_PREFIX,
                "the template's coinbase prefix is {} bytes, more than 8",
                coinbase_prefix.len()
            );
            ensure!(
                (coinbase_tx_outputs_count as usize) <= MAX_TEMPLATE_OUTPUTS,
                "the template declares {coinbase_tx_outputs_count} coinbase outputs"
            );
            let mut vector = Vec::new();
            btc::write_varint(&mut vector, u64::from(coinbase_tx_outputs_count));
            vector.extend_from_slice(&coinbase_tx_outputs);
            let outputs = btc::parse_output_vector(&vector, MAX_TEMPLATE_OUTPUTS)
                .context("the template's coinbase outputs do not parse")?;
            let t = Template {
                id: template_id,
                future: future_template,
                version,
                coinbase_tx_version,
                coinbase_prefix,
                sequence: coinbase_tx_input_sequence,
                value: coinbase_tx_value_remaining,
                outputs,
                locktime: coinbase_tx_locktime,
                merkle_path,
            };
            let data = json!({"template_id": t.id, "future": t.future, "version": t.version,
                "height": btc::bip34_height(&t.coinbase_prefix),
                "coinbase_value_sats": t.value, "merkle_path_len": t.merkle_path.len(),
                "coinbase_outputs": t.outputs.iter().map(btc::describe_output).collect::<Vec<_>>(),
                "prev_hash": rx.tip.filter(|_| !t.future).map(|tip| wire::display_hex(&tip.prev_hash))});
            rx.templates.retain(|x| x.id != t.id);
            if rx.templates.len() >= MAX_TEMPLATES {
                rx.templates.pop_front();
            }
            rx.templates.push_back(t);
            rx.emit(&actions::TEMPLATE_EVENT, data, 0)
        }
        Message::TemplateSetNewPrevHash {
            template_id,
            prev_hash,
            header_timestamp,
            nbits,
            target,
        } => {
            rx.tip = Some(Tip {
                prev_hash,
                ntime: header_timestamp,
                nbits,
                target,
            });
            if rx.activated.len() >= MAX_TEMPLATES {
                rx.activated.pop_front();
            }
            rx.activated.push_back(template_id);
            // Templates on the old tip can no longer be mined.
            rx.templates
                .retain(|t| t.id == template_id || (t.future && t.id > template_id));
            let consistent = btc::compact_to_target(nbits).ok() == Some(target);
            rx.emit(
                &actions::TEMPLATE_PREV_HASH_EVENT,
                json!({"template_id": template_id, "prev_hash": wire::display_hex(&prev_hash),
                       "ntime": header_timestamp, "nbits": format!("{nbits:08x}"),
                       "target_matches_nbits": consistent}),
                0,
            )
        }
        Message::RequestTransactionDataSuccess {
            template_id,
            transaction_list,
            ..
        } => {
            let depth = match rx.requests.iter().position(|(t, _)| *t == template_id) {
                Some(i) => rx.requests.remove(i).map(|(_, d)| d).unwrap_or(0),
                None => 0,
            };
            let mut txs = Vec::with_capacity(transaction_list.len());
            for raw in &transaction_list {
                txs.push(
                    Tx::parse(raw)
                        .context("the template provider sent a transaction that does not parse")?,
                );
            }
            let txids: Vec<[u8; 32]> = txs.iter().map(Tx::txid).collect();
            let wtxids: Vec<[u8; 32]> = txs.iter().map(Tx::wtxid).collect();
            let t = rx.templates.iter().find(|t| t.id == template_id);
            let path_matches = t.map(|t| btc::coinbase_merkle_path(&txids) == t.merkle_path);
            let commitment_matches = t.and_then(|t| {
                btc::find_witness_commitment(&t.outputs)
                    .map(|c| *c == btc::witness_commitment(&wtxids, &[0u8; 32]))
            });
            rx.emit(
                &actions::TEMPLATE_TRANSACTIONS_EVENT,
                json!({"template_id": template_id, "transaction_count": txs.len(),
                       "segwit_transactions": txs.iter().filter(|t| t.has_witness()).count(),
                       "weight": txs.iter().map(Tx::weight).sum::<u64>(),
                       "merkle_path_matches": path_matches,
                       "witness_commitment_matches": commitment_matches}),
                depth,
            )
        }
        Message::RequestTransactionDataError {
            template_id,
            error_code,
        } => {
            let depth = match rx.requests.iter().position(|(t, _)| *t == template_id) {
                Some(i) => rx.requests.remove(i).map(|(_, d)| d).unwrap_or(0),
                None => 0,
            };
            rx.emit(
                &actions::TEMPLATE_TRANSACTIONS_EVENT,
                json!({"template_id": template_id, "error_code": wire::text(&error_code)}),
                depth,
            )
        }
        other => bail!(
            "the template provider sent {}, which a Template Provider does not send",
            other.name()
        ),
    }
}
