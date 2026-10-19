//! Apache Pulsar client: one connection to a broker, producers and consumers created on
//! demand (each after a lookup), messages handed to the handler and acknowledged after it.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::pulsar::wire::{self, command_type as t, BaseCommand, Entry};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::PulsarClientProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;
/// Permits granted to each consumer, topped up when half are used.
pub const PERMITS: u32 = 1000;
/// Requests and sends awaiting the broker at once.
pub const MAX_PENDING: usize = 256;
/// The broker pings every 30 s; this long without a frame means it is gone.
pub const READ_IDLE: Duration = Duration::from_secs(120);

type Frame = (BaseCommand, wire::Payload);

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let target = ctx
        .remote_addr
        .trim_start_matches("pulsar://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = tokio::time::timeout(wire::IO_TIMEOUT, TcpStream::connect(&target))
        .await
        .context("Pulsar connect deadline")??;
    let local = stream.local_addr()?;
    let mut hello = BaseCommand::of(t::CONNECT);
    hello.connect = Some(wire::CommandConnect {
        client_version: concat!("NetGet/", env!("CARGO_PKG_VERSION")).into(),
        protocol_version: Some(wire::PROTOCOL_VERSION),
        ..Default::default()
    });
    stream.write_all(&wire::simple(&hello)).await?;
    let (answer, _) = wire::read_frame(&mut stream, wire::IO_TIMEOUT)
        .await?
        .context("the broker closed the connection before CONNECTED")?;
    let connected = match (answer.r#type, answer.connected, answer.error) {
        (t::CONNECTED, Some(c), _) => c,
        (_, _, Some(e)) => bail!("the broker refused CONNECT: {}", e.message),
        (other, _, _) => bail!("the broker answered CONNECT with command {other}"),
    };
    let (mut reader, writer) = tokio::io::split(stream);
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (frame_tx, frame_rx) = mpsc::channel::<Result<Frame>>(256);
    let reader_task = tokio::spawn(async move {
        loop {
            let item = wire::read_frame(&mut reader, READ_IDLE).await;
            let end = !matches!(item, Ok(Some(_)));
            let sent = match item {
                Ok(Some(f)) => frame_tx.send(Ok(f)).await,
                Ok(None) => {
                    frame_tx
                        .send(Err(anyhow::anyhow!("the broker closed the connection")))
                        .await
                }
                Err(e) => frame_tx.send(Err(e)).await,
            };
            if end || sent.is_err() {
                return;
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;

    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(64);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize, Option<Ack>)>(256);
    // Acknowledgements are sent once the handler has run on the message.
    let (ack_tx, ack_rx) = mpsc::channel::<Ack>(256);
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({"server_version": connected.server_version, "protocol_version": connected.protocol_version.unwrap_or(0),
                   "max_message_size": connected.max_message_size}),
        ),
        0,
        None,
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        // An event that would not have joined the previous batch starts the next one.
        let mut carried = None;
        while let Some(first) = match carried.take() {
            Some(item) => Some(item),
            None => event_rx.recv().await,
        } {
            // With batching on, everything raised while the model was answering is answered
            // in this one call; with it off, one event per call. Only events the model itself
            // will answer together are drained: one a script, static or manual rule answers
            // stays in the bounded queue, as it would without batching.
            let mut batch = vec![first];
            while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                let mut ids: Vec<&str> = batch.iter().map(|item| item.0.id()).collect();
                if ids.len() == 1
                    && !crate::llm::action_helper::client_batch_goes_to_the_model(
                        &events_ctx.state,
                        events_ctx.client_id,
                        &ids,
                    )
                    .await
                {
                    break;
                }
                let Ok(next) = event_rx.try_recv() else {
                    break;
                };
                ids.push(next.0.id());
                if !crate::llm::action_helper::client_batch_goes_to_the_model(
                    &events_ctx.state,
                    events_ctx.client_id,
                    &ids,
                )
                .await
                {
                    carried = Some(next);
                    break;
                }
                drop(ids);
                batch.push(next);
            }
            // A follow-up is as deep as the deepest event it answers; every message in the
            // batch is acknowledged once the handler has run on all of them.
            let depth = batch.iter().map(|(_, d, _)| *d).max().unwrap_or(0);
            let mut events = Vec::with_capacity(batch.len());
            let mut acks = Vec::new();
            for (event, _, ack) in batch {
                events_ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(events_ctx.client_id.as_u32()),
                        "Pulsar",
                        None,
                        event.id(),
                        event.data.clone(),
                        vec![],
                    )
                    .await;
                events.push(event);
                acks.extend(ack);
            }
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
            match call_llm_for_client_batch(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &PulsarClientProtocol,
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
                    .warn(format!("Pulsar client handler: {e}")),
            }
            for ack in acks {
                if ack_tx.send(ack).await.is_err() {
                    return;
                }
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut s = Session {
            writer,
            remote: target,
            next_request: 0,
            pending: HashMap::new(),
            producers: HashMap::new(),
            sends: HashMap::new(),
            consumers: HashMap::new(),
            events: event_tx,
        };
        let result = s
            .run(&session_ctx, frame_rx, external, internal_rx, ack_rx)
            .await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("Pulsar client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
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

/// A message to acknowledge once handled.
struct Ack {
    consumer_id: u64,
    ledger_id: u64,
    entry_id: u64,
}

/// What a broker answer is for.
enum Pending {
    LookupForProducer {
        topic: String,
        queued: Vec<(Value, usize, Option<ClientCommand>)>,
    },
    LookupForConsumer {
        topic: String,
        action: Value,
        depth: usize,
        caller: Option<ClientCommand>,
    },
    Producer {
        topic: String,
        producer_id: u64,
        queued: Vec<(Value, usize, Option<ClientCommand>)>,
    },
    Subscribe {
        topic: String,
        subscription: String,
        consumer_id: u64,
        depth: usize,
        caller: Option<ClientCommand>,
    },
    Unsubscribe {
        topic: String,
        subscription: String,
        consumer_id: u64,
        depth: usize,
        caller: Option<ClientCommand>,
    },
}

struct ProducerState {
    producer_id: u64,
    name: String,
    next_sequence: u64,
}

struct ConsumerState {
    topic: String,
    subscription: String,
    received: u32,
}

struct Session {
    writer: WriteHalf<TcpStream>,
    remote: String,
    next_request: u64,
    pending: HashMap<u64, Pending>,
    /// topic → producer (None while the PRODUCER request is outstanding)
    producers: HashMap<String, Option<ProducerState>>,
    /// (producer id, sequence id) → (topic, depth, caller)
    sends: HashMap<(u64, u64), (String, usize, Option<ClientCommand>)>,
    consumers: HashMap<u64, ConsumerState>,
    events: mpsc::Sender<(Event, usize, Option<Ack>)>,
}

fn reply(caller: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = caller {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

impl Session {
    async fn write(&mut self, frame: &[u8]) -> Result<()> {
        tokio::time::timeout(wire::IO_TIMEOUT, self.writer.write_all(frame))
            .await
            .context("Pulsar write deadline")??;
        Ok(())
    }

    fn request_id(&mut self) -> Result<u64> {
        if self.pending.len() >= MAX_PENDING {
            bail!("too many requests awaiting the broker");
        }
        self.next_request += 1;
        Ok(self.next_request)
    }

    fn emit(
        &self,
        event: &'static crate::protocol::EventType,
        data: Value,
        depth: usize,
        caller: Option<ClientCommand>,
    ) -> Result<()> {
        reply(
            caller,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        self.events
            .try_send((Event::new(event, data), depth, None))
            .context("Pulsar event queue full; consumer stalled")
    }

    async fn lookup(&mut self, topic: &str, pending: impl FnOnce(String) -> Pending) -> Result<()> {
        let request_id = self.request_id()?;
        let mut c = BaseCommand::of(t::LOOKUP);
        c.lookup_topic = Some(wire::CommandLookupTopic {
            topic: topic.to_string(),
            request_id,
            authoritative: Some(false),
        });
        self.pending.insert(request_id, pending(topic.to_string()));
        self.write(&wire::simple(&c)).await
    }

    async fn send(
        &mut self,
        topic: &str,
        action: &Value,
        depth: usize,
        caller: Option<ClientCommand>,
    ) -> Result<()> {
        let Some(Some(p)) = self.producers.get_mut(topic) else {
            return Ok(());
        };
        let sequence_id = p.next_sequence;
        p.next_sequence += 1;
        let (producer_id, name) = (p.producer_id, p.name.clone());
        let payload = wire::bytes(
            action["payload"].as_str().unwrap_or_default(),
            action["encoding"].as_str(),
        )?;
        let properties = action["properties"]
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| wire::KeyValue {
                        key: k.clone(),
                        value: v.as_str().unwrap_or_default().into(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let meta = wire::MessageMetadata {
            producer_name: name,
            sequence_id,
            publish_time: wire::now_millis(),
            properties,
            partition_key: action["key"].as_str().map(str::to_string),
            uncompressed_size: Some(payload.len() as u32),
            ..Default::default()
        };
        let mut c = BaseCommand::of(t::SEND);
        c.send = Some(wire::CommandSend {
            producer_id,
            sequence_id,
            num_messages: Some(1),
            ..Default::default()
        });
        self.sends.insert(
            (producer_id, sequence_id),
            (topic.to_string(), depth, caller),
        );
        let frame = wire::with_payload(&c, &meta, &payload);
        self.write(&frame).await
    }

    async fn act(
        &mut self,
        action: Value,
        depth: usize,
        caller: Option<ClientCommand>,
    ) -> Result<()> {
        let topic = wire::full_topic(action["topic"].as_str().unwrap_or_default())?;
        match action["type"].as_str().unwrap_or_default() {
            actions::PRODUCE => match self.producers.get(&topic) {
                Some(Some(_)) => self.send(&topic, &action, depth, caller).await,
                Some(None) => {
                    // The producer is being looked up or created: queue behind it.
                    for p in self.pending.values_mut() {
                        if let Pending::Producer {
                            topic: pt, queued, ..
                        }
                        | Pending::LookupForProducer { topic: pt, queued } = p
                        {
                            if *pt == topic {
                                queued.push((action, depth, caller));
                                return Ok(());
                            }
                        }
                    }
                    Ok(())
                }
                None => {
                    self.producers.insert(topic.clone(), None);
                    self.lookup(&topic, |topic| Pending::LookupForProducer {
                        topic,
                        queued: vec![(action, depth, caller)],
                    })
                    .await
                }
            },
            actions::SUBSCRIBE => {
                self.lookup(&topic, |topic| Pending::LookupForConsumer {
                    topic,
                    action,
                    depth,
                    caller,
                })
                .await
            }
            actions::UNSUBSCRIBE => {
                let sub = action["subscription"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let Some(consumer_id) = self
                    .consumers
                    .iter()
                    .find(|(_, c)| c.topic == topic && c.subscription == sub)
                    .map(|(id, _)| *id)
                else {
                    reply(
                        caller,
                        ClientSendOutcome::Rejected {
                            error: format!("not subscribed to {sub} on {topic}"),
                        },
                    );
                    return Ok(());
                };
                let request_id = self.request_id()?;
                let mut c = BaseCommand::of(t::UNSUBSCRIBE);
                c.unsubscribe = Some(wire::CommandUnsubscribe {
                    consumer_id,
                    request_id,
                });
                self.pending.insert(
                    request_id,
                    Pending::Unsubscribe {
                        topic,
                        subscription: sub,
                        consumer_id,
                        depth,
                        caller,
                    },
                );
                self.write(&wire::simple(&c)).await
            }
            _ => Ok(()),
        }
    }

    async fn on_frame(
        &mut self,
        ctx: &ConnectContext,
        cmd: BaseCommand,
        payload: wire::Payload,
    ) -> Result<()> {
        let log = Log::new(Some(&ctx.status_tx));
        match cmd.r#type {
            t::PING => {
                self.write(&wire::simple(&BaseCommand {
                    pong: Some(wire::CommandPong {}),
                    ..BaseCommand::of(t::PONG)
                }))
                .await?
            }
            t::PONG => {}
            t::LOOKUP_RESPONSE => {
                let r = cmd.lookup_topic_response.unwrap_or_default();
                let Some(pending) = self.pending.remove(&r.request_id) else {
                    return Ok(());
                };
                let here = r.response == Some(1)
                    && r.broker_service_url
                        .as_deref()
                        .map(|u| u.trim_start_matches("pulsar://").trim_end_matches('/'))
                        == Some(self.remote.as_str());
                let refusal = match r.response {
                    Some(1) if here => None,
                    Some(1) | Some(0) => Some(format!(
                        "the topic is served by {} and this client does not follow lookups to other brokers",
                        r.broker_service_url.unwrap_or_default()
                    )),
                    _ => Some(r.message.unwrap_or_else(|| "lookup failed".into())),
                };
                match pending {
                    Pending::LookupForProducer { topic, queued } => {
                        if let Some(why) = refusal {
                            self.producers.remove(&topic);
                            for (_, depth, caller) in queued {
                                self.emit(
                                    &actions::PRODUCED_EVENT,
                                    json!({"topic": topic, "ok": false, "error": why}),
                                    depth,
                                    caller,
                                )?;
                            }
                            return Ok(());
                        }
                        let request_id = self.request_id()?;
                        let producer_id = request_id;
                        let mut c = BaseCommand::of(t::PRODUCER);
                        c.producer = Some(wire::CommandProducer {
                            topic: topic.clone(),
                            producer_id,
                            request_id,
                            ..Default::default()
                        });
                        self.pending.insert(
                            request_id,
                            Pending::Producer {
                                topic,
                                producer_id,
                                queued,
                            },
                        );
                        self.write(&wire::simple(&c)).await?;
                    }
                    Pending::LookupForConsumer {
                        topic,
                        action,
                        depth,
                        caller,
                    } => {
                        let sub = action["subscription"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        if let Some(why) = refusal {
                            return self.emit(&actions::SUBSCRIBED_EVENT, json!({"topic": topic, "subscription": sub, "operation": "subscribe", "ok": false, "error": why}), depth, caller);
                        }
                        let request_id = self.request_id()?;
                        let consumer_id = request_id;
                        let sub_type = action["sub_type"]
                            .as_str()
                            .and_then(|s| wire::SUB_TYPES.iter().position(|x| *x == s))
                            .unwrap_or(0) as i32;
                        let mut c = BaseCommand::of(t::SUBSCRIBE);
                        c.subscribe = Some(wire::CommandSubscribe {
                            topic: topic.clone(),
                            subscription: sub.clone(),
                            sub_type,
                            consumer_id,
                            request_id,
                            consumer_name: Some(format!("netget-{consumer_id}")),
                            durable: Some(true),
                            initial_position: Some(i32::from(
                                action["initial_position"] == "earliest",
                            )),
                        });
                        self.pending.insert(
                            request_id,
                            Pending::Subscribe {
                                topic,
                                subscription: sub,
                                consumer_id,
                                depth,
                                caller,
                            },
                        );
                        self.write(&wire::simple(&c)).await?;
                    }
                    _ => {}
                }
            }
            t::PRODUCER_SUCCESS => {
                let r = cmd.producer_success.unwrap_or_default();
                if let Some(Pending::Producer {
                    topic,
                    producer_id,
                    queued,
                }) = self.pending.remove(&r.request_id)
                {
                    self.producers.insert(
                        topic.clone(),
                        Some(ProducerState {
                            producer_id,
                            name: r.producer_name,
                            next_sequence: 0,
                        }),
                    );
                    for (action, depth, caller) in queued {
                        self.send(&topic, &action, depth, caller).await?;
                    }
                }
            }
            t::SEND_RECEIPT => {
                let r = cmd.send_receipt.unwrap_or_default();
                if let Some((topic, depth, caller)) =
                    self.sends.remove(&(r.producer_id, r.sequence_id))
                {
                    let id = r
                        .message_id
                        .map(|m| json!({"ledger_id": m.ledger_id, "entry_id": m.entry_id}));
                    self.emit(
                        &actions::PRODUCED_EVENT,
                        json!({"topic": topic, "ok": true, "message_id": id}),
                        depth,
                        caller,
                    )?;
                }
            }
            t::SEND_ERROR => {
                let r = cmd.send_error.unwrap_or_default();
                if let Some((topic, depth, caller)) =
                    self.sends.remove(&(r.producer_id, r.sequence_id))
                {
                    self.emit(
                        &actions::PRODUCED_EVENT,
                        json!({"topic": topic, "ok": false, "error": r.message}),
                        depth,
                        caller,
                    )?;
                }
            }
            t::SUCCESS => {
                let r = cmd.success.unwrap_or_default();
                match self.pending.remove(&r.request_id) {
                    Some(Pending::Subscribe {
                        topic,
                        subscription,
                        consumer_id,
                        depth,
                        caller,
                    }) => {
                        let mut f = BaseCommand::of(t::FLOW);
                        f.flow = Some(wire::CommandFlow {
                            consumer_id,
                            message_permits: PERMITS,
                        });
                        self.write(&wire::simple(&f)).await?;
                        self.consumers.insert(
                            consumer_id,
                            ConsumerState {
                                topic: topic.clone(),
                                subscription: subscription.clone(),
                                received: 0,
                            },
                        );
                        self.emit(&actions::SUBSCRIBED_EVENT, json!({"topic": topic, "subscription": subscription, "operation": "subscribe", "ok": true}), depth, caller)?;
                    }
                    Some(Pending::Unsubscribe {
                        topic,
                        subscription,
                        consumer_id,
                        depth,
                        caller,
                    }) => {
                        self.consumers.remove(&consumer_id);
                        self.emit(&actions::SUBSCRIBED_EVENT, json!({"topic": topic, "subscription": subscription, "operation": "unsubscribe", "ok": true}), depth, caller)?;
                    }
                    _ => {}
                }
            }
            t::ERROR => {
                let e = cmd.error.unwrap_or_default();
                match self.pending.remove(&e.request_id) {
                    Some(Pending::Producer { topic, queued, .. }) => {
                        self.producers.remove(&topic);
                        for (_, depth, caller) in queued {
                            self.emit(
                                &actions::PRODUCED_EVENT,
                                json!({"topic": topic, "ok": false, "error": e.message}),
                                depth,
                                caller,
                            )?;
                        }
                    }
                    Some(Pending::Subscribe {
                        topic,
                        subscription,
                        depth,
                        caller,
                        ..
                    }) => {
                        self.emit(&actions::SUBSCRIBED_EVENT, json!({"topic": topic, "subscription": subscription, "operation": "subscribe", "ok": false, "error": e.message}), depth, caller)?;
                    }
                    Some(Pending::Unsubscribe {
                        topic,
                        subscription,
                        depth,
                        caller,
                        ..
                    }) => {
                        self.emit(&actions::SUBSCRIBED_EVENT, json!({"topic": topic, "subscription": subscription, "operation": "unsubscribe", "ok": false, "error": e.message}), depth, caller)?;
                    }
                    _ => log.warn(format!("Pulsar broker error {}: {}", e.error, e.message)),
                }
            }
            t::MESSAGE => {
                let m = cmd.message.unwrap_or_default();
                let Some(consumer) = self.consumers.get_mut(&m.consumer_id) else {
                    return Ok(());
                };
                let (meta, body) = match payload {
                    Ok(Some(p)) => p,
                    _ => {
                        log.warn("Pulsar client: a MESSAGE with a bad checksum or no payload was dropped".to_string());
                        return Ok(());
                    }
                };
                let entries: Vec<Entry> = match wire::entries(&meta, &body) {
                    Ok(e) => e,
                    Err(e) => {
                        log.warn(format!("Pulsar client: a message could not be read: {e:#}"));
                        Vec::new()
                    }
                };
                let (topic, sub) = (consumer.topic.clone(), consumer.subscription.clone());
                consumer.received += 1;
                let refill = consumer.received >= PERMITS / 2;
                if refill {
                    consumer.received = 0;
                }
                let n = entries.len();
                for (i, e) in entries.into_iter().enumerate() {
                    let (text, encoding) = wire::show(&e.payload);
                    let props: serde_json::Map<String, Value> = e
                        .properties
                        .iter()
                        .map(|kv| (kv.key.clone(), json!(kv.value)))
                        .collect();
                    let ack = (i + 1 == n).then_some(Ack {
                        consumer_id: m.consumer_id,
                        ledger_id: m.message_id.ledger_id,
                        entry_id: m.message_id.entry_id,
                    });
                    self.events
                        .try_send((
                            Event::new(
                                &actions::MESSAGE_EVENT,
                                json!({"topic": topic, "subscription": sub, "payload": text, "encoding": encoding,
                                       "properties": props, "key": e.key, "producer_name": meta.producer_name,
                                       "message_id": {"ledger_id": m.message_id.ledger_id, "entry_id": m.message_id.entry_id},
                                       "redelivery_count": m.redelivery_count.unwrap_or(0)}),
                            ),
                            0,
                            ack,
                        ))
                        .context("Pulsar event queue full; consumer stalled")?;
                }
                if refill {
                    let mut f = BaseCommand::of(t::FLOW);
                    f.flow = Some(wire::CommandFlow {
                        consumer_id: m.consumer_id,
                        message_permits: PERMITS / 2,
                    });
                    self.write(&wire::simple(&f)).await?;
                }
            }
            other => log.debug(format!("Pulsar client: command {other} ignored")),
        }
        Ok(())
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut frames: mpsc::Receiver<Result<Frame>>,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        mut acks: mpsc::Receiver<Ack>,
    ) -> Result<()> {
        let log = Log::new(Some(&ctx.status_tx));
        loop {
            let (action, depth, mut injected) = tokio::select! {
                frame = frames.recv() => {
                    let Some(frame) = frame else { return Ok(()) };
                    let (cmd, payload) = frame?;
                    self.on_frame(ctx, cmd, payload).await?;
                    continue;
                }
                ack = acks.recv() => {
                    let Some(a) = ack else { return Ok(()) };
                    let mut c = BaseCommand::of(t::ACK);
                    c.ack = Some(wire::CommandAck {
                        consumer_id: a.consumer_id,
                        ack_type: 0,
                        message_id: vec![wire::MessageIdData { ledger_id: a.ledger_id, entry_id: a.entry_id, partition: None, batch_index: None }],
                        request_id: None,
                    });
                    self.write(&wire::simple(&c)).await?;
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
            match PulsarClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(injected.take(), ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("Pulsar client action refused: {e}"));
                    reply(
                        injected.take(),
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            }
            if depth > MAX_FOLLOWUP_DEPTH {
                log.warn(format!(
                    "Pulsar client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            if injected.is_some() {
                ctx.state
                    .record_access_log(
                        AccessLogOwner::Client(ctx.client_id.as_u32()),
                        "Pulsar",
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
            }
            if let Err(e) = self.act(action, depth, injected.take()).await {
                log.warn(format!("Pulsar client action failed: {e:#}"));
            }
        }
    }
}
