//! MQTT-SN 1.2 sensor client over the gateway's codec: one outstanding operation at a time,
//! retried, with deliveries from the gateway acknowledged and reported as they arrive.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::mqtt_sn::packet::{self, Flags, Packet};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::MqttSnClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value as Json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub const DEFAULT_KEEP_ALIVE: u16 = 60;
const RETRY_AFTER: Duration = Duration::from_secs(5);
const RETRIES: u32 = 3;

/// The payload of a publish action.
pub fn payload(v: &Json) -> Result<Vec<u8>> {
    let text = v["payload"].as_str().context("payload is text")?;
    let data = match v.get("encoding").and_then(Json::as_str) {
        None | Some("utf8") => text.as_bytes().to_vec(),
        Some("hex") => hex::decode(text).context("payload is not hex")?,
        Some(e) => bail!("encoding {e:?} is utf8 or hex"),
    };
    ensure!(data.len() <= 60_000, "payload is at most 60000 bytes");
    Ok(data)
}

struct Job {
    topic: String,
    data: Vec<u8>,
    qos: i8,
    retain: bool,
}

enum Op {
    Register {
        topic: String,
        then: Option<Job>,
    },
    Publish {
        topic: String,
        topic_id: u16,
        stage: u8,
    },
    Subscribe {
        topic: String,
    },
    Unsubscribe {
        topic: String,
    },
    Sleep,
    Wake,
    Ping,
}

struct Pending {
    op: Op,
    msg_id: u16,
    bytes: Vec<u8>,
    deadline: Instant,
    tries: u32,
}

struct Sensor {
    socket: UdpSocket,
    client_id: String,
    keep_alive: u16,
    clean: bool,
    will: Option<(String, Vec<u8>)>,
    predefined: HashMap<String, u16>,
    ids: HashMap<String, u16>,
    names: HashMap<u16, String>,
    next_id: u16,
    pending: Option<Pending>,
    queue: VecDeque<(Json, Option<ClientCommand>)>,
    received: HashSet<u16>,
    woken: u32,
    events: mpsc::Sender<Event>,
    last_sent: Instant,
    asleep: bool,
}

fn result(operation: &str, extra: Json) -> Event {
    let mut data = json!({"operation": operation});
    if let (Some(d), Some(e)) = (data.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    Event::new(&actions::RESULT_EVENT, data)
}

impl Sensor {
    async fn send(&mut self, p: &Packet) -> Result<Vec<u8>> {
        let bytes = packet::encode(p);
        self.socket.send(&bytes).await?;
        self.last_sent = Instant::now();
        Ok(bytes)
    }

    fn msg_id(&mut self) -> u16 {
        self.next_id = self.next_id.checked_add(1).unwrap_or(1);
        self.next_id
    }

    async fn emit(&self, e: Event) {
        let _ = self.events.send(e).await;
    }

    /// CONNECT and its will exchange; packets that arrive meanwhile are returned.
    async fn handshake(&mut self) -> Result<Vec<Packet>> {
        let connect = Packet::Connect {
            flags: Flags {
                will: self.will.is_some(),
                clean_session: self.clean,
                ..Flags::default()
            },
            duration: self.keep_alive,
            client_id: self.client_id.clone(),
        };
        let mut stray = Vec::new();
        let mut buf = vec![0u8; 65_535];
        for _ in 0..=RETRIES {
            self.send(&connect).await?;
            let deadline = Instant::now() + RETRY_AFTER;
            while let Ok(r) = tokio::time::timeout_at(deadline, self.socket.recv(&mut buf)).await {
                let n = r?;
                let Ok(p) = packet::decode(&buf[..n]) else {
                    continue;
                };
                match p {
                    Packet::WillTopicReq => {
                        let (topic, _) = self.will.clone().unwrap_or_default();
                        self.send(&Packet::WillTopic {
                            flags: Flags::default(),
                            topic,
                        })
                        .await?;
                    }
                    Packet::WillMsgReq => {
                        let (_, msg) = self.will.clone().unwrap_or_default();
                        self.send(&Packet::WillMsg { msg }).await?;
                    }
                    Packet::ConnAck { rc } => {
                        ensure!(
                            rc == packet::ACCEPTED,
                            "the gateway refused the connection: {}",
                            packet::return_code_name(rc)
                        );
                        self.asleep = false;
                        return Ok(stray);
                    }
                    other => stray.push(other),
                }
            }
        }
        bail!("the gateway did not answer CONNECT")
    }

    fn topic_ref(&self, topic: &str) -> Option<(u8, u16)> {
        if let Some(id) = self.predefined.get(topic) {
            Some((packet::TOPIC_PREDEFINED, *id))
        } else if let Some(s) = packet::short_topic(topic) {
            Some((packet::TOPIC_SHORT, s))
        } else {
            self.ids.get(topic).map(|id| (packet::TOPIC_NORMAL, *id))
        }
    }

    fn pend(&mut self, op: Op, msg_id: u16, bytes: Vec<u8>) {
        self.pending = Some(Pending {
            op,
            msg_id,
            bytes,
            deadline: Instant::now() + RETRY_AFTER,
            tries: 0,
        });
    }

    async fn publish(&mut self, job: Job) -> Result<()> {
        let Some((kind, id)) = self.topic_ref(&job.topic) else {
            ensure!(job.qos != -1, "QoS -1 needs a short or predefined topic");
            let msg_id = self.msg_id();
            let bytes = self
                .send(&Packet::Register {
                    topic_id: 0,
                    msg_id,
                    topic: job.topic.clone(),
                })
                .await?;
            self.pend(
                Op::Register {
                    topic: job.topic.clone(),
                    then: Some(job),
                },
                msg_id,
                bytes,
            );
            return Ok(());
        };
        let msg_id = if job.qos > 0 { self.msg_id() } else { 0 };
        let flags = Flags {
            qos: job.qos,
            retain: job.retain,
            topic_id_type: kind,
            ..Flags::default()
        };
        self.send(&Packet::Publish {
            flags,
            topic: id,
            msg_id,
            data: job.data.clone(),
        })
        .await?;
        if job.qos > 0 {
            let dup = packet::encode(&Packet::Publish {
                flags: Flags { dup: true, ..flags },
                topic: id,
                msg_id,
                data: job.data,
            });
            self.pend(
                Op::Publish {
                    topic: job.topic,
                    topic_id: id,
                    stage: job.qos as u8,
                },
                msg_id,
                dup,
            );
        } else {
            self.emit(result(
                "publish",
                json!({"topic": job.topic, "topic_id": id, "return_code": "sent"}),
            ))
            .await;
        }
        Ok(())
    }

    /// Start one queued action. Ok(false) ends the session.
    async fn start(&mut self, v: &Json) -> Result<bool> {
        let topic = v["topic"].as_str().unwrap_or_default().to_owned();
        match v["type"].as_str().unwrap_or_default() {
            "disconnect" => {
                self.send(&Packet::Disconnect { duration: None }).await?;
                return Ok(false);
            }
            "mqttsn_register" => {
                let msg_id = self.msg_id();
                let bytes = self
                    .send(&Packet::Register {
                        topic_id: 0,
                        msg_id,
                        topic: topic.clone(),
                    })
                    .await?;
                self.pend(Op::Register { topic, then: None }, msg_id, bytes);
            }
            "mqttsn_publish" => {
                let qos = v["qos"].as_i64().unwrap_or(0) as i8;
                self.publish(Job {
                    topic,
                    data: payload(v)?,
                    qos,
                    retain: v["retain"].as_bool().unwrap_or(false),
                })
                .await?;
            }
            "mqttsn_subscribe" | "mqttsn_unsubscribe" => {
                let qos = v["qos"].as_i64().unwrap_or(0) as i8;
                let msg_id = self.msg_id();
                let (name, kind, id) = match self.predefined.get(&topic) {
                    Some(id) => (None, packet::TOPIC_PREDEFINED, *id),
                    None => match packet::short_topic(&topic) {
                        Some(s) => (None, packet::TOPIC_SHORT, s),
                        None => (Some(topic.clone()), packet::TOPIC_NORMAL, 0),
                    },
                };
                let flags = Flags {
                    qos,
                    topic_id_type: kind,
                    ..Flags::default()
                };
                if v["type"] == "mqttsn_subscribe" {
                    let bytes = self
                        .send(&Packet::Subscribe {
                            flags,
                            msg_id,
                            topic_name: name,
                            topic_id: id,
                        })
                        .await?;
                    self.pend(Op::Subscribe { topic }, msg_id, bytes);
                } else {
                    let bytes = self
                        .send(&Packet::Unsubscribe {
                            flags,
                            msg_id,
                            topic_name: name,
                            topic_id: id,
                        })
                        .await?;
                    self.pend(Op::Unsubscribe { topic }, msg_id, bytes);
                }
            }
            "mqttsn_sleep" => {
                let d = v["duration_secs"].as_u64().unwrap_or(60) as u16;
                let bytes = self.send(&Packet::Disconnect { duration: Some(d) }).await?;
                self.pend(Op::Sleep, 0, bytes);
            }
            "mqttsn_wake" => {
                self.woken = 0;
                let bytes = self
                    .send(&Packet::PingReq {
                        client_id: Some(self.client_id.clone()),
                    })
                    .await?;
                self.pend(Op::Wake, 0, bytes);
            }
            "mqttsn_ping" => {
                let bytes = self.send(&Packet::PingReq { client_id: None }).await?;
                self.pend(Op::Ping, 0, bytes);
            }
            "mqttsn_connect" => {
                let stray = self.handshake().await?;
                self.emit(result("connect", json!({"return_code": "accepted"})))
                    .await;
                for p in stray {
                    if !Box::pin(self.packet(p)).await? {
                        return Ok(false);
                    }
                }
            }
            other => bail!("{other} is not an MQTT-SN client action"),
        }
        Ok(true)
    }

    /// One packet from the gateway. Ok(false) ends the session.
    async fn packet(&mut self, p: Packet) -> Result<bool> {
        let pending_id = self.pending.as_ref().map(|q| q.msg_id);
        match p {
            Packet::Publish {
                flags,
                topic,
                msg_id,
                data,
            } => {
                let name = match flags.topic_id_type {
                    packet::TOPIC_SHORT => Some(packet::short_name(topic)),
                    packet::TOPIC_PREDEFINED => self
                        .predefined
                        .iter()
                        .find(|(_, id)| **id == topic)
                        .map(|(n, _)| n.clone()),
                    _ => self.names.get(&topic).cloned(),
                };
                let Some(name) = name else {
                    if flags.qos > 0 {
                        self.send(&Packet::PubAck {
                            topic_id: topic,
                            msg_id,
                            rc: packet::INVALID_TOPIC_ID,
                        })
                        .await?;
                    }
                    return Ok(true);
                };
                match flags.qos {
                    1 => {
                        self.send(&Packet::PubAck {
                            topic_id: topic,
                            msg_id,
                            rc: packet::ACCEPTED,
                        })
                        .await?;
                    }
                    2 => {
                        self.send(&Packet::PubRec { msg_id }).await?;
                        if !self.received.insert(msg_id) {
                            return Ok(true);
                        }
                    }
                    _ => {}
                }
                self.woken += 1;
                let (payload, enc) = match std::str::from_utf8(&data) {
                    Ok(s) => (json!(s), "utf8"),
                    Err(_) => (json!(hex::encode(&data)), "hex"),
                };
                self.emit(Event::new(&actions::MESSAGE_EVENT, json!({"topic": name, "payload": payload, "payload_encoding": enc, "qos": flags.qos, "retain": flags.retain}))).await;
            }
            Packet::PubRel { msg_id } => {
                self.received.remove(&msg_id);
                self.send(&Packet::PubComp { msg_id }).await?;
            }
            Packet::Register {
                topic_id,
                msg_id,
                topic,
            } => {
                self.ids.insert(topic.clone(), topic_id);
                self.names.insert(topic_id, topic);
                self.send(&Packet::RegAck {
                    topic_id,
                    msg_id,
                    rc: packet::ACCEPTED,
                })
                .await?;
            }
            Packet::RegAck {
                topic_id,
                msg_id,
                rc,
            } if pending_id == Some(msg_id) => {
                let Some(Pending {
                    op: Op::Register { topic, then },
                    ..
                }) = self.pending.take()
                else {
                    return Ok(true);
                };
                if rc == packet::ACCEPTED {
                    self.ids.insert(topic.clone(), topic_id);
                    self.names.insert(topic_id, topic.clone());
                }
                match then {
                    Some(job) if rc == packet::ACCEPTED => self.publish(job).await?,
                    Some(job) => self.emit(result("publish", json!({"topic": job.topic, "return_code": packet::return_code_name(rc)}))).await,
                    None => self.emit(result("register", json!({"topic": topic, "topic_id": topic_id, "return_code": packet::return_code_name(rc)}))).await,
                }
            }
            Packet::PubAck {
                msg_id,
                rc,
                topic_id,
            } => {
                if pending_id == Some(msg_id)
                    && matches!(
                        self.pending.as_ref().map(|q| &q.op),
                        Some(Op::Publish { .. })
                    )
                {
                    if let Some(Pending {
                        op:
                            Op::Publish {
                                topic, topic_id, ..
                            },
                        ..
                    }) = self.pending.take()
                    {
                        self.emit(result("publish", json!({"topic": topic, "topic_id": topic_id, "return_code": packet::return_code_name(rc)}))).await;
                    }
                } else if rc != packet::ACCEPTED {
                    // A rejection of a QoS 0 publish.
                    let topic = self.names.get(&topic_id).cloned();
                    self.emit(result("publish", json!({"topic": topic, "topic_id": topic_id, "return_code": packet::return_code_name(rc)}))).await;
                }
            }
            Packet::PubRec { msg_id } if pending_id == Some(msg_id) => {
                let bytes = self.send(&Packet::PubRel { msg_id }).await?;
                if let Some(q) = self.pending.as_mut() {
                    if let Op::Publish { stage, .. } = &mut q.op {
                        *stage = 3;
                    }
                    q.bytes = bytes;
                    q.tries = 0;
                    q.deadline = Instant::now() + RETRY_AFTER;
                }
            }
            Packet::PubComp { msg_id } if pending_id == Some(msg_id) => {
                if let Some(Pending {
                    op:
                        Op::Publish {
                            topic, topic_id, ..
                        },
                    ..
                }) = self.pending.take()
                {
                    self.emit(result(
                        "publish",
                        json!({"topic": topic, "topic_id": topic_id, "return_code": "accepted"}),
                    ))
                    .await;
                }
            }
            Packet::SubAck {
                flags,
                topic_id,
                msg_id,
                rc,
            } if pending_id == Some(msg_id) => {
                if let Some(Pending {
                    op: Op::Subscribe { topic },
                    ..
                }) = self.pending.take()
                {
                    if rc == packet::ACCEPTED
                        && topic_id != 0
                        && !topic.contains(['+', '#'])
                        && packet::short_topic(&topic).is_none()
                        && !self.predefined.contains_key(&topic)
                    {
                        self.ids.insert(topic.clone(), topic_id);
                        self.names.insert(topic_id, topic.clone());
                    }
                    self.emit(result("subscribe", json!({"topic": topic, "topic_id": topic_id, "granted_qos": flags.qos, "return_code": packet::return_code_name(rc)}))).await;
                }
            }
            Packet::UnsubAck { msg_id } if pending_id == Some(msg_id) => {
                if let Some(Pending {
                    op: Op::Unsubscribe { topic },
                    ..
                }) = self.pending.take()
                {
                    self.emit(result(
                        "unsubscribe",
                        json!({"topic": topic, "return_code": "accepted"}),
                    ))
                    .await;
                }
            }
            Packet::PingResp => match self.pending.as_ref().map(|q| &q.op) {
                Some(Op::Wake) => {
                    self.pending = None;
                    let n = self.woken;
                    self.emit(result(
                        "wake",
                        json!({"messages": n, "return_code": "accepted"}),
                    ))
                    .await;
                }
                Some(Op::Ping) => {
                    self.pending = None;
                    self.emit(result("ping", json!({"return_code": "accepted"})))
                        .await;
                }
                _ => {}
            },
            Packet::Disconnect { .. } => {
                if matches!(self.pending.as_ref().map(|q| &q.op), Some(Op::Sleep)) {
                    self.pending = None;
                    self.asleep = true;
                    self.emit(result("sleep", json!({"return_code": "accepted"})))
                        .await;
                } else {
                    self.emit(Event::new(
                        &actions::DISCONNECTED_EVENT,
                        json!({"reason": "the gateway sent DISCONNECT"}),
                    ))
                    .await;
                    return Ok(false);
                }
            }
            Packet::PingReq { .. } => {
                self.send(&Packet::PingResp).await?;
            }
            other => Log::new(None).debug(format!("MQTT-SN client: unexpected {}", other.name())),
        }
        Ok(true)
    }

    async fn timers(&mut self) -> Result<()> {
        let now = Instant::now();
        if let Some(q) = self.pending.as_mut() {
            if now >= q.deadline {
                if q.tries < RETRIES {
                    q.tries += 1;
                    q.deadline = now + RETRY_AFTER;
                    let bytes = q.bytes.clone();
                    self.socket.send(&bytes).await?;
                } else if let Some(q) = self.pending.take() {
                    let operation = match q.op {
                        Op::Register { .. } => "register",
                        Op::Publish { .. } => "publish",
                        Op::Subscribe { .. } => "subscribe",
                        Op::Unsubscribe { .. } => "unsubscribe",
                        Op::Sleep => "sleep",
                        Op::Wake => "wake",
                        Op::Ping => "ping",
                    };
                    self.emit(result(operation, json!({"return_code": "timeout"})))
                        .await;
                }
            }
        }
        if !self.asleep
            && self.pending.is_none()
            && self.keep_alive > 0
            && now.duration_since(self.last_sent)
                > Duration::from_millis(self.keep_alive as u64 * 750)
        {
            self.send(&Packet::PingReq { client_id: None }).await?;
        }
        Ok(())
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx.startup_params.as_ref();
    let get = |k: &str| {
        p.map(|p| p.get_optional_string(k))
            .transpose()
            .map(Option::flatten)
    };
    let client_id =
        get("client_id")?.unwrap_or_else(|| format!("netget-{}", ctx.client_id.as_u32()));
    ensure!(
        !client_id.is_empty() && client_id.len() <= 23,
        "client_id is 1 to 23 characters"
    );
    let keep_alive = match p
        .map(|p| p.get_optional_u64("keep_alive_secs"))
        .transpose()?
        .flatten()
    {
        Some(k) => u16::try_from(k).context("keep_alive_secs is 0-65535")?,
        None => DEFAULT_KEEP_ALIVE,
    };
    let clean = p
        .map(|p| p.get_optional_bool("clean_session"))
        .transpose()?
        .flatten()
        .unwrap_or(true);
    let will = match get("will_topic")? {
        Some(t) => {
            ensure!(packet::valid_topic(&t), "will_topic is a topic name");
            Some((t, get("will_message")?.unwrap_or_default().into_bytes()))
        }
        None => None,
    };
    let mut predefined = HashMap::new();
    if let Some(map) = p
        .map(|p| p.get_optional_object("predefined_topics"))
        .transpose()?
        .flatten()
    {
        for (id, name) in map {
            predefined.insert(
                name.as_str()
                    .context("a predefined topic is a name")?
                    .to_owned(),
                id.parse().context("a predefined topic id is 1-65535")?,
            );
        }
    }
    let remote: SocketAddr = tokio::net::lookup_host(&ctx.remote_addr)
        .await?
        .next()
        .context("the gateway address does not resolve")?;
    let socket = UdpSocket::bind(if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    socket.connect(remote).await?;
    let local = socket.local_addr()?;
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(64);
    let mut sensor = Sensor {
        socket,
        client_id: client_id.clone(),
        keep_alive,
        clean,
        will,
        predefined,
        ids: HashMap::new(),
        names: HashMap::new(),
        next_id: 0,
        pending: None,
        queue: VecDeque::new(),
        received: HashSet::new(),
        woken: 0,
        events: event_tx.clone(),
        last_sent: Instant::now(),
        asleep: false,
    };
    let stray = sensor.handshake().await?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Json>(64);
    event_tx.try_send(Event::new(
        &actions::CONNECTED_EVENT,
        json!({"gateway": remote.to_string(), "client_id": client_id}),
    ))?;
    let events_ctx = ctx.clone();
    // One model call at a time. What the session reports while a call runs (deliveries from
    // the gateway, results of earlier operations) waits on `event_rx`; with batching on the
    // next call takes everything waiting, one event each, and with it off one event per call.
    // Deliveries are acknowledged by `Sensor::packet` before they are queued, so none waits on
    // the model for its PUBACK/PUBREC.
    let dispatcher = tokio::spawn(async move {
        let protocol = MqttSnClientProtocol;
        while let Some(event) = event_rx.recv().await {
            let mut events = vec![event];
            if events_ctx
                .state
                .client_conversation_settings(events_ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching)
            {
                while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match event_rx.try_recv() {
                        Ok(next) => events.push(next),
                        Err(_) => break,
                    }
                }
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
                &protocol,
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
                        if internal_tx.send(action).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("MQTT-SN client handler: {e}")),
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        if let Err(e) = run(&session_ctx, &mut sensor, stray, external, internal_rx).await {
            Log::new(Some(&session_ctx.status_tx)).warn(format!("MQTT-SN client ended: {e:#}"));
        }
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
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

async fn run(
    ctx: &ConnectContext,
    s: &mut Sensor,
    stray: Vec<Packet>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Json>,
) -> Result<()> {
    for p in stray {
        if !s.packet(p).await? {
            return Ok(());
        }
    }
    let mut buf = vec![0u8; 65_535];
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            r = s.socket.recv(&mut buf) => {
                // ICMP port unreachable surfaces here as an error; the retries decide.
                if let Ok(n) = r {
                    if let Ok(p) = packet::decode(&buf[..n]) {
                        if !s.packet(p).await? {
                            return Ok(());
                        }
                    }
                }
            }
            c = external.recv() => match c {
                Some(c) => {
                    let action = c.action.clone();
                    match MqttSnClientProtocol.execute_action(action.clone()) {
                        Err(e) => crate::client::command_support::reply(c, Ok(ClientSendOutcome::Rejected { error: e.to_string() })),
                        Ok(_) => s.queue.push_back((action, Some(c))),
                    }
                }
                None => return Ok(()),
            },
            a = internal.recv() => match a {
                Some(a) => match MqttSnClientProtocol.execute_action(a.clone()) {
                    Ok(ClientActionResult::Disconnect) | Ok(ClientActionResult::Custom { .. }) => s.queue.push_back((a, None)),
                    Ok(_) => {}
                    Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("MQTT-SN action refused: {e}")),
                },
                None => return Ok(()),
            },
            _ = tick.tick() => s.timers().await?,
        }
        while s.pending.is_none() {
            let Some((action, command)) = s.queue.pop_front() else {
                break;
            };
            let kind = action["type"].as_str().unwrap_or_default().to_owned();
            let started = s.start(&action).await;
            if let Some(c) = command {
                let outcome = match &started {
                    Ok(true) => ClientSendOutcome::Sent { bytes_sent: 0 },
                    Ok(false) => ClientSendOutcome::Disconnected,
                    Err(e) => ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                };
                ctx.state
                    .record_access_log(
                        AccessLogOwner::Client(ctx.client_id.as_u32()),
                        "MQTT-SN",
                        None,
                        "injected_action",
                        json!({"type": kind}),
                        vec![serde_json::to_value(&outcome).unwrap_or(Json::Null)],
                    )
                    .await;
                crate::client::command_support::reply(c, Ok(outcome));
            } else if let Err(e) = &started {
                Log::new(Some(&ctx.status_tx)).warn(format!("MQTT-SN {kind} failed: {e:#}"));
            }
            if matches!(started, Ok(false)) {
                return Ok(());
            }
        }
    }
}
