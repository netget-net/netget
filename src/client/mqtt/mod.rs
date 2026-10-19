//! MQTT client implementation, over rumqttc's 3.1.1 and 5.0 stacks.
//!
//! `protocol_version` picks the stack at connect time. Everything above the transport — the
//! turn queue, the model calls, the injected-command loop — is shared: [`Broker`] is the one
//! handle actions are applied through, [`Transport`] the one event loop polled, and
//! [`Message`] the one shape a received PUBLISH reaches the model in. Only the two enums know
//! there are two rumqttc APIs.
pub mod actions;

pub use actions::MqttClientProtocol;

use anyhow::{Context, Result};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::protocol::StartupParams;

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::client::mqtt::actions::{MQTT_CLIENT_CONNECTED_EVENT, MQTT_MESSAGE_RECEIVED_EVENT};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event as ProtocolEvent;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// MQTT client that connects to an MQTT broker
pub struct MqttClient;

impl MqttClient {
    /// Connect to an MQTT broker with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse remote address (host:port)
        let parts: Vec<&str> = remote_addr.split(':').collect();
        let host = parts
            .get(0)
            .context("Missing host in remote_addr")?
            .to_string();
        let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(1883);

        // Extract startup parameters
        let mqtt_client_id = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("client_id"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| format!("netget-{}", client_id));

        let username = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("username"))
            .transpose()?
            .flatten();

        let password = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("password"))
            .transpose()?
            .flatten();

        let keep_alive = startup_params
            .as_ref()
            .map(|p| p.get_optional_u64("keep_alive"))
            .transpose()?
            .flatten()
            .unwrap_or(60);

        let clean_session = startup_params
            .as_ref()
            .map(|p| p.get_optional_bool("clean_session"))
            .transpose()?
            .flatten()
            .unwrap_or(true);

        let version = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("protocol_version"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string());
        let v5 = match version.trim() {
            "3.1.1" | "4" | "311" => false,
            "5" | "5.0" | "v5" => true,
            other => anyhow::bail!("protocol_version must be \"3.1.1\" or \"5.0\", not {other:?}"),
        };

        info!(
            "MQTT client {} connecting to {}:{} with client_id={} (MQTT {})",
            client_id,
            host,
            port,
            mqtt_client_id,
            if v5 { "5.0" } else { "3.1.1" }
        );

        let (mqtt_client, eventloop) = if v5 {
            let mut options = rumqttc::v5::MqttOptions::new(&mqtt_client_id, &host, port);
            options.set_keep_alive(Duration::from_secs(keep_alive));
            options.set_clean_start(clean_session);
            if let (Some(user), Some(pass)) = (username, password) {
                options.set_credentials(user, pass);
            }
            let (c, e) = rumqttc::v5::AsyncClient::new(options, 10);
            (Broker::V5(c), Transport::V5(Box::new(e)))
        } else {
            let mut options = MqttOptions::new(&mqtt_client_id, &host, port);
            options.set_keep_alive(Duration::from_secs(keep_alive));
            options.set_clean_session(clean_session);
            if let (Some(user), Some(pass)) = (username, password) {
                options.set_credentials(user, pass);
            }
            let (c, e) = AsyncClient::new(options, 10);
            (Broker::V4(c), Transport::V4(Box::new(e)))
        };

        // For returning the local address, we need to extract it from the eventloop
        // rumqttc doesn't expose local_addr directly, so we'll construct a fake SocketAddr
        // based on the remote address. The actual TCP connection is managed internally.
        let local_addr: SocketAddr = format!("0.0.0.0:0").parse().unwrap();

        // Clone for the event loop task
        let mqtt_client_clone = mqtt_client.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();

        // Set when a `disconnect` was asked for, so the event loop's read error that follows
        // is reported as a clean disconnect rather than as a connection failure.
        let disconnecting = Arc::new(AtomicBool::new(false));

        // Command channel for injected actions (the dashboard's [ send ]). Registered here,
        // before the transport task starts, so it exists throughout the connected-event LLM
        // call the turn task makes on CONNACK - a manual `*` rule can park that call for
        // minutes and the operator must still be able to publish.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_client = mqtt_client.clone();
        let cmd_state = app_state.clone();
        let cmd_status_tx = status_tx.clone();
        let cmd_disconnecting = disconnecting.clone();
        let cmd_task = tokio::spawn(async move {
            command_loop(
                command_rx,
                cmd_client,
                client_id,
                cmd_state,
                cmd_status_tx,
                cmd_disconnecting,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Two tasks per connection, because the transport and the model run on different
        // clocks. rumqttc writes PINGREQ and reads PINGRESP only while `EventLoop::poll` is
        // being awaited; a model turn can take minutes (a `manual` rule parks it for a human
        // for up to 300s), and a broker drops a client that is silent for 1.5 x keep-alive.
        // So `poll_transport` owns the event loop and never waits on the model, and
        // `run_model_turns` answers events one at a time, in order, from a queue - which is
        // also what keeps two turns from ever overlapping on this connection.
        let (turn_tx, turn_rx) = mpsc::channel::<TurnEvent>(TURN_QUEUE_CAPACITY);
        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                run_model_turns(
                    turn_rx,
                    mqtt_client_clone,
                    llm_client,
                    app_state_clone.clone(),
                    status_tx_clone.clone(),
                    client_id,
                    mqtt_client_id,
                    disconnecting.clone(),
                ),
            )
            .await;
        app_state
            .spawn_client_task(
                client_id,
                poll_transport(
                    eventloop,
                    app_state_clone,
                    status_tx_clone,
                    client_id,
                    disconnecting,
                    turn_tx,
                    turn_abort,
                ),
            )
            .await;

        Ok(local_addr)
    }
}

/// How many broker events may wait for the model while a turn is running.
///
/// The transport task must never block on the model - that is the whole point of running it
/// separately - so when this queue is full an incoming PUBLISH is dropped (and logged with
/// `decision=turn_queue_full`) rather than stalling the keep-alive. Each entry is at most one
/// packet of rumqttc's default 10 KiB incoming limit, so the queue bounds the memory a
/// flooding broker can pin at ~2.5 MiB per client. 256 unanswered messages is already many
/// minutes of model time; a backlog past that is not going to be caught up with.
const TURN_QUEUE_CAPACITY: usize = 256;

/// `protocol_version` when the caller names none.
pub const DEFAULT_PROTOCOL_VERSION: &str = "3.1.1";

/// One thing the model is asked about, in arrival order.
enum TurnEvent {
    /// The first CONNACK: the client's chance to subscribe or publish first. On v5 it carries
    /// what the CONNACK said (reason code and properties).
    Connected(Option<serde_json::Value>),
    /// A PUBLISH delivered by the broker.
    Message(Message),
}

/// A PUBLISH from the broker, in either version.
struct Message {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
    /// v5 only: the message's properties as the model sees them.
    properties: Option<serde_json::Value>,
}

/// The request side of a connection: what actions are applied through.
#[derive(Clone)]
enum Broker {
    V4(AsyncClient),
    V5(rumqttc::v5::AsyncClient),
}

/// Subscription options the model may set. Only v5 has anything beyond QoS.
#[derive(Clone, Copy, Default)]
struct SubscribeOptions {
    no_local: bool,
    retain_as_published: bool,
    retain_handling: u8,
}

impl Broker {
    fn is_v5(&self) -> bool {
        matches!(self, Broker::V5(_))
    }

    async fn subscribe(&self, topic: &str, qos: u8, opts: SubscribeOptions) -> Result<()> {
        match self {
            Broker::V4(c) => c.subscribe(topic, qos_from_u64(u64::from(qos))).await?,
            Broker::V5(c) => {
                use rumqttc::v5::mqttbytes::v5::{Filter, RetainForwardRule};
                let mut filter = Filter::new(topic, v5_qos(qos));
                filter.nolocal = opts.no_local;
                filter.preserve_retain = opts.retain_as_published;
                filter.retain_forward_rule = match opts.retain_handling {
                    1 => RetainForwardRule::OnNewSubscribe,
                    2 => RetainForwardRule::Never,
                    _ => RetainForwardRule::OnEverySubscribe,
                };
                c.subscribe_many(vec![filter]).await?
            }
        }
        Ok(())
    }

    async fn publish(
        &self,
        topic: &str,
        qos: u8,
        retain: bool,
        payload: Vec<u8>,
        properties: Option<&serde_json::Value>,
    ) -> Result<()> {
        match self {
            Broker::V4(c) => {
                c.publish(topic, qos_from_u64(u64::from(qos)), retain, payload)
                    .await?
            }
            Broker::V5(c) => match properties {
                Some(p) => {
                    c.publish_with_properties(
                        topic,
                        v5_qos(qos),
                        retain,
                        payload,
                        publish_properties(p)?,
                    )
                    .await?
                }
                None => c.publish(topic, v5_qos(qos), retain, payload).await?,
            },
        }
        Ok(())
    }

    async fn unsubscribe(&self, topic: &str) -> Result<()> {
        match self {
            Broker::V4(c) => c.unsubscribe(topic).await?,
            Broker::V5(c) => c.unsubscribe(topic).await?,
        }
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        match self {
            Broker::V4(c) => c.disconnect().await?,
            Broker::V5(c) => c.disconnect().await?,
        }
        Ok(())
    }
}

fn v5_qos(qos: u8) -> rumqttc::v5::mqttbytes::QoS {
    use rumqttc::v5::mqttbytes::QoS as Q;
    match qos {
        1 => Q::AtLeastOnce,
        2 => Q::ExactlyOnce,
        _ => Q::AtMostOnce,
    }
}

/// The model's `properties` object (validated by the action executor) as rumqttc's.
fn publish_properties(
    p: &serde_json::Value,
) -> Result<rumqttc::v5::mqttbytes::v5::PublishProperties> {
    use crate::server::mqtt::v5 as props;
    let text = |k: &str| p.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let correlation_data = match text("correlation_data") {
        Some(c) => Some(
            props::text_to_binary(
                &c,
                p.get("correlation_data_encoding").and_then(|e| e.as_str()),
            )
            .map_err(|e| anyhow::anyhow!("correlation_data: {e}"))?
            .into(),
        ),
        None => None,
    };
    Ok(rumqttc::v5::mqttbytes::v5::PublishProperties {
        payload_format_indicator: p
            .get("payload_format_indicator")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8),
        message_expiry_interval: p
            .get("message_expiry_interval")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        topic_alias: None,
        response_topic: text("response_topic"),
        correlation_data,
        user_properties: props::user_properties_from_json(p.get("user_properties"))
            .map_err(|e| anyhow::anyhow!(e))?,
        subscription_identifiers: Vec::new(),
        content_type: text("content_type"),
    })
}

/// What the transport saw, in either version.
enum Notice {
    ConnAck(Option<serde_json::Value>),
    Publish(Message),
    /// The broker closed the session; on v5 its DISCONNECT may say why.
    Disconnect(Option<String>),
    /// The broker broke the protocol in a way this client ends the connection over. Carries
    /// the category only, never the packet's content.
    ProtocolViolation(&'static str),
    Other,
}

/// What a v5 PUBLISH carrying a Topic Alias is reported as.
pub const TOPIC_ALIAS_VIOLATION: &str = "topic alias";

/// The event-loop side of a connection.
enum Transport {
    V4(Box<EventLoop>),
    V5(Box<rumqttc::v5::EventLoop>),
}

impl Transport {
    async fn next(&mut self) -> std::result::Result<Notice, String> {
        match self {
            Transport::V4(e) => match e.poll().await.map_err(|e| e.to_string())? {
                Event::Incoming(Packet::ConnAck(_)) => Ok(Notice::ConnAck(None)),
                Event::Incoming(Packet::Publish(p)) => Ok(Notice::Publish(Message {
                    topic: p.topic.clone(),
                    payload: p.payload.to_vec(),
                    qos: p.qos as u8,
                    retain: p.retain,
                    properties: None,
                })),
                Event::Incoming(Packet::Disconnect) => Ok(Notice::Disconnect(None)),
                other => {
                    trace!("MQTT event: {:?}", other);
                    Ok(Notice::Other)
                }
            },
            Transport::V5(e) => {
                use rumqttc::v5::mqttbytes::v5::Packet as P5;
                use rumqttc::v5::Event as E5;
                match e.poll().await.map_err(|e| e.to_string())? {
                    E5::Incoming(P5::ConnAck(ack)) => {
                        let mut info = serde_json::json!({
                            "reason_code": connack_code(&ack.code),
                            "session_present": ack.session_present,
                        });
                        if let Some(p) = &ack.properties {
                            info["properties"] = connack_properties_json(p);
                        }
                        Ok(Notice::ConnAck(Some(info)))
                    }
                    // NetGet's CONNECT sends no Topic Alias Maximum, which is 0, so the broker
                    // MUST NOT send an alias (§3.1.2.11.5, [MQTT-3.1.2-27]). rumqttc does not
                    // check that: it stores every alias it reads in a map of its own with no
                    // bound, before the PUBLISH reaches this code. So the first aliased
                    // PUBLISH ends the connection. What rumqttc stored by then is bounded by
                    // one read batch (it handles at most 10 packets before yielding the first,
                    // each within its 10 KiB incoming limit), and dropping the event loop frees
                    // it. rumqttc's socket is private, so no DISCONNECT 0x94 precedes the close.
                    E5::Incoming(P5::Publish(p))
                        if p.properties
                            .as_ref()
                            .is_some_and(|props| props.topic_alias.is_some()) =>
                    {
                        Ok(Notice::ProtocolViolation(TOPIC_ALIAS_VIOLATION))
                    }
                    E5::Incoming(P5::Publish(p)) => Ok(Notice::Publish(Message {
                        topic: String::from_utf8_lossy(&p.topic).into_owned(),
                        payload: p.payload.to_vec(),
                        qos: p.qos as u8,
                        retain: p.retain,
                        properties: Some(
                            p.properties
                                .as_ref()
                                .map(publish_properties_json)
                                .unwrap_or_else(|| serde_json::json!({})),
                        ),
                    })),
                    E5::Incoming(P5::Disconnect(d)) => Ok(Notice::Disconnect(Some(format!(
                        "reason 0x{:02x}{}",
                        d.reason_code as u8,
                        d.properties
                            .as_ref()
                            .and_then(|p| p.reason_string.as_ref())
                            .map(|r| format!(" ({r})"))
                            .unwrap_or_default()
                    )))),
                    other => {
                        trace!("MQTT v5 event: {:?}", other);
                        Ok(Notice::Other)
                    }
                }
            }
        }
    }
}

/// A v5 CONNACK reason as its wire value (§3.2.2.2).
fn connack_code(code: &rumqttc::v5::mqttbytes::v5::ConnectReturnCode) -> u8 {
    use rumqttc::v5::mqttbytes::v5::ConnectReturnCode as C;
    match code {
        C::Success => 0x00,
        C::RefusedProtocolVersion | C::UnsupportedProtocolVersion => 0x84,
        C::BadClientId | C::ClientIdentifierNotValid => 0x85,
        C::ServiceUnavailable | C::ServerUnavailable => 0x88,
        C::UnspecifiedError => 0x80,
        C::MalformedPacket => 0x81,
        C::ProtocolError => 0x82,
        C::ImplementationSpecificError => 0x83,
        C::BadUserNamePassword => 0x86,
        C::NotAuthorized => 0x87,
        C::ServerBusy => 0x89,
        C::Banned => 0x8A,
        C::BadAuthenticationMethod => 0x8C,
        C::TopicNameInvalid => 0x90,
        C::PacketTooLarge => 0x95,
        C::QuotaExceeded => 0x97,
        C::PayloadFormatInvalid => 0x99,
        C::RetainNotSupported => 0x9A,
        C::QoSNotSupported => 0x9B,
        C::UseAnotherServer => 0x9C,
        C::ServerMoved => 0x9D,
        C::ConnectionRateExceeded => 0x9F,
    }
}

fn pairs_json(pairs: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Array(
        pairs
            .iter()
            .map(|(k, v)| serde_json::json!([k, v]))
            .collect(),
    )
}

/// CONNACK properties under the server's own snake_case names.
fn connack_properties_json(p: &rumqttc::v5::mqttbytes::v5::ConnAckProperties) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        if !v.is_null() {
            out.insert(k.to_string(), v);
        }
    };
    put(
        "session_expiry_interval",
        serde_json::json!(p.session_expiry_interval),
    );
    put("receive_maximum", serde_json::json!(p.receive_max));
    put("maximum_qos", serde_json::json!(p.max_qos));
    put("retain_available", serde_json::json!(p.retain_available));
    put("maximum_packet_size", serde_json::json!(p.max_packet_size));
    put(
        "assigned_client_identifier",
        serde_json::json!(p.assigned_client_identifier),
    );
    put("topic_alias_maximum", serde_json::json!(p.topic_alias_max));
    put("reason_string", serde_json::json!(p.reason_string));
    put("server_keep_alive", serde_json::json!(p.server_keep_alive));
    put(
        "response_information",
        serde_json::json!(p.response_information),
    );
    put("server_reference", serde_json::json!(p.server_reference));
    if !p.user_properties.is_empty() {
        put("user_properties", pairs_json(&p.user_properties));
    }
    serde_json::Value::Object(out)
}

/// PUBLISH properties under the server's own snake_case names, binary as text or hex.
fn publish_properties_json(p: &rumqttc::v5::mqttbytes::v5::PublishProperties) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    if let Some(v) = p.payload_format_indicator {
        out.insert("payload_format_indicator".into(), serde_json::json!(v));
    }
    if let Some(v) = p.message_expiry_interval {
        out.insert("message_expiry_interval".into(), serde_json::json!(v));
    }
    if let Some(v) = &p.content_type {
        out.insert("content_type".into(), serde_json::json!(v));
    }
    if let Some(v) = &p.response_topic {
        out.insert("response_topic".into(), serde_json::json!(v));
    }
    if let Some(v) = &p.correlation_data {
        let (text, encoding) = crate::server::mqtt::v5::binary_to_text(v);
        out.insert("correlation_data".into(), serde_json::json!(text));
        out.insert(
            "correlation_data_encoding".into(),
            serde_json::json!(encoding),
        );
    }
    if !p.subscription_identifiers.is_empty() {
        out.insert(
            "subscription_identifiers".into(),
            serde_json::json!(p.subscription_identifiers),
        );
    }
    if !p.user_properties.is_empty() {
        out.insert("user_properties".into(), pairs_json(&p.user_properties));
    }
    serde_json::Value::Object(out)
}

/// Own the rumqttc event loop for the life of the connection.
///
/// Awaiting `poll` is what drives the MQTT transport: it writes queued requests (the model's
/// publishes and subscribes, injected commands), sends PINGREQ once per keep-alive interval
/// and reads PINGRESP. Nothing here waits on the model; events it needs answered go onto the
/// turn queue. Status (Connected / Disconnected / Error) is set here, so it stays true while a
/// turn is parked.
async fn poll_transport(
    mut eventloop: Transport,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    disconnecting: Arc<AtomicBool>,
    turn_tx: mpsc::Sender<TurnEvent>,
    turn_abort: tokio::task::AbortHandle,
) {
    let mut connected = false;

    loop {
        match eventloop.next().await {
            Ok(notification) => {
                match notification {
                    Notice::ConnAck(info) => {
                        if !connected {
                            connected = true;
                            info!("MQTT client {} connected to broker", client_id);
                            app_state
                                .update_client_status(client_id, ClientStatus::Connected)
                                .await;
                            let _ = status_tx
                                .send(format!("[CLIENT] MQTT client {} connected", client_id));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            enqueue_turn(&turn_tx, TurnEvent::Connected(info), client_id);
                        }
                    }
                    Notice::Publish(publish) => {
                        debug!(
                            "MQTT client {} received message on topic '{}': {} bytes",
                            client_id,
                            publish.topic,
                            publish.payload.len()
                        );
                        enqueue_turn(&turn_tx, TurnEvent::Message(publish), client_id);
                    }
                    Notice::Disconnect(why) => {
                        let why = why.map(|w| format!(" ({w})")).unwrap_or_default();
                        info!("MQTT client {} disconnected by broker{}", client_id, why);
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx.send(format!(
                            "[CLIENT] MQTT client {} disconnected by broker{}",
                            client_id, why
                        ));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Notice::ProtocolViolation(category) => {
                        // Returning ends the connection: the event loop, its socket and
                        // whatever rumqttc stored for it are dropped below.
                        warn!(
                            "MQTT client {} closing: broker sent a {} \
                             decision=protocol_error",
                            client_id, category
                        );
                        app_state
                            .update_client_status(
                                client_id,
                                ClientStatus::Error(format!("protocol violation: {category}")),
                            )
                            .await;
                        let _ = status_tx.send(format!(
                            "[CLIENT] MQTT client {} closed the connection: protocol violation \
                             ({})",
                            client_id, category
                        ));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    // PINGREQ / PINGRESP, acknowledgements and outgoing packets are traced by
                    // `Transport::next`.
                    Notice::Other => {}
                }
            }
            Err(e) => {
                // A `disconnect` action closes the socket, and rumqttc reports the closed
                // socket as a poll error. Reporting that as ClientStatus::Error would draw a
                // deliberate hang-up as a failure, so the requested case is separated out.
                if disconnecting.load(Ordering::SeqCst) {
                    info!("MQTT client {} disconnected on request", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ =
                        status_tx.send(format!("[CLIENT] MQTT client {} disconnected", client_id));
                } else {
                    error!("MQTT client {} connection error: {}", client_id, e);
                    app_state
                        .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                        .await;
                    let _ =
                        status_tx.send(format!("[CLIENT] MQTT client {} error: {}", client_id, e));
                }
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    // The connection is gone, so a turn still running - or parked for a human - has nothing
    // left to answer on, and the queued events behind it would each cost a model call for a
    // reply that cannot be sent.
    turn_abort.abort();
    // Every exit path lands here: drop the command handle so the dashboard stops offering
    // [ send ] on a dead connection. It also closes the command channel, which ends
    // `command_loop`.
    app_state.remove_client_handle(client_id).await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Put an event on the turn queue without ever waiting for room.
fn enqueue_turn(turn_tx: &mpsc::Sender<TurnEvent>, event: TurnEvent, client_id: ClientId) {
    match turn_tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(TurnEvent::Message(publish))) => {
            warn!(
                "MQTT client {} dropped a message on '{}': {} events already wait for the \
                 model decision=turn_queue_full",
                client_id, publish.topic, TURN_QUEUE_CAPACITY
            );
        }
        Err(mpsc::error::TrySendError::Full(TurnEvent::Connected(_))) => {
            warn!(
                "MQTT client {} dropped its connected event decision=turn_queue_full",
                client_id
            );
        }
        // The turn task has ended (aborted with the client); nothing to answer.
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// Answer queued events with the model, in arrival order.
///
/// With batching off each event is its own model call. With it on, a PUBLISH taken off the
/// queue brings every PUBLISH already waiting behind it — what arrived while the model was
/// answering the previous turn — into the same call (`call_llm_for_client_batch`, one event
/// per message). A `Connected` met while draining ends the batch and is answered next. QoS
/// acknowledgements are rumqttc's, written by the transport task, so no delivery waits on the
/// model to be acknowledged and folding several into one call cannot lose an ack.
#[allow(clippy::too_many_arguments)]
async fn run_model_turns(
    mut turn_rx: mpsc::Receiver<TurnEvent>,
    mqtt_client: Broker,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    mqtt_client_id: String,
    disconnecting: Arc<AtomicBool>,
) {
    let mut held: Option<TurnEvent> = None;
    loop {
        let turn = match held.take() {
            Some(turn) => turn,
            None => match turn_rx.recv().await {
                Some(turn) => turn,
                None => break,
            },
        };
        match turn {
            TurnEvent::Connected(info) => {
                handle_connected(
                    info,
                    &mqtt_client,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    client_id,
                    &mqtt_client_id,
                    &disconnecting,
                )
                .await;
            }
            TurnEvent::Message(publish) => {
                let mut messages = vec![publish];
                // Read per turn: batching is hot-changeable.
                if app_state
                    .client_conversation_settings(client_id)
                    .await
                    .is_some_and(|(_, batching)| batching)
                {
                    while messages.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match turn_rx.try_recv() {
                            Ok(TurnEvent::Message(next)) => messages.push(next),
                            Ok(other) => {
                                held = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }
                handle_incoming_messages(
                    &messages,
                    &mqtt_client,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    client_id,
                    &disconnecting,
                )
                .await;
            }
        }
    }
}

/// Ask the model what to do now that the broker accepted the CONNECT.
#[allow(clippy::too_many_arguments)]
async fn handle_connected(
    connack: Option<serde_json::Value>,
    mqtt_client: &Broker,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    client_id: ClientId,
    mqtt_client_id: &str,
    disconnecting: &Arc<AtomicBool>,
) {
    let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
        return;
    };
    let protocol = Arc::new(MqttClientProtocol::new());
    let mut data = serde_json::json!({
        "remote_addr": "connected",
        "client_id": mqtt_client_id,
        "protocol_version": if mqtt_client.is_v5() { "5.0" } else { "3.1.1" },
    });
    // v5 CONNACK: its reason code and properties (an assigned client id among them).
    if let Some(serde_json::Value::Object(ack)) = connack {
        for (k, v) in ack {
            data[k] = v;
        }
    }
    let event = ProtocolEvent::new(&MQTT_CLIENT_CONNECTED_EVENT, data);

    let memory = app_state
        .get_memory_for_client(client_id)
        .await
        .unwrap_or_default();

    match call_llm_for_client(
        llm_client,
        app_state,
        client_id.to_string(),
        &instruction,
        &memory,
        Some(&event),
        protocol.as_ref(),
        status_tx,
    )
    .await
    {
        Ok(result) => {
            handle_llm_actions(
                result,
                mqtt_client,
                app_state,
                client_id,
                &protocol,
                disconnecting,
            )
            .await;
        }
        Err(e) => {
            error!("LLM error for MQTT client {}: {}", client_id, e);
        }
    }
}

/// The event one received PUBLISH raises.
fn message_event(publish: &Message) -> ProtocolEvent {
    let mut data = serde_json::json!({
        "topic": publish.topic,
        "payload": String::from_utf8_lossy(&publish.payload).to_string(),
        "qos": publish.qos,
        "retain": publish.retain,
    });
    if let Some(properties) = &publish.properties {
        data["properties"] = properties.clone();
    }
    ProtocolEvent::new(&MQTT_MESSAGE_RECEIVED_EVENT, data)
}

/// Ask the model about received messages — more than one only when batching gathered them —
/// and apply its answer.
#[allow(clippy::too_many_arguments)]
async fn handle_incoming_messages(
    messages: &[Message],
    mqtt_client: &Broker,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    client_id: ClientId,
    disconnecting: &Arc<AtomicBool>,
) {
    let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
        return;
    };
    let protocol = Arc::new(MqttClientProtocol::new());
    let events: Vec<ProtocolEvent> = messages.iter().map(message_event).collect();

    let memory = app_state
        .get_memory_for_client(client_id)
        .await
        .unwrap_or_default();

    match call_llm_for_client_batch(
        llm_client,
        app_state,
        client_id.to_string(),
        &instruction,
        &memory,
        &events,
        protocol.as_ref(),
        status_tx,
    )
    .await
    {
        Ok(result) => {
            handle_llm_actions(
                result,
                mqtt_client,
                app_state,
                client_id,
                &protocol,
                disconnecting,
            )
            .await;
        }
        Err(e) => {
            error!("LLM error for MQTT client {}: {}", client_id, e);
        }
    }
}

/// What [`apply_action`] did with one executed action.
enum MqttApplied {
    /// Handed to rumqttc, whose event loop writes the packet on the socket. rumqttc returns
    /// as soon as the request is accepted and reports no byte count, so this is deliberately
    /// not a "sent N bytes" claim.
    Queued(String),
    /// Ran, but nothing was put on the wire.
    NoWire(String),
    /// A disconnect was requested and sent to the broker.
    Disconnect,
}

/// Apply one executed action to the live broker connection.
///
/// Shared by the LLM path ([`handle_llm_actions`]) and by injected commands
/// ([`command_loop`]), so the mapping from `mqtt_publish`/`mqtt_subscribe`/`mqtt_unsubscribe`
/// onto `rumqttc` calls exists exactly once and an injected action behaves identically to an
/// LLM-produced one.
async fn apply_action(
    action_result: ClientActionResult,
    mqtt_client: &Broker,
    client_id: ClientId,
    disconnecting: &Arc<AtomicBool>,
) -> Result<MqttApplied> {
    match action_result {
        ClientActionResult::Custom { name, data } => match name.as_str() {
            "mqtt_subscribe" => {
                let topics = data
                    .get("topics")
                    .and_then(|v| v.as_array())
                    .context("mqtt_subscribe result has no 'topics' array")?;
                let qos = data.get("qos").and_then(|v| v.as_u64()).unwrap_or(0);
                let flag = |k: &str| data.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
                let opts = SubscribeOptions {
                    no_local: flag("no_local"),
                    retain_as_published: flag("retain_as_published"),
                    retain_handling: data
                        .get("retain_handling")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u8,
                };

                let mut subscribed: Vec<String> = Vec::new();
                for topic in topics {
                    if let Some(topic_str) = topic.as_str() {
                        mqtt_client
                            .subscribe(topic_str, qos as u8, opts)
                            .await
                            .with_context(|| format!("subscribe to '{topic_str}' failed"))?;
                        info!(
                            "MQTT client {} subscribed to '{}' with QoS {}",
                            client_id, topic_str, qos
                        );
                        subscribed.push(topic_str.to_string());
                    }
                }
                if subscribed.is_empty() {
                    return Ok(MqttApplied::NoWire(
                        "mqtt_subscribe: no valid topic strings".to_string(),
                    ));
                }
                Ok(MqttApplied::Queued(format!(
                    "SUBSCRIBE to [{}] at QoS {} accepted by rumqttc",
                    subscribed.join(", "),
                    qos
                )))
            }
            "mqtt_publish" => {
                let topic = data
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .context("mqtt_publish result has no 'topic'")?;
                let payload = data
                    .get("payload")
                    .and_then(|v| v.as_str())
                    .context("mqtt_publish result has no 'payload'")?;
                let qos = data.get("qos").and_then(|v| v.as_u64()).unwrap_or(0);
                let retain = data
                    .get("retain")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let properties = data.get("properties").filter(|p| !p.is_null());
                if properties.is_some() && !mqtt_client.is_v5() {
                    anyhow::bail!(
                        "PUBLISH properties need MQTT 5; this client connected with 3.1.1 \
                         (start it with protocol_version \"5.0\")"
                    );
                }
                mqtt_client
                    .publish(
                        topic,
                        qos as u8,
                        retain,
                        payload.as_bytes().to_vec(),
                        properties,
                    )
                    .await
                    .with_context(|| format!("publish to '{topic}' failed"))?;
                info!(
                    "MQTT client {} published to '{}': {}",
                    client_id, topic, payload
                );
                Ok(MqttApplied::Queued(format!(
                    "PUBLISH to '{}' ({} byte payload, QoS {}, retain {}) accepted by rumqttc",
                    topic,
                    payload.len(),
                    qos,
                    retain
                )))
            }
            "mqtt_unsubscribe" => {
                let topics = data
                    .get("topics")
                    .and_then(|v| v.as_array())
                    .context("mqtt_unsubscribe result has no 'topics' array")?;
                let mut removed: Vec<String> = Vec::new();
                for topic in topics {
                    if let Some(topic_str) = topic.as_str() {
                        mqtt_client
                            .unsubscribe(topic_str)
                            .await
                            .with_context(|| format!("unsubscribe from '{topic_str}' failed"))?;
                        info!(
                            "MQTT client {} unsubscribed from '{}'",
                            client_id, topic_str
                        );
                        removed.push(topic_str.to_string());
                    }
                }
                if removed.is_empty() {
                    return Ok(MqttApplied::NoWire(
                        "mqtt_unsubscribe: no valid topic strings".to_string(),
                    ));
                }
                Ok(MqttApplied::Queued(format!(
                    "UNSUBSCRIBE from [{}] accepted by rumqttc",
                    removed.join(", ")
                )))
            }
            other => Err(anyhow::anyhow!(
                "MQTT client cannot apply custom result '{}'",
                other
            )),
        },
        ClientActionResult::Disconnect => {
            info!("MQTT client {} disconnecting", client_id);
            // Set before the request goes out, so the poll error rumqttc raises for the
            // closed socket is already attributable when the event loop sees it.
            disconnecting.store(true, Ordering::SeqCst);
            mqtt_client
                .disconnect()
                .await
                .inspect_err(|_| disconnecting.store(false, Ordering::SeqCst))
                .context("disconnect request failed")?;
            Ok(MqttApplied::Disconnect)
        }
        ClientActionResult::WaitForMore => Ok(MqttApplied::NoWire(
            "waiting for the next broker message; nothing sent".to_string(),
        )),
        ClientActionResult::NoAction => {
            Ok(MqttApplied::NoWire("no_action: nothing sent".to_string()))
        }
        ClientActionResult::SendData(_) => {
            Err(anyhow::anyhow!("MQTT has no raw-byte channel; use publish"))
        }
        ClientActionResult::Multiple(_) => Err(anyhow::anyhow!(
            "MQTT client does not support Multiple action results"
        )),
    }
}

fn qos_from_u64(qos: u64) -> QoS {
    match qos {
        1 => QoS::AtLeastOnce,
        2 => QoS::ExactlyOnce,
        _ => QoS::AtMostOnce,
    }
}

/// Handle LLM action results
async fn handle_llm_actions(
    result: ClientLlmResult,
    mqtt_client: &Broker,
    app_state: &Arc<AppState>,
    client_id: ClientId,
    protocol: &Arc<MqttClientProtocol>,
    disconnecting: &Arc<AtomicBool>,
) {
    // Update memory
    if let Some(mem) = result.memory_updates {
        app_state.set_memory_for_client(client_id, mem).await;
    }

    // Execute actions
    for action in result.actions {
        match protocol.execute_action(action) {
            Ok(action_result) => {
                match apply_action(action_result, mqtt_client, client_id, disconnecting).await {
                    Ok(MqttApplied::Queued(detail)) => {
                        debug!("MQTT client {}: {}", client_id, detail);
                    }
                    Ok(MqttApplied::NoWire(detail)) => {
                        debug!("MQTT client {}: {}", client_id, detail);
                    }
                    Ok(MqttApplied::Disconnect) => {}
                    Err(e) => {
                        error!("MQTT client {} could not apply action: {}", client_id, e);
                    }
                }
            }
            Err(e) => {
                error!("Error executing MQTT action: {}", e);
            }
        }
    }
}

/// Drain injected commands (the dashboard's \[ send \]) until the channel closes - which
/// happens when the client is removed or the broker event loop exits - or until an injected
/// `disconnect` ends the session.
///
/// This is option (a) of the library-driven archetype: `rumqttc::AsyncClient` is a cheap
/// clonable handle to the event loop's request channel, so no `Arc<Mutex<_>>` and no
/// restructuring was needed - the command loop holds its own clone and applies actions
/// through the same [`apply_action`] the LLM path uses.
async fn command_loop(
    mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    mqtt_client: Broker,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    disconnecting: Arc<AtomicBool>,
) {
    use crate::llm::actions::protocol_trait::Protocol;
    use crate::state::client_handles::ClientSendOutcome;
    use crate::state::AccessLogOwner;

    let protocol = MqttClientProtocol::new();

    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(result) => match apply_action(result, &mqtt_client, client_id, &disconnecting).await
            {
                // Never `Sent`: rumqttc accepts the request into its event loop's queue and
                // returns; the bytes are written by that loop afterwards and it reports no
                // count, so claiming a byte count here would be a guess.
                Ok(MqttApplied::Queued(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                Ok(MqttApplied::NoWire(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                Ok(MqttApplied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                Err(e) => Err(e),
            },
        };

        let outcome_json = match &outcome {
            Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
            Err(e) => serde_json::json!({"error": e.to_string()}),
        };
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![outcome_json],
            )
            .await;

        let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
        if let Err(e) = &outcome {
            error!("MQTT client {} injected action failed: {}", client_id, e);
            let _ = status_tx.send(format!(
                "[WARN] Client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);

        if disconnect {
            // The event loop drops the handle on its way out too; doing it here as well means
            // the dashboard stops offering [ send ] the moment the DISCONNECT went out.
            app_state.remove_client_handle(client_id).await;
            break;
        }
    }
}
