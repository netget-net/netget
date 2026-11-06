//! DataLink client implementation for raw frame injection, capture and IPv4/TCP probing
//!
//! # Lifecycle
//!
//! `connect_with_llm_actions` **awaits readiness**: the blocking pcap task reports over a
//! oneshot whether it found the device and opened a capture handle, and `connect` returns
//! `Err` when it did not. Without that the client reported `Connected` on a host with no BPF
//! access, having opened nothing — the family bug (`arp`, `datalink`, `icmp`, `isis` all had
//! it on the server side, where it is already fixed).
//!
//! # Link type
//!
//! The handle's link type (`pcap_datalink`) is read when it opens and decides how every
//! structured frame is built and every captured frame decoded — see [`packet`]. macOS `lo0`
//! is `DLT_NULL`, a 4-byte address family and no MACs; treating it as Ethernet put garbage on
//! the wire. It is reported to the model as `link_type` in `datalink_connected`.
//!
//! # Capture, filter, probe
//!
//! `capture` (default: the value of `promiscuous`) decides whether frames are read and handed
//! to the model; promiscuous mode is only the NIC setting. `filter` is a BPF expression applied
//! to the capture, defaulting from a `remote_addr` that is an address. `probe_tcp` does not
//! depend on either: each probe opens its own short-lived handle filtered to the reply flow
//! before its segment is injected, and the decoded replies come back as the result.
//!
//! # Shutdown
//!
//! `JoinHandle::abort()` cannot interrupt a thread parked in `pcap::next_packet()`, so the
//! blocking loop is stopped cooperatively through [`crate::utils::StopSignal`], registered
//! with `register_client_task` exactly as the server side does. `remove_client` aborts that
//! parked task, the guard trips the flag, and the loop exits at its next poll (≤10ms when not
//! capturing, ≤100ms while parked in `next_packet`). Before this the loop ran forever: it held
//! the capture handle after the client was gone, and — measurably — hung any process that
//! dropped its runtime while a capture was open. `injected_frame_is_transmitted` did not
//! fail, it hung the whole test binary in `BlockingPool::shutdown`.
//!
//! # Bounds
//!
//! * **The inject → report → inject chain.** A frame that goes out raises
//!   `datalink_frame_injected`, which asks the model, which may inject again. That is a real
//!   cycle with an LLM call per hop, so [`InjectionCommand::llm_depth`] caps it at
//!   [`MAX_INJECTION_FOLLOWUPS`] — the `MAX_FOLLOWUP_DEPTH` pattern the repo prescribes,
//!   carried through the queue rather than the stack. A model's `probe_tcp` is bounded the
//!   same way through `datalink_probe_completed`. A frame the operator injects from the
//!   dashboard always starts a fresh chain at depth 0.
//! * **Captured frames arriving while the model is busy.** They are counted and dropped.

pub mod actions;
pub mod packet;

pub use actions::DataLinkClientProtocol;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{error, info, trace, warn};

use crate::client::datalink::actions::{
    LinkSession, ProbeRequest, DATALINK_CLIENT_CONNECTED_EVENT,
    DATALINK_CLIENT_FRAME_CAPTURED_EVENT, DATALINK_CLIENT_FRAME_INJECTED_EVENT,
    DATALINK_CLIENT_PROBE_COMPLETED_EVENT,
};
use crate::client::datalink::packet::{
    decode_frame, echoed_options, parse_target, summarize, target_filter, BuildDefaults, LinkType,
    TcpFlow,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::utils::StopSignal;

/// Connection state for LLM processing
#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
}

/// Per-client capture bookkeeping: one LLM turn at a time, and a count of frames dropped
/// because a turn was already running.
struct ClientData {
    state: ConnectionState,
    /// Frames dropped because a turn was already running. Reported, not accumulated.
    dropped_while_busy: u64,
}

/// Channel message for one frame for the pcap thread to send.
///
/// libpcap is a blocking API and its handle lives on the blocking task, so nothing else can
/// call `sendpacket`. `ack` is how an injected command learns whether the frame really went
/// out: the pcap loop reports the result back, which is what lets the command loop answer
/// `Sent { bytes_sent }` truthfully instead of guessing.
struct InjectionCommand {
    frame: Vec<u8>,
    ack: Option<oneshot::Sender<std::result::Result<usize, String>>>,
    /// How many LLM turns deep into an inject → report → inject chain this frame is.
    ///
    /// 0 for anything the operator or the connected event started. The pcap loop only raises
    /// `datalink_frame_injected` while this is below [`MAX_INJECTION_FOLLOWUPS`].
    llm_depth: u8,
    /// Whether to raise `datalink_frame_injected` for it. A probe's segment is reported by
    /// the probe's own result instead.
    report: bool,
}

/// One `probe_tcp` for the probe worker: what to send, and where the result goes — back to
/// the operator's `send_to_client` (`reply`), or to the model as `datalink_probe_completed`.
struct ProbeJob {
    request: ProbeRequest,
    depth: u8,
    reply: Option<oneshot::Sender<Result<(usize, serde_json::Value)>>>,
}

/// How long an injected command waits for the pcap loop's acknowledgement.
const INJECTION_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum number of `inject → datalink_frame_injected → inject` hops in one chain.
const MAX_INJECTION_FOLLOWUPS: u8 = 4;

/// How many bytes of a captured or injected frame are hex-encoded into an event.
///
/// A frame can be 65535 bytes; all of it as hex is 131070 characters of prompt per event. The
/// true length is always in `frame_length`.
pub const MAX_HEX_BYTES_TO_MODEL: usize = 2048;

/// [`frame_event_fields_for_link`] for an Ethernet frame on a non-loopback interface.
pub fn frame_event_fields(frame: &[u8]) -> serde_json::Value {
    frame_event_fields_for_link(frame, LinkType::Ethernet, false)
}

/// The event payload the model is given for one frame: the link header read out as fields
/// for the interface's link type, the IPv4 / TCP / UDP / ICMP headers decoded where present,
/// the payload after the link header with an explicit `payload_encoding`, and the whole frame
/// as hex for exact replay — all of it cut at [`MAX_HEX_BYTES_TO_MODEL`] bytes, with the
/// fields that say so.
///
/// The link fields are spelled exactly as `inject_frame` accepts them, so answering a captured
/// frame is copying fields. `dst_mac` and `src_mac` are `null` on a link with no MACs (macOS
/// `lo0` is `NULL`: a 4-byte address family, reported as `family`) and for a runt shorter
/// than the link header.
///
/// Pure, and public, so it can be asserted against literal frame bytes with no capture handle.
pub fn frame_event_fields_for_link(
    frame: &[u8],
    link: LinkType,
    loopback: bool,
) -> serde_json::Value {
    let shown = frame.len().min(MAX_HEX_BYTES_TO_MODEL);
    let visible = &frame[..shown];

    let mut fields = decode_frame(visible, link, loopback);
    // Everything after the link header; nothing for a runt shorter than one, or for a link
    // whose header length is unknown (the frame is all in `frame_hex`).
    let payload: &[u8] = match link.header_len() {
        Some(h) if visible.len() >= h => &visible[h..],
        _ => &[],
    };

    // Printable ASCII reaches the model as itself; anything else is hex and `payload_encoding`
    // says which. Handing the pair straight back to `inject_frame` reproduces these bytes.
    let (payload_text, payload_encoding) = if payload
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(payload).to_string(), "utf8")
    } else {
        (hex::encode(payload), "hex")
    };

    fields.insert("frame_hex".into(), serde_json::json!(hex::encode(visible)));
    fields.insert("frame_length".into(), serde_json::json!(frame.len()));
    fields.insert("captured_length".into(), serde_json::json!(shown));
    fields.insert("truncated".into(), serde_json::json!(shown < frame.len()));
    fields.insert("payload".into(), serde_json::json!(payload_text));
    fields.insert(
        "payload_encoding".into(),
        serde_json::json!(payload_encoding),
    );
    serde_json::Value::Object(fields)
}

/// How a client's `remote_addr` and `filter` resolve into a capture filter.
///
/// `explicit` is the `filter` startup parameter: a non-empty string is used as given, `""`
/// means no filter at all. Without one, a `remote_addr` that is an address implies `host X
/// [and port Y]`. Returns `(filter, came_from_remote_addr)`.
pub fn resolve_capture_filter(remote_addr: &str, explicit: Option<&str>) -> (Option<String>, bool) {
    match explicit {
        Some(f) if f.trim().is_empty() => (None, false),
        Some(f) => (Some(f.trim().to_string()), false),
        None => match parse_target(remote_addr) {
            Some((ip, port)) => (Some(target_filter(ip, port)), true),
            None => (None, false),
        },
    }
}

/// Everything one open client's async paths share.
#[derive(Clone)]
struct Session {
    client_id: ClientId,
    interface: String,
    link: LinkSession,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    inject_tx: mpsc::UnboundedSender<InjectionCommand>,
    probe_tx: mpsc::UnboundedSender<ProbeJob>,
    stop: StopSignal,
}

impl Session {
    fn protocol(&self) -> DataLinkClientProtocol {
        DataLinkClientProtocol::with_session(self.link.clone())
    }
}

/// DataLink client that injects raw frames
pub struct DataLinkClient;

impl DataLinkClient {
    /// Open an interface for frame injection, capture and probing, with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        let params = startup_params.as_ref().ok_or_else(|| {
            anyhow::anyhow!("DataLink client requires startup parameters (interface)")
        })?;

        let interface = params.get_string("interface")?;
        let promiscuous = params.get_optional_bool("promiscuous")?.unwrap_or(false);
        // Capture used to be promiscuous mode itself, so a client that captured had to put the
        // NIC in promiscuous mode and one that wanted neither could not see a reply. Its
        // default stays tied to `promiscuous`, so every existing client behaves as it did.
        let capture = params.get_optional_bool("capture")?.unwrap_or(promiscuous);
        let explicit_filter = params.get_optional_string("filter")?;
        let (filter, filter_from_target) =
            resolve_capture_filter(&remote_addr, explicit_filter.as_deref());
        let target = parse_target(&remote_addr);
        let defaults = BuildDefaults {
            dst_ip: target.and_then(|(ip, _)| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }),
            dst_port: target.and_then(|(_, port)| port),
        };

        info!(
            "DataLink client {} opening interface: {} (promiscuous: {}, capture: {}, filter: {:?})",
            client_id, interface, promiscuous, capture, filter
        );

        let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<InjectionCommand>();
        let (probe_tx, probe_rx) = mpsc::unbounded_channel::<ProbeJob>();

        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            dropped_while_busy: 0,
        }));

        // Stops the blocking loop. Registered below, once the capture is genuinely open.
        let stop = StopSignal::new();

        // Whether the pcap handle really opened, and what it is. `connect` returns Err if it
        // did not, so a client on a host without BPF access lands in ClientStatus::Error.
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(LinkType, bool)>>();
        // The blocking loop needs the session to raise events; the session needs the link
        // type the loop reads. The loop gets it over this once it is built.
        let (session_tx, session_rx) = std::sync::mpsc::channel::<Session>();

        let interface_clone = interface.clone();
        let filter_clone = filter.clone();
        let status_tx_thread = status_tx.clone();
        let app_state_thread = app_state.clone();
        let client_data_clone = client_data.clone();
        let stop_in_loop = stop.clone();

        tokio::task::spawn_blocking(move || {
            let open_capture = || -> Result<(pcap::Capture<pcap::Active>, LinkType, bool)> {
                let device = Self::find_device(&interface_clone)
                    .with_context(|| format!("no such capture device '{}'", interface_clone))?;
                let loopback = device.flags.is_loopback();

                let mut cap = Capture::from_device(device)
                    .map(|c| {
                        c.promisc(promiscuous)
                            .snaplen(65535)
                            .timeout(100)
                            .immediate_mode(true)
                    })
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap capture on '{}' (needs root, or read access \
                             to /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)",
                            interface_clone
                        )
                    })?;
                let link = LinkType::from_dlt(cap.get_datalink().0);
                if capture {
                    if let Some(f) = &filter_clone {
                        cap.filter(f, true)
                            .with_context(|| format!("invalid BPF filter '{f}'"))?;
                    }
                }
                Ok((cap, link, loopback))
            };

            let mut cap = match open_capture() {
                Ok((cap, link, loopback)) => {
                    let _ = ready_tx.send(Ok((link, loopback)));
                    cap
                }
                Err(e) => {
                    error!(
                        "DataLink client {} capture startup failed: {:#}",
                        client_id, e
                    );
                    let _ = status_tx_thread.send(format!(
                        "[ERROR] DataLink client {} capture startup failed: {:#}",
                        client_id, e
                    ));
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let Ok(session) = session_rx.recv() else {
                return;
            };

            info!("DataLink client {} capture opened successfully", client_id);
            let _ = status_tx_thread.send(format!(
                "[INFO] DataLink client {} ready for frame injection",
                client_id
            ));

            let runtime = tokio::runtime::Handle::current();

            // Main loop: send queued frames and, with capture on, read frames. Exits when the
            // client is removed (which aborts the task holding `stop`) or the capture errors.
            loop {
                if stop_in_loop.is_stopped() {
                    break;
                }

                match inject_rx.try_recv() {
                    Ok(cmd) => {
                        let result = match cap.sendpacket(&cmd.frame[..]) {
                            Ok(_) => {
                                trace!(
                                    "DataLink client {} injected frame ({} bytes)",
                                    client_id,
                                    cmd.frame.len()
                                );
                                let _ = status_tx_thread.send(format!(
                                    "[TRACE] DataLink client {} injected frame ({} bytes)",
                                    client_id,
                                    cmd.frame.len()
                                ));

                                // Tell the model the frame went out. Spawned onto the runtime
                                // rather than awaited: this is the blocking pcap thread, and
                                // the LLM call can park for minutes on a manual routing rule.
                                // Bounded: past MAX_INJECTION_FOLLOWUPS hops the frame still
                                // goes out, the model is simply not asked again.
                                if !cmd.report {
                                } else if cmd.llm_depth < MAX_INJECTION_FOLLOWUPS {
                                    let s = session.clone();
                                    let frame = cmd.frame.clone();
                                    let depth = cmd.llm_depth;
                                    runtime.spawn(async move {
                                        Self::report_injection(s, frame, depth).await;
                                    });
                                } else {
                                    warn!(
                                        "DataLink client {} decision=followup_depth_capped: \
                                         {}-byte frame sent, model not asked again after {} \
                                         inject→report→inject hops",
                                        client_id,
                                        cmd.frame.len(),
                                        MAX_INJECTION_FOLLOWUPS
                                    );
                                    let _ = status_tx_thread.send(format!(
                                        "[WARN] DataLink client {} stopped an injection chain \
                                         at depth {}",
                                        client_id, MAX_INJECTION_FOLLOWUPS
                                    ));
                                }

                                Ok(cmd.frame.len())
                            }
                            Err(e) => {
                                error!(
                                    "DataLink client {} frame injection failed: {}",
                                    client_id, e
                                );
                                let _ = status_tx_thread.send(format!(
                                    "[ERROR] DataLink client {} frame injection failed: {}",
                                    client_id, e
                                ));
                                Err(e.to_string())
                            }
                        };
                        if let Some(ack) = cmd.ack {
                            let _ = ack.send(result);
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }

                if capture {
                    match cap.next_packet() {
                        Ok(packet) => {
                            let frame = packet.data.to_vec();
                            trace!(
                                "DataLink client {} captured frame ({} bytes)",
                                client_id,
                                frame.len()
                            );
                            let s = session.clone();
                            let data = client_data_clone.clone();
                            runtime.spawn(async move {
                                Self::handle_captured_frame(s, frame, data).await;
                            });
                        }
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(e) => {
                            error!("DataLink client {} capture error: {}", client_id, e);
                            let _ = status_tx_thread.send(format!(
                                "[ERROR] DataLink client {} capture error: {}",
                                client_id, e
                            ));
                            break;
                        }
                    }
                } else {
                    // Nothing blocks when not capturing, so bound the poll rate and the
                    // latency with which a stop is noticed.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }

            info!("DataLink client {} disconnected", client_id);
            runtime.block_on(async {
                let dropped = client_data_clone.lock().await.dropped_while_busy;
                if dropped > 0 {
                    warn!(
                        "DataLink client {} dropped {} captured frame(s) that arrived while a \
                         model turn was already running",
                        client_id, dropped
                    );
                }
                app_state_thread
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                // The pcap handle is gone: drop the command handle so the dashboard stops
                // offering [ send ] on a client that can no longer inject anything. This
                // also closes the command channel, which ends `command_loop`.
                app_state_thread.remove_client_handle(client_id).await;
                let _ = status_tx_thread.send(format!(
                    "[CLIENT] DataLink client {} disconnected",
                    client_id
                ));
                let _ = status_tx_thread.send("__UPDATE_UI__".to_string());
            });
        });

        // Wait for the blocking task to report whether the capture actually came up. Nothing
        // below this line runs for a client that has no capture handle.
        let (link_type, loopback) = match ready_rx.await {
            Ok(Ok(opened)) => opened,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "DataLink capture task on '{}' exited before signalling readiness",
                    interface
                ))
            }
        };

        let session = Session {
            client_id,
            interface: interface.clone(),
            link: LinkSession {
                link_type: Some(link_type),
                loopback,
                defaults,
            },
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            inject_tx,
            probe_tx,
            stop: stop.clone(),
        };
        let _ = session_tx.send(session.clone());

        let note = Self::connect_note(
            &interface,
            &remote_addr,
            link_type,
            loopback,
            capture,
            filter.as_deref(),
            filter_from_target,
            &defaults,
        );
        app_state
            .with_client_mut(client_id, |c| {
                c.set_protocol_field("connect_note".to_string(), serde_json::json!(note));
                c.set_protocol_field("link_type".to_string(), serde_json::json!(link_type.name()));
            })
            .await;

        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] DataLink client {} connected to interface {}: {}",
            client_id, interface, note
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Ends the blocking loop when the client is removed: `remove_client` aborts every
        // registered task, and dropping this one's future trips `stop`.
        app_state
            .register_client_task(client_id, stop.park_task())
            .await;

        // Probes run one at a time on their own task, so neither the command loop nor a model
        // turn holds anything while one listens for replies.
        let probe_task = tokio::spawn(Self::probe_worker(probe_rx, session.clone()));
        app_state.register_client_task(client_id, probe_task).await;

        // Command channel for injected actions (the dashboard's [ send ], MCP send_to_client).
        // Registered before the connected-event call below, which a `*` -> manual routing
        // rule can park for minutes — `[ send ]` must be live throughout that.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(command_rx, session.clone()));
        app_state.register_client_task(client_id, cmd_task).await;

        // Ask the model what to do now that the interface is open. Run from a registered task
        // rather than inline, because a dashboard-created client defaults to a `*` -> manual
        // rule and that call can park for minutes -- `connect` must return.
        let conn_session = session.clone();
        let conn_filter = filter.clone();
        let conn_task = tokio::spawn(async move {
            let s = conn_session;
            let Some(instruction) = s.app_state.get_instruction_for_client(s.client_id).await
            else {
                return;
            };
            let event = Event::new(
                &DATALINK_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "interface": s.interface,
                    "promiscuous": promiscuous,
                    "link_type": link_type.name(),
                    "capture": capture,
                    "filter": conn_filter,
                }),
            );
            Self::run_llm_turn(&s, &instruction, event, 0).await;
        });
        app_state.register_client_task(client_id, conn_task).await;

        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    /// What the operator is told the client opened, and what `remote_addr` was taken to mean.
    #[allow(clippy::too_many_arguments)]
    fn connect_note(
        interface: &str,
        remote_addr: &str,
        link_type: LinkType,
        loopback: bool,
        capture: bool,
        filter: Option<&str>,
        filter_from_target: bool,
        defaults: &BuildDefaults,
    ) -> String {
        let mut parts = vec![format!(
            "interface {interface}, link_type {}{}",
            link_type.name(),
            if loopback { " (loopback)" } else { "" }
        )];
        parts.push(match (capture, filter) {
            (false, _) => "capture off: frames are injected, not delivered to the model \
                           (probe_tcp still returns its replies)"
                .to_string(),
            (true, Some(f)) if filter_from_target => {
                format!("capturing through BPF filter \"{f}\", taken from remote_addr")
            }
            (true, Some(f)) => format!("capturing through BPF filter \"{f}\""),
            (true, None) => "capturing every frame on the interface (no filter)".to_string(),
        });
        match (defaults.dst_ip, defaults.dst_port) {
            (Some(ip), Some(port)) => {
                parts.push(format!("send_ipv4_tcp / probe_tcp default to {ip}:{port}"))
            }
            (Some(ip), None) => parts.push(format!("send_ipv4_tcp / probe_tcp default to {ip}")),
            (None, _) if parse_target(remote_addr).is_none() => parts.push(format!(
                "remote_addr \"{remote_addr}\" is not an address and is not used (the \
                 interface comes from startup_params.interface)"
            )),
            (None, _) => {}
        }
        parts.join("; ")
    }

    /// One captured frame: ask the model, unless a turn is already running for this client.
    async fn handle_captured_frame(
        s: Session,
        frame: Vec<u8>,
        client_data: Arc<Mutex<ClientData>>,
    ) {
        {
            let mut data = client_data.lock().await;
            if data.state != ConnectionState::Idle {
                data.dropped_while_busy += 1;
                let dropped = data.dropped_while_busy;
                drop(data);
                if dropped == 1 || dropped % 100 == 0 {
                    warn!(
                        "DataLink client {} dropped {} captured frame(s): a model turn was \
                         already running. Narrow the capture with 'filter', or use a \
                         script/static handler, for high-rate capture.",
                        s.client_id, dropped
                    );
                }
                return;
            }
            data.state = ConnectionState::Processing;
        }

        if let Some(instruction) = s.app_state.get_instruction_for_client(s.client_id).await {
            let event = Event::new(
                &DATALINK_CLIENT_FRAME_CAPTURED_EVENT,
                Self::event_fields(&s, &frame),
            );
            Self::run_llm_turn(&s, &instruction, event, 0).await;
        }

        client_data.lock().await.state = ConnectionState::Idle;
    }

    fn event_fields(s: &Session, frame: &[u8]) -> serde_json::Value {
        frame_event_fields_for_link(frame, s.link.link_type.unwrap_or_default(), s.link.loopback)
    }

    /// Report a frame that really went out, and queue whatever the model answers with.
    async fn report_injection(s: Session, frame: Vec<u8>, llm_depth: u8) {
        let Some(instruction) = s.app_state.get_instruction_for_client(s.client_id).await else {
            return;
        };
        let event = Event::new(
            &DATALINK_CLIENT_FRAME_INJECTED_EVENT,
            Self::event_fields(&s, &frame),
        );
        Self::run_llm_turn(&s, &instruction, event, llm_depth.saturating_add(1)).await;
    }

    /// One LLM turn: raise `event`, then queue any frames or probes the model asks for.
    ///
    /// Deliberately does NOT recurse. Injecting a frame raises `datalink_frame_injected`
    /// from the pcap loop, and a probe raises `datalink_probe_completed` from the probe
    /// worker; both come back here, so the chain continues through a queue rather than the
    /// stack. `depth` is what bounds it.
    async fn run_llm_turn(s: &Session, instruction: &str, event: Event, depth: u8) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};

        let client_id = s.client_id;
        let protocol = s.protocol();
        let memory = s
            .app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
        let event_id = event.event_type.id.clone();

        match call_llm_for_client(
            &s.llm_client,
            &s.app_state,
            client_id.to_string(),
            instruction,
            &memory,
            Some(&event),
            &protocol,
            &s.status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    s.app_state.set_memory_for_client(client_id, mem).await;
                }
                // Nothing goes on the wire in three of the four outcomes, and they are
                // indistinguishable there, so the log has to tell them apart. Grep `decision=`.
                let mut injected = 0usize;
                let mut rejected = 0usize;
                let action_count = actions.len();
                for action in actions {
                    match protocol.execute_action(action) {
                        Ok(ClientActionResult::SendData(frame)) => {
                            injected += 1;
                            let _ = s.inject_tx.send(InjectionCommand {
                                frame,
                                ack: None,
                                llm_depth: depth,
                                report: true,
                            });
                        }
                        Ok(ClientActionResult::Custom { name, data }) if name == "probe_tcp" => {
                            match serde_json::from_value::<ProbeRequest>(data) {
                                Ok(request) if depth < MAX_INJECTION_FOLLOWUPS => {
                                    injected += 1;
                                    let _ = s.probe_tx.send(ProbeJob {
                                        request,
                                        depth,
                                        reply: None,
                                    });
                                }
                                Ok(_) => warn!(
                                    "DataLink client {} decision=followup_depth_capped: \
                                     probe_tcp not run at depth {}",
                                    client_id, depth
                                ),
                                Err(e) => {
                                    rejected += 1;
                                    error!(
                                        "DataLink client {} bad probe request: {}",
                                        client_id, e
                                    );
                                }
                            }
                        }
                        Ok(ClientActionResult::Disconnect) => {
                            info!("DataLink client {} decision=model_disconnect", client_id);
                            Self::shut_down(s).await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            rejected += 1;
                            error!(
                                "DataLink client {} rejected action on {}: {}",
                                client_id, event_id, e
                            );
                        }
                    }
                }
                let decision = if injected > 0 {
                    "model_inject"
                } else if action_count == 0 {
                    "model_silent"
                } else if rejected == action_count {
                    "model_reject"
                } else {
                    "model_no_frame"
                };
                info!(
                    "DataLink client {} {} decision={} depth={} ({} action(s), {} injected)",
                    client_id, event_id, decision, depth, action_count, injected
                );
            }
            Err(e) => {
                // Nothing is written to the interface on failure. DataLink is one of the
                // deliberately silent protocols: a fabricated frame on a real network is
                // worse than no frame at all.
                let category = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                    "overloaded"
                } else {
                    "unavailable"
                };
                error!(
                    "DataLink client {} {} decision=fail_closed_llm_error category={}, nothing \
                     injected: {}",
                    client_id, event_id, category, e
                );
                let _ = s.status_tx.send(format!(
                    "[ERROR] DataLink client {} decision=fail_closed_llm_error category={}: {}",
                    client_id, category, e
                ));
            }
        }
    }

    /// Tear the client down: stop the pcap loop, drop the command handle, mark it
    /// disconnected. The blocking loop notices `stop` within one poll and does the rest.
    async fn shut_down(s: &Session) {
        s.stop.stop();
        s.app_state.remove_client_handle(s.client_id).await;
        s.app_state
            .update_client_status(s.client_id, ClientStatus::Disconnected)
            .await;
        let _ = s.status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Run probes one at a time: to the operator who asked, or to the model as
    /// `datalink_probe_completed`.
    async fn probe_worker(mut rx: mpsc::UnboundedReceiver<ProbeJob>, s: Session) {
        while let Some(job) = rx.recv().await {
            let result = Self::run_probe(&s, &job.request).await;
            match job.reply {
                Some(reply) => {
                    let _ = reply.send(result);
                }
                None => match result {
                    Ok((_, report)) => {
                        let Some(instruction) =
                            s.app_state.get_instruction_for_client(s.client_id).await
                        else {
                            continue;
                        };
                        let event = Event::new(&DATALINK_CLIENT_PROBE_COMPLETED_EVENT, report);
                        Self::run_llm_turn(&s, &instruction, event, job.depth.saturating_add(1))
                            .await;
                    }
                    Err(e) => error!("DataLink client {} probe_tcp failed: {:#}", s.client_id, e),
                },
            }
        }
    }

    /// Send one probe and collect the replies on its flow.
    ///
    /// A dedicated pcap handle, kernel-filtered to the reply flow, is opened **before** the
    /// segment is injected, so a reply cannot arrive unseen, and it does not depend on the
    /// client's `capture` or `filter`. Returns the bytes sent and the report.
    pub async fn run_probe_on(
        interface: &str,
        link_type: LinkType,
        loopback: bool,
        request: &ProbeRequest,
        send: impl std::future::Future<Output = Result<usize>>,
    ) -> Result<(usize, serde_json::Value)> {
        let flow = request.flow;
        let filter = flow.reply_filter();
        let timeout = std::time::Duration::from_millis(request.timeout_ms);
        let max_replies = request.max_replies;

        let (armed_tx, armed_rx) = oneshot::channel::<Result<()>>();
        let (sent_tx, sent_rx) = std::sync::mpsc::channel::<std::time::Instant>();
        let iface = interface.to_string();
        let filter_thread = filter.clone();
        let reader = tokio::task::spawn_blocking(move || -> Vec<(u64, Vec<u8>)> {
            let open = || -> Result<pcap::Capture<pcap::Active>> {
                let device = Self::find_device(&iface)?;
                let mut cap = Capture::from_device(device)?
                    .snaplen(65535)
                    .timeout(20)
                    .immediate_mode(true)
                    .open()
                    .with_context(|| format!("failed to open a probe capture on '{iface}'"))?;
                cap.filter(&filter_thread, true)
                    .with_context(|| format!("probe reply filter '{filter_thread}' refused"))?;
                Ok(cap)
            };
            let mut cap = match open() {
                Ok(c) => {
                    let _ = armed_tx.send(Ok(()));
                    c
                }
                Err(e) => {
                    let _ = armed_tx.send(Err(e));
                    return Vec::new();
                }
            };
            let armed_at = std::time::Instant::now();
            // Until the send is confirmed, wait at most the ack timeout plus the probe's own.
            let mut deadline = armed_at + INJECTION_ACK_TIMEOUT + timeout;
            let mut sent_at: Option<std::time::Instant> = None;
            let mut replies = Vec::new();
            loop {
                if let Ok(at) = sent_rx.try_recv() {
                    sent_at = Some(at);
                    deadline = at + timeout;
                }
                if std::time::Instant::now() >= deadline || replies.len() >= max_replies {
                    break;
                }
                match cap.next_packet() {
                    Ok(p) => {
                        let decoded = decode_frame(p.data, link_type, loopback);
                        if reply_matches(&decoded, &flow) {
                            let after =
                                sent_at.map(|t| t.elapsed().as_millis() as u64).unwrap_or(0);
                            replies.push((after, p.data.to_vec()));
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(_) => break,
                }
            }
            replies
        });

        armed_rx
            .await
            .map_err(|_| anyhow::anyhow!("probe capture task exited before it was ready"))??;
        let bytes_sent = match send.await {
            Ok(n) => {
                let _ = sent_tx.send(std::time::Instant::now());
                n
            }
            Err(e) => {
                // Unblock the reader at once rather than waiting out its guard deadline.
                let _ = sent_tx.send(std::time::Instant::now() - timeout);
                let _ = reader.await;
                return Err(e);
            }
        };
        let started = std::time::Instant::now();
        let frames = reader.await.context("probe capture task panicked")?;
        let waited_ms = started.elapsed().as_millis() as u64;

        let sent = decode_frame(&request.frame, link_type, loopback);
        let sent_options: Vec<serde_json::Value> = sent
            .get("tcp")
            .and_then(|t| t["options"].as_array().cloned())
            .unwrap_or_default();
        let mut summary = Vec::new();
        let replies: Vec<serde_json::Value> = frames
            .iter()
            .map(|(after_ms, frame)| {
                let mut fields = match frame_event_fields_for_link(frame, link_type, loopback) {
                    serde_json::Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                let mut line = summarize(&decode_frame(frame, link_type, loopback));
                if let Some(opts) = fields
                    .get("tcp")
                    .and_then(|t| t["options"].as_array().cloned())
                {
                    let (echoed, missing) = echoed_options(&sent_options, &opts);
                    if !sent_options.is_empty() {
                        line.push_str(&format!(
                            "; echoed: {}; not echoed: {}",
                            if echoed.is_empty() {
                                "none".to_string()
                            } else {
                                echoed.join(", ")
                            },
                            if missing.is_empty() {
                                "none".to_string()
                            } else {
                                missing.join(", ")
                            }
                        ));
                    }
                    fields.insert("options_echoed".into(), serde_json::json!(echoed));
                    fields.insert("options_not_echoed".into(), serde_json::json!(missing));
                }
                fields.insert("after_ms".into(), serde_json::json!(after_ms));
                summary.push(format!("+{after_ms}ms {line}"));
                serde_json::Value::Object(fields)
            })
            .collect();
        if replies.is_empty() {
            summary.push(format!(
                "no reply on {}:{} -> {}:{} within {} ms",
                flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, request.timeout_ms
            ));
        }

        let mut sent_view = serde_json::Map::new();
        for key in ["ip", "tcp"] {
            if let Some(v) = sent.get(key) {
                sent_view.insert(key.into(), v.clone());
            }
        }
        sent_view.insert("summary".into(), serde_json::json!(summarize(&sent)));

        Ok((
            bytes_sent,
            serde_json::json!({
                "flow": flow,
                "sent": sent_view,
                "reply_count": replies.len(),
                "replies": replies,
                "waited_ms": waited_ms,
                "summary": summary,
            }),
        ))
    }

    async fn run_probe(s: &Session, request: &ProbeRequest) -> Result<(usize, serde_json::Value)> {
        let inject_tx = s.inject_tx.clone();
        let frame = request.frame.clone();
        let send = async move {
            let (ack_tx, ack_rx) = oneshot::channel();
            inject_tx
                .send(InjectionCommand {
                    frame,
                    ack: Some(ack_tx),
                    llm_depth: 0,
                    report: false,
                })
                .map_err(|_| anyhow::anyhow!("the pcap capture is no longer open"))?;
            match tokio::time::timeout(INJECTION_ACK_TIMEOUT, ack_rx).await {
                Ok(Ok(Ok(n))) => Ok(n),
                Ok(Ok(Err(e))) => Err(anyhow::anyhow!("pcap sendpacket failed: {e}")),
                Ok(Err(_)) => Err(anyhow::anyhow!("the pcap loop exited before sending")),
                Err(_) => Err(anyhow::anyhow!(
                    "the pcap loop did not acknowledge the probe within {}s",
                    INJECTION_ACK_TIMEOUT.as_secs()
                )),
            }
        };
        Self::run_probe_on(
            &s.interface,
            s.link.link_type.unwrap_or_default(),
            s.link.loopback,
            request,
            send,
        )
        .await
    }

    /// Drain injected commands until the channel closes (client removed, or the pcap loop
    /// exited and dropped the handle) or an injected `disconnect` ends the session.
    async fn command_loop(mut command_rx: mpsc::Receiver<ClientCommand>, s: Session) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = s.protocol();
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = Self::execute_injected_action(&s, &protocol, &action).await;

            // The access log keeps the outcome without the whole probe report.
            let outcome_json = match &outcome {
                Ok(ClientSendOutcome::Probed { bytes_sent, report }) => serde_json::json!({
                    "Probed": {
                        "bytes_sent": bytes_sent,
                        "reply_count": report["reply_count"],
                        "summary": report["summary"],
                    }
                }),
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            s.app_state
                .record_access_log(
                    AccessLogOwner::Client(s.client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!(
                    "DataLink client {} injected action failed: {}",
                    s.client_id, e
                );
                let _ = s.status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    s.client_id, e
                ));
            }
            let _ = s.status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::shut_down(&s).await;
                break;
            }
        }
    }

    /// Execute one injected action and report exactly what happened to it.
    ///
    /// - `Sent { bytes_sent }` only after the pcap loop has acknowledged a successful
    ///   `sendpacket` for that many bytes.
    /// - `Probed { bytes_sent, report }` for `probe_tcp`: sent, and the decoded replies.
    /// - `Executed { detail }` when the frame could not be handed over — the pcap loop has
    ///   exited, which for a live client means it is on its way down.
    /// - `Rejected { error }` for an action the protocol refuses (unknown type, bad fields,
    ///   a frame the link cannot carry, a frame too short or too long).
    /// - `Err` when pcap accepted the frame and failed to transmit it.
    async fn execute_injected_action(
        s: &Session,
        protocol: &DataLinkClientProtocol,
        action: &serde_json::Value,
    ) -> Result<ClientSendOutcome> {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};

        let result = match protocol.execute_action(action.clone()) {
            Ok(result) => result,
            Err(e) => {
                return Ok(ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                })
            }
        };

        let frame = match result {
            ClientActionResult::SendData(frame) => frame,
            ClientActionResult::Disconnect => return Ok(ClientSendOutcome::Disconnected),
            ClientActionResult::WaitForMore => {
                return Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                })
            }
            ClientActionResult::Custom { name, data } if name == "probe_tcp" => {
                let request: ProbeRequest = serde_json::from_value(data)?;
                let wait = INJECTION_ACK_TIMEOUT
                    + std::time::Duration::from_millis(request.timeout_ms)
                    + std::time::Duration::from_secs(5);
                let (reply_tx, reply_rx) = oneshot::channel();
                s.probe_tx
                    .send(ProbeJob {
                        request,
                        depth: 0,
                        reply: Some(reply_tx),
                    })
                    .map_err(|_| anyhow::anyhow!("the probe worker is not running"))?;
                return match tokio::time::timeout(wait, reply_rx).await {
                    Ok(Ok(Ok((bytes_sent, report)))) => {
                        Ok(ClientSendOutcome::Probed { bytes_sent, report })
                    }
                    Ok(Ok(Err(e))) => Err(e),
                    Ok(Err(_)) => Ok(ClientSendOutcome::Executed {
                        detail: "probe dropped: the client is shutting down".to_string(),
                    }),
                    Err(_) => Ok(ClientSendOutcome::Executed {
                        detail: format!("probe did not finish within {}s", wait.as_secs()),
                    }),
                };
            }
            other => {
                return Ok(ClientSendOutcome::Executed {
                    detail: format!("{other:?} injects no frame"),
                })
            }
        };

        let frame_len = frame.len();
        let (ack_tx, ack_rx) = oneshot::channel();
        if s.inject_tx
            .send(InjectionCommand {
                frame,
                ack: Some(ack_tx),
                // The operator asking for a frame starts a fresh chain, however deep the
                // model's own chain went.
                llm_depth: 0,
                report: true,
            })
            .is_err()
        {
            return Ok(ClientSendOutcome::Executed {
                detail: format!(
                    "{frame_len}-byte frame built but not injected: the pcap capture is no \
                     longer open"
                ),
            });
        }

        match tokio::time::timeout(INJECTION_ACK_TIMEOUT, ack_rx).await {
            Ok(Ok(Ok(bytes_sent))) => Ok(ClientSendOutcome::Sent { bytes_sent }),
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!("pcap sendpacket failed: {e}")),
            Ok(Err(_)) => Ok(ClientSendOutcome::Executed {
                detail: format!(
                    "{frame_len}-byte frame not injected: it was handed to the pcap loop, \
                     which exited without reporting the result"
                ),
            }),
            Err(_) => Ok(ClientSendOutcome::Executed {
                detail: format!(
                    "{frame_len}-byte frame not confirmed injected: the pcap loop did not \
                     acknowledge it within {}s",
                    INJECTION_ACK_TIMEOUT.as_secs()
                ),
            }),
        }
    }

    /// Find a network device by name
    fn find_device(name: &str) -> Result<Device> {
        let devices = Device::list().context("Failed to list network devices")?;
        devices
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow::anyhow!("Network device '{}' not found", name))
    }
}

/// Whether a decoded frame answers `flow`: TCP from its destination back to its source, or an
/// ICMP error about it.
pub fn reply_matches(decoded: &serde_json::Map<String, serde_json::Value>, flow: &TcpFlow) -> bool {
    let Some(ip) = decoded.get("ip") else {
        return false;
    };
    let src = flow.src_ip.to_string();
    let dst = flow.dst_ip.to_string();
    if let Some(t) = decoded.get("tcp") {
        return ip["src"] == dst.as_str()
            && ip["dst"] == src.as_str()
            && t["src_port"] == flow.dst_port
            && t["dst_port"] == flow.src_port;
    }
    if let Some(c) = decoded.get("icmp") {
        let about = &c["about"];
        return ip["dst"] == src.as_str()
            && about["src"] == src.as_str()
            && about["dst"] == dst.as_str()
            && about["src_port"] == flow.src_port
            && about["dst_port"] == flow.dst_port;
    }
    false
}
