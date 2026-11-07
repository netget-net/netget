//! Data Link layer (Layer 2) server implementation using pcap
//!
//! This module provides functionality to capture packets at the data link layer.
//! It uses libpcap to interact with network interfaces.
//!
//! # What the model is shown, and what it is not
//!
//! A captured frame is up to `snaplen` (65535) bytes. Handing all of that to the model as hex
//! would be 131070 characters of prompt per packet — so `packet_hex` carries the first
//! [`MAX_HEX_BYTES_TO_MODEL`] bytes and the event says, in `truncated` and `captured_length`,
//! that it did. `packet_length` is always the real length.
//!
//! # Backpressure
//!
//! Every captured frame used to `runtime.spawn` an LLM task unconditionally. libpcap delivers
//! frames as fast as the link does and an LLM turn takes seconds, so on any interface busier
//! than the model is fast the spawned tasks — each holding a copy of the frame and its hex —
//! accumulated without bound, all queued behind the same rate limiter. In-flight work is now
//! capped by a semaphore ([`MAX_INFLIGHT_LLM_PACKETS`]) and frames arriving over that are
//! dropped with a counted WARN. Dropping a frame is what a capture tool does under load;
//! growing the heap until the process dies is not.

pub mod actions;

use anyhow::{Context, Result};
use bytes::Bytes;
use pcap::{Capture, Device};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

use crate::client::datalink::packet::{decode_frame, LinkType};
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::utils::truncate_for_log;
use crate::{console_debug, console_error, console_info, console_trace, console_warn};
use actions::{DataLinkProtocol, DATALINK_PACKET_CAPTURED_EVENT};

/// How many bytes of a captured frame are hex-encoded into the event handed to the model.
///
/// 2 KiB covers every layer-2 header plus a useful slice of payload and costs at most 4096
/// prompt characters. The full length is always reported in `packet_length`.
pub const MAX_HEX_BYTES_TO_MODEL: usize = 2048;

/// How many bytes of frame hex reach the TRACE line / status stream.
///
/// The status channel is unbounded (see the repo CLAUDE.md), so a per-packet full hex dump is
/// exactly the high-frequency message that must not go on it.
const MAX_HEX_BYTES_TO_LOG: usize = 512;

/// Maximum number of captured frames being handled by the LLM at once. Frames arriving while
/// this many are outstanding are dropped rather than queued.
const MAX_INFLIGHT_LLM_PACKETS: usize = 32;

/// The event payload the model is given for one captured frame.
///
/// Pure, and public, so it can be asserted against literal frame bytes without a capture
/// handle — the only part of this protocol that can be tested at all without BPF access.
pub fn packet_event_data(frame: &[u8]) -> serde_json::Value {
    packet_event_data_for_link(frame, LinkType::Ethernet, false)
}

/// [`packet_event_data`] for the capture's real link type, with the frame decoded.
///
/// The interface's link type decides what the first bytes are: on macOS `lo0` (this server's
/// default interface) it is `NULL`, a 4-byte address family — reading MACs out of it would be
/// garbage. So `link_type` is always reported, the link header is read for that type
/// (`dst_mac` / `src_mac` / `ethertype`, or `family` on loopback), and IPv4 with TCP / UDP /
/// ICMP is decoded where present — TCP options included, with the loopback checksum-offload
/// note when a checksum is 0 (`crate::client::datalink::packet::decode_frame`).
pub fn packet_event_data_for_link(
    frame: &[u8],
    link: LinkType,
    loopback: bool,
) -> serde_json::Value {
    let shown = frame.len().min(MAX_HEX_BYTES_TO_MODEL);
    let mut data = decode_frame(&frame[..shown], link, loopback);
    data.insert("packet_length".into(), serde_json::json!(frame.len()));
    data.insert(
        "packet_hex".into(),
        serde_json::json!(hex::encode(&frame[..shown])),
    );
    data.insert("captured_length".into(), serde_json::json!(shown));
    data.insert("truncated".into(), serde_json::json!(shown < frame.len()));
    serde_json::Value::Object(data)
}

// `get_llm_protocol_prompt()` used to live here. It was called by nothing (`grep -rn
// get_llm_protocol_prompt src/ tests/`) and what it told the model was false in both halves:
// "You can capture and inject Ethernet frames … handle ARP requests/responses" of a
// capture-only protocol, and an output format —
// `{"output": "Ethernet frame data as hex (null if no response to inject)"}` — that is neither
// the shape the executor parses nor a capability this protocol has. The model's real prompt
// comes from the action definitions in `actions.rs`. Deleted rather than corrected: a second,
// unreferenced description of the protocol is a thing to drift, not a thing to maintain.

/// Data Link layer server that captures packets
pub struct DataLinkServer;

impl DataLinkServer {
    /// List available network interfaces
    pub fn list_devices() -> Result<Vec<Device>> {
        Device::list().context("Failed to list network devices")
    }

    /// Find a device by name
    pub fn find_device(name: &str) -> Result<Device> {
        let devices = Self::list_devices()?;
        devices
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow::anyhow!("Device '{}' not found", name))
    }

    /// Spawn datalink server with integrated LLM handling (async wrapper for blocking pcap)
    pub async fn spawn_with_llm(
        interface: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        filter: Option<String>,
        server_id: crate::state::ServerId,
    ) -> Result<String> {
        console_info!(
            status_tx,
            "Starting packet capture on interface: {}",
            interface
        );

        // Retained by this function; the capture task takes ownership of `status_tx`.
        let status_tx_ready = status_tx.clone();

        let protocol = Arc::new(DataLinkProtocol::new());

        // Datalink/pcap is blocking, so we run it in a blocking task.
        //
        // Opening the pcap handle needs privileges (root, or read access to /dev/bpf* on
        // macOS/BSD, or CAP_NET_RAW on Linux) and a valid BPF filter. Both are reported back
        // over a oneshot so `spawn_with_llm` can return Err and the server is marked Error,
        // rather than reporting Running while capturing nothing.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in `next_packet()`, so the
        // capture loop is stopped cooperatively: it polls this flag every iteration, and the
        // task registered with `register_server_task` below trips it when `stop_server` aborts
        // it. Without this the capture kept running (and kept calling the LLM) after the server
        // was stopped, until the process exited. See `crate::utils::shutdown`.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();
        // Retained by this function; the capture task takes ownership of `app_state`.
        let app_state_reg = app_state.clone();

        // Bounds the number of frames being handled by the LLM at once; see the module docs.
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_LLM_PACKETS));

        let interface_clone = interface.clone();
        let protocol_clone = protocol.clone();
        tokio::task::spawn_blocking(move || {
            let open_capture = || -> Result<(pcap::Capture<pcap::Active>, LinkType, bool)> {
                let device = Self::find_device(&interface_clone)
                    .with_context(|| format!("no such capture device '{}'", interface_clone))?;
                let loopback = device.flags.is_loopback();

                let mut cap = Capture::from_device(device)
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap capture on '{}' (needs root, or \
                             read access to /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)",
                            interface_clone
                        )
                    })?;

                // Apply filter if provided
                if let Some(ref filter_str) = filter {
                    cap.filter(filter_str, true)
                        .with_context(|| format!("invalid BPF filter '{}'", filter_str))?;
                }

                let link = LinkType::from_dlt(cap.get_datalink().0);
                Ok((cap, link, loopback))
            };

            let (mut cap, link_type, loopback) = match open_capture() {
                Ok(opened) => {
                    console_info!(
                        status_tx,
                        "DataLink capture on {} has link type {}{}",
                        interface_clone,
                        opened.1.name(),
                        if opened.2 { " (loopback)" } else { "" }
                    );
                    let _ = ready_tx.send(Ok(()));
                    opened
                }
                Err(e) => {
                    console_error!(status_tx, "DataLink capture startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            let runtime = tokio::runtime::Handle::current();
            let mut dropped: u64 = 0;

            // Capture loop. The pcap read timeout (1000ms, set above) is what bounds how long
            // a stop takes to be noticed on an idle interface.
            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(
                        status_tx,
                        "DataLink capture on {} stopping",
                        interface_clone
                    );
                    break;
                }
                match cap.next_packet() {
                    Ok(packet) => {
                        let data = Bytes::copy_from_slice(packet.data);

                        // DEBUG: Log summary
                        console_debug!(status_tx, "Datalink received {} bytes", data.len());

                        // TRACE: bounded hex preview. The status channel is unbounded, so the
                        // full dump of every frame must not go on it.
                        console_trace!(
                            status_tx,
                            "Datalink data (hex): {}",
                            truncate_for_log(
                                &hex::encode(&data),
                                MAX_HEX_BYTES_TO_LOG.saturating_mul(2)
                            )
                        );

                        // Backpressure: refuse to start another LLM turn when
                        // MAX_INFLIGHT_LLM_PACKETS are already outstanding.
                        let permit = match inflight.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                dropped += 1;
                                if dropped == 1 || dropped % 100 == 0 {
                                    console_warn!(
                                        status_tx,
                                        "DataLink dropped {} captured frame(s) on {}: \
                                         {} already awaiting the model. Narrow the BPF filter \
                                         or use a script/static handler for high-rate capture.",
                                        dropped,
                                        interface_clone,
                                        MAX_INFLIGHT_LLM_PACKETS
                                    );
                                }
                                continue;
                            }
                        };

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_task_clone = protocol_clone.clone();

                        // Spawn async task to handle packet with LLM
                        runtime.spawn(async move {
                            // Released when this turn ends, freeing a slot for the next frame.
                            let _permit = permit;

                            let full_len = data.len();
                            let event = Event::new(
                                &DATALINK_PACKET_CAPTURED_EVENT,
                                packet_event_data_for_link(&data, link_type, loopback),
                            );

                            Log::to(&status_clone).debug(format!(
                                "Datalink calling LLM for packet ({} bytes)",
                                full_len
                            ));

                            match call_llm(
                                &llm_clone,
                                &state_clone,
                                server_id,
                                None,
                                &event,
                                protocol_task_clone.as_ref(),
                            )
                            .await
                            {
                                Ok(execution_result) => {
                                    for message in &execution_result.messages {
                                        Log::to(&status_clone).info(message);
                                    }

                                    // DataLink writes nothing to the wire in any case, so the
                                    // three outcomes are indistinguishable on the interface and
                                    // must be told apart in the log. Grep `decision=`.
                                    let named_ignore =
                                        execution_result.raw_actions.iter().any(|a| {
                                            a.get("type").and_then(|v| v.as_str())
                                                == Some("ignore_packet")
                                        });
                                    let decision = if named_ignore {
                                        "model_ignore"
                                    } else if execution_result.raw_actions.is_empty() {
                                        "model_silent"
                                    } else {
                                        "model_analysed"
                                    };
                                    Log::to(&status_clone).debug(format!(
                                        "Datalink packet ({} bytes) decision={} ({} actions, \
                                         {} protocol results)",
                                        full_len,
                                        decision,
                                        execution_result.raw_actions.len(),
                                        execution_result.protocol_results.len()
                                    ));

                                    let _ = status_clone.send(format!(
                                        "→ Datalink packet processed: {} bytes",
                                        full_len
                                    ));
                                }
                                Err(e) => {
                                    // Nothing is written to the interface, because DataLink
                                    // has nothing it *could* write: it is capture-only and
                                    // declares no injection action. The failure is therefore
                                    // reported to the operator only, with the category kept
                                    // separate from the error text so a saturated backend
                                    // (retry worthwhile) is distinguishable from a broken one.
                                    let category = if crate::utils::WireFailure::classify(&e)
                                        .is_overloaded()
                                    {
                                        "overloaded"
                                    } else {
                                        "unavailable"
                                    };
                                    warn!(
                                        "Datalink packet ({} bytes) decision=fail_closed_llm_error \
                                         category={}: {}",
                                        full_len, category, e
                                    );
                                    let _ = status_clone.send(format!(
                                        "✗ Datalink packet decision=fail_closed_llm_error \
                                         category={}: {}",
                                        category, e
                                    ));
                                }
                            }
                        });
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal timeout, continue
                        continue;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Packet capture error: {}", e);
                        break;
                    }
                }
            }

            if dropped > 0 {
                console_warn!(
                    status_tx,
                    "DataLink capture on {} ended having dropped {} frame(s) to backpressure",
                    interface_clone,
                    dropped
                );
            }

            drop(cap);
        });

        // Wait for the blocking task to report whether the capture actually came up.
        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "DataLink capture task on '{}' exited before signalling readiness",
                    interface
                ))
            }
        }

        // Only now that the capture is genuinely live: `stop_server` aborts this parked task,
        // which trips `stop` and ends the blocking loop above.
        app_state_reg
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx_ready, "DataLink capture active on {}", interface);

        Ok(interface)
    }
}
