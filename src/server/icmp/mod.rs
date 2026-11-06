//! ICMP (Internet Control Message Protocol) server implementation
//!
//! This module provides functionality to capture and respond to ICMP messages at the network layer.
//! It uses raw IP sockets via socket2 and pnet for ICMP packet handling.

pub mod actions;

use anyhow::{Context, Result};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
// Note: pnet doesn't provide timestamp packet types
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::{console_error, console_info, console_trace};
use actions::{
    IcmpProtocol,
    ICMP_ECHO_REQUEST_EVENT,
    ICMP_OTHER_MESSAGE_EVENT,
    // ICMP_TIMESTAMP_REQUEST_EVENT, // TODO: Removed - timestamp support requires pnet timestamp packet types
};

/// ICMP server that captures and responds to ICMP messages
pub struct IcmpServer;

impl IcmpServer {
    /// Spawn ICMP server with integrated LLM handling
    pub async fn spawn_with_llm(
        interface: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<String> {
        console_info!(
            status_tx,
            "Starting ICMP capture on interface: {}",
            interface
        );

        // Retained by this function; the receive task takes ownership of `status_tx`.
        let status_tx_ready = status_tx.clone();

        let protocol = Arc::new(IcmpProtocol::new());

        // ICMP requires raw sockets, so we run it in a blocking task.
        //
        // Creating an AF_INET/SOCK_RAW/IPPROTO_ICMP socket needs root on macOS and the BSDs,
        // and root or CAP_NET_RAW on Linux. The outcome is reported back over a oneshot so
        // `spawn_with_llm` can return Err and the server is marked Error, rather than reporting
        // Running while never receiving a packet.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in a blocking receive, so the
        // receive loop is stopped cooperatively: it polls this flag every iteration, and the
        // task registered with `register_server_task` below trips it when `stop_server` aborts
        // it. Without this the raw socket kept receiving (and kept calling the LLM) after the
        // server was stopped, until the process exited. The socket is non-blocking and the loop
        // sleeps 10ms on `WouldBlock`, so a stop is noticed within ~10ms.
        // See `crate::utils::shutdown`.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();
        // Retained by this function; the receive task takes ownership of `app_state`.
        let app_state_reg = app_state.clone();

        let interface_clone = interface.clone();
        let protocol_clone = protocol.clone();
        tokio::task::spawn_blocking(move || {
            let open_sockets = || -> Result<(Socket, Arc<Socket>)> {
                // Create raw ICMP socket
                let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).context(
                    "failed to create raw ICMP receive socket \
                         (needs root, or CAP_NET_RAW on Linux)",
                )?;

                // Set socket to non-blocking for timeout handling
                socket
                    .set_nonblocking(true)
                    .context("failed to put the raw ICMP socket in non-blocking mode")?;

                // Create a separate socket for sending (to avoid conflicts)
                let send_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                    .context("failed to create raw ICMP send socket")?;

                // Every reply this server builds is a *complete* IPv4 packet: 20-byte header
                // written by `build_echo_reply` / `build_destination_unreachable` /
                // `build_time_exceeded`, then the ICMP message. Handing that to a
                // SOCK_RAW/IPPROTO_ICMP socket with IP_HDRINCL off makes the kernel prepend a
                // header of its own and treat our 20 bytes as the first 20 bytes of the ICMP
                // *message* - so the peer reads ICMP type 0x45 (69, unassigned) and the reply is
                // garbage. `IP_HDRINCL` is what says "the buffer starts at the IP header"; pnet's
                // own Layer3 transport channel sets exactly this option for exactly this reason
                // (pnet_transport 0.35, `transport_channel`).
                send_socket
                    .set_header_included_v4(true)
                    .context("failed to set IP_HDRINCL on the raw ICMP send socket")?;

                // The send socket is used from async tasks, so it must never park a Tokio
                // worker: a raw send only blocks when the socket buffer is full, which is
                // precisely the hostile case. Dropping a reply under that pressure (and logging
                // it) is the correct outcome for a datagram protocol.
                send_socket
                    .set_nonblocking(true)
                    .context("failed to put the raw ICMP send socket in non-blocking mode")?;

                Ok((socket, Arc::new(send_socket)))
            };

            let (socket, send_socket) = match open_sockets() {
                Ok(sockets) => {
                    let _ = ready_tx.send(Ok(()));
                    sockets
                }
                Err(e) => {
                    console_error!(status_tx, "ICMP raw socket startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            // TODO: Bind to specific interface if needed
            // For now, we receive on all interfaces

            console_info!(
                status_tx,
                "ICMP server listening for packets on {}",
                interface_clone
            );

            let runtime = tokio::runtime::Handle::current();

            // Receive loop
            let mut buffer = vec![std::mem::MaybeUninit::uninit(); 65535];
            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(
                        status_tx,
                        "ICMP receive loop on {} stopping",
                        interface_clone
                    );
                    break;
                }
                // Use recv_from with timeout
                match socket.recv_from(&mut buffer) {
                    Ok((n, _src_addr)) => {
                        let data = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, n).to_vec()
                        };

                        // DEBUG: Log raw received data
                        trace!(
                            "Raw socket received {} bytes: {}",
                            n,
                            hex::encode(&data[..std::cmp::min(n, 60)])
                        );

                        // Parse IP packet
                        let ip_packet = match Ipv4Packet::new(&data) {
                            Some(p) => p,
                            None => {
                                debug!("Failed to parse IPv4 packet");
                                continue;
                            }
                        };

                        // DEBUG: Log IP packet details
                        trace!(
                            "IP header length: {}, payload length: {}",
                            ip_packet.get_header_length() * 4,
                            ip_packet.payload().len()
                        );

                        // Check if it's ICMP
                        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                            continue;
                        }

                        // DEBUG: Log the payload we're about to parse as ICMP
                        let ip_payload = ip_packet.payload();
                        trace!("IP payload (ICMP data): {}", hex::encode(ip_payload));

                        // Tolerate a peer that wrote an IP header onto a socket without
                        // IP_HDRINCL: the kernel then prepends its own header and the peer's
                        // lands where the ICMP message should be, so we receive IP-in-IP. This
                        // used to be described here as "common on loopback"; it is nothing to do
                        // with loopback, it is that sender's bug (netget had it too - see the
                        // IP_HDRINCL note on the send socket above). ICMP type 0x45 does not
                        // exist, so the check cannot misfire on a well-formed message.
                        let icmp_data: Vec<u8>;
                        let icmp_payload = if ip_payload.len() >= 20 && ip_payload[0] == 0x45 {
                            if let Some(inner_ip) = Ipv4Packet::new(ip_payload) {
                                if inner_ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmp
                                {
                                    trace!("Detected IP-in-IP encapsulation on loopback, unwrapping inner packet");
                                    icmp_data = inner_ip.payload().to_vec();
                                    trace!(
                                        "Inner IP payload (actual ICMP): {}",
                                        hex::encode(&icmp_data)
                                    );
                                    icmp_data.as_slice()
                                } else {
                                    ip_payload
                                }
                            } else {
                                ip_payload
                            }
                        } else {
                            ip_payload
                        };

                        // Parse ICMP packet
                        let icmp_packet = match IcmpPacket::new(icmp_payload) {
                            Some(p) => p,
                            None => {
                                debug!("Failed to parse ICMP packet");
                                continue;
                            }
                        };

                        // Extract IP information
                        let source_ip = ip_packet.get_source();
                        let dest_ip = ip_packet.get_destination();
                        let ttl = ip_packet.get_ttl();
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();

                        // DEBUG: Log ICMP type extraction
                        trace!(
                            "ICMP type extracted: {} (raw: {}), code: {}",
                            icmp_type.0,
                            icmp_type.0,
                            icmp_code.0
                        );
                        // Never index a wire-supplied slice directly: this task is the whole
                        // server, so one out-of-range index would kill it silently.
                        trace!(
                            "First 4 bytes of icmp_payload: {}",
                            hex::encode(&icmp_payload[..std::cmp::min(icmp_payload.len(), 4)])
                        );

                        // DEBUG: Log summary
                        Log::to(&status_tx).debug(format!(
                            "ICMP {} from {} to {} (TTL: {})",
                            icmp_type_to_string(icmp_type),
                            source_ip,
                            dest_ip,
                            ttl
                        ));

                        // TRACE: Log full packet
                        let hex_str = hex::encode(ip_packet.payload());
                        console_trace!(status_tx, "ICMP packet (hex): {}", hex_str);

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_task_clone = protocol_clone.clone();
                        let send_socket_clone = send_socket.clone();
                        // Store the full ICMP packet (including header) for parsing by specific packet types
                        // Use the unwrapped payload in case of IP-in-IP encapsulation
                        let icmp_packet_data = icmp_payload.to_vec();

                        // Spawn async task to handle packet with LLM
                        runtime.spawn(async move {
                            // Build event based on ICMP type
                            let event = match icmp_type {
                                IcmpTypes::EchoRequest => {
                                    // Parse echo request
                                    if let Some(echo_req) =
                                        EchoRequestPacket::new(&icmp_packet_data)
                                    {
                                        let identifier = echo_req.get_identifier();
                                        let sequence = echo_req.get_sequence_number();
                                        let payload_hex = hex::encode(echo_req.payload());

                                        Event::new(
                                            &ICMP_ECHO_REQUEST_EVENT,
                                            serde_json::json!({
                                                "source_ip": source_ip.to_string(),
                                                "destination_ip": dest_ip.to_string(),
                                                // Numbers, not strings. The event type
                                                // declares both as `number` and
                                                // `execute_send_echo_reply` reads them with
                                                // `as_u64()`, so a stringified id made the
                                                // protocol's own scripted startup example
                                                // ("identifier": event["identifier"]) fail with
                                                // "Missing 'identifier' parameter".
                                                "identifier": identifier,
                                                "sequence": sequence,
                                                "payload_hex": payload_hex,
                                                "ttl": ttl,
                                            }),
                                        )
                                    } else {
                                        debug!("Failed to parse ICMP echo request");
                                        return;
                                    }
                                }
                                /* TODO: Timestamp support requires pnet to add timestamp packet types
                                IcmpTypes::Timestamp => {
                                    // Parse timestamp request
                                    if let Some(ts_req) = TimestampPacket::new(&icmp_payload) {
                                        let identifier = ts_req.get_identifier();
                                        let sequence = ts_req.get_sequence_number();
                                        let originate_timestamp = ts_req.get_originate_timestamp();

                                        Event::new(
                                            &ICMP_TIMESTAMP_REQUEST_EVENT,
                                            serde_json::json!({
                                                "source_ip": source_ip.to_string(),
                                                "destination_ip": dest_ip.to_string(),
                                                "identifier": identifier,
                                                "sequence": sequence,
                                                "originate_timestamp": originate_timestamp,
                                            }),
                                        )
                                    } else {
                                        debug!("Failed to parse ICMP timestamp request");
                                        return;
                                    }
                                }
                                */
                                _ => {
                                    // Other ICMP types
                                    Event::new(
                                        &ICMP_OTHER_MESSAGE_EVENT,
                                        serde_json::json!({
                                            "source_ip": source_ip.to_string(),
                                            "destination_ip": dest_ip.to_string(),
                                            "icmp_type": icmp_type.0,
                                            "icmp_code": icmp_code.0,
                                            "packet_hex": hex::encode(&icmp_packet_data),
                                        }),
                                    )
                                }
                            };

                            Log::to(&status_clone).debug(format!(
                                "ICMP calling LLM for {} packet", icmp_type_to_string(icmp_type)
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

                                    Log::to(&status_clone).debug(format!(
                                        "ICMP got {} protocol results",
                                        execution_result.protocol_results.len()
                                    ));

                                    // An explicit `ignore_icmp` and an empty answer both put
                                    // nothing on the wire, but only one of them is a decision.
                                    // Keep them apart in the log so an operator can tell a
                                    // deliberate silent honeypot from a model that said nothing.
                                    let answered_nothing = execution_result.raw_actions.is_empty();
                                    let explicit_ignore = !answered_nothing
                                        && execution_result.raw_actions.iter().all(|a| {
                                            a.get("type").and_then(|v| v.as_str())
                                                == Some("ignore_icmp")
                                        });
                                    let action_failures = execution_result.failures.len();
                                    let mut packets_sent = 0usize;

                                    // Send ICMP replies if any
                                    for protocol_result in execution_result.protocol_results {
                                        // Every output, not just the first: an answer of two
                                        // echo replies used to put one packet on the wire and
                                        // drop the other without a word.
                                        for mut output_data in protocol_result.get_all_output() {
                                            // Send packet via raw socket
                                            // Extract destination from the IP header in output_data
                                            let dest_ip_of_reply = Ipv4Packet::new(&output_data)
                                                .map(|ip_pkt| ip_pkt.get_destination());
                                            let Some(reply_dest) = dest_ip_of_reply else {
                                                error!("Failed to parse IP packet from LLM output");
                                                continue;
                                            };
                                            let dest_addr =
                                                std::net::SocketAddr::from((reply_dest, 0));

                                            // Last thing before the syscall: on Darwin/FreeBSD
                                            // the two fields below must reach the kernel in
                                            // host byte order. After this the buffer is no
                                            // longer a well-formed RFC 791 header, so nothing
                                            // may parse it again.
                                            prepare_ipv4_for_raw_send(&mut output_data);

                                            match send_socket_clone
                                                .send_to(&output_data, &dest_addr.into())
                                            {
                                                Ok(_) => {
                                                    packets_sent += 1;
                                                    Log::to(&status_clone).debug(format!(
                                                        "ICMP sent {} bytes to {}",
                                                        output_data.len(),
                                                        dest_addr.ip()
                                                    ));

                                                    Log::to(&status_clone).trace(format!(
                                                        "ICMP reply (hex): {}",
                                                        hex::encode(&output_data)
                                                    ));
                                                }
                                                Err(e) => {
                                                    Log::to(&status_clone).error(format!(
                                                        "Failed to send ICMP reply: {}", e
                                                    ));
                                                }
                                            }
                                        }
                                    }

                                    // The token is stable so an operator can grep
                                    // `decision=fail_closed_` and find every packet that went
                                    // unanswered because no usable answer was produced, as
                                    // distinct from one the model chose to ignore.
                                    let decision = if packets_sent > 0 {
                                        "model_reply"
                                    } else if explicit_ignore {
                                        "model_ignore"
                                    } else if answered_nothing {
                                        "fail_closed_no_action"
                                    } else if action_failures > 0 {
                                        "fail_closed_action_error"
                                    } else {
                                        "fail_closed_no_reply"
                                    };
                                    let summary = format!(
                                        "ICMP {} {} -> {} decision={} sent={}",
                                        icmp_type_to_string(icmp_type),
                                        source_ip,
                                        dest_ip,
                                        decision,
                                        packets_sent
                                    );
                                    if decision.starts_with("fail_closed_") {
                                        error!("{} (nothing put on the wire)", summary);
                                        let _ = status_clone
                                            .send(format!("✗ {} (nothing put on the wire)", summary));
                                    } else {
                                        info!("{}", summary);
                                        let _ = status_clone.send(format!("→ {}", summary));
                                    }
                                }
                                Err(e) => {
                                    // ICMP has no in-band way to say "I cannot answer": RFC 792
                                    // defines no failure reply for an echo request, and RFC 1122
                                    // §3.2.2 forbids generating an ICMP error in response to an
                                    // ICMP error — a synthesised Destination Unreachable would be
                                    // a lie about reachability, not a service-unavailable signal.
                                    // Silence is therefore the protocol-correct outcome here; what
                                    // matters is that it is loud in the log and distinguishable
                                    // from an `ignore_icmp` decision. The error text is logged,
                                    // never derived into anything a peer could read.
                                    let category = if crate::utils::WireFailure::classify(&e)
                                        .is_overloaded()
                                    {
                                        "overloaded"
                                    } else {
                                        "unavailable"
                                    };
                                    error!(
                                        "ICMP {} {} -> {} decision=fail_closed_llm_error category={} (no reply: ICMP has no failure message): {}",
                                        icmp_type_to_string(icmp_type),
                                        source_ip,
                                        dest_ip,
                                        category,
                                        e
                                    );
                                    let _ = status_clone.send(format!(
                                        "✗ ICMP {} {} -> {} decision=fail_closed_llm_error category={}: {}",
                                        icmp_type_to_string(icmp_type),
                                        source_ip,
                                        dest_ip,
                                        category,
                                        e
                                    ));
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, sleep briefly
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => {
                        console_error!(status_tx, "ICMP receive error: {}", e);
                        break;
                    }
                }
            }

            // Close both raw sockets. `send_socket` is an `Arc` shared with in-flight reply
            // tasks, so it closes once the last of them finishes.
            drop(socket);
            drop(send_socket);
        });

        // Wait for the blocking task to report whether the raw sockets actually opened.
        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "ICMP receive task for '{}' exited before signalling readiness",
                    interface
                ))
            }
        }

        // Only now that the sockets are genuinely open: `stop_server` aborts this parked task,
        // which trips `stop` and ends the blocking loop above.
        app_state_reg
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx_ready, "ICMP raw sockets active on {}", interface);

        Ok(interface)
    }

    /// Helper function to build an ICMP echo reply packet with IP header
    pub fn build_echo_reply(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
        use pnet::packet::icmp::IcmpTypes;
        use pnet::packet::ipv4::checksum;

        // ICMP echo reply: 8 bytes header + payload
        let icmp_size = 8 + payload.len();
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut echo_reply = MutableEchoReplyPacket::new(&mut icmp_buffer).unwrap();
            echo_reply.set_icmp_type(IcmpTypes::EchoReply);
            echo_reply.set_icmp_code(IcmpCode::new(0));
            echo_reply.set_identifier(identifier);
            echo_reply.set_sequence_number(sequence);
            echo_reply.set_payload(payload);
        }

        // Calculate ICMP checksum
        let icmp_checksum = {
            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            pnet::packet::icmp::checksum(&icmp_packet.to_immutable())
        };

        {
            let mut echo_reply = MutableEchoReplyPacket::new(&mut icmp_buffer).unwrap();
            echo_reply.set_checksum(icmp_checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_identification(0);
            ip_packet.set_flags(0);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            // Calculate IP checksum
            let ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);
        }

        ip_buffer
    }

    /// Helper function to build an ICMP destination unreachable packet
    pub fn build_destination_unreachable(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        code: u8,
        original_packet: &[u8],
    ) -> Vec<u8> {
        use pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
        use pnet::packet::icmp::IcmpTypes;
        use pnet::packet::ipv4::checksum;

        // Take first 28 bytes of original packet (IP header + 8 bytes of data)
        let payload_len = std::cmp::min(original_packet.len(), 28);
        let payload = &original_packet[..payload_len];

        // ICMP destination unreachable: 8 bytes header + original packet fragment
        let icmp_size = 8 + payload.len();
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut dest_unreach =
                MutableDestinationUnreachablePacket::new(&mut icmp_buffer).unwrap();
            dest_unreach.set_icmp_type(IcmpTypes::DestinationUnreachable);
            dest_unreach.set_icmp_code(IcmpCode::new(code));
            dest_unreach.set_payload(payload);
        }

        // Calculate ICMP checksum
        let icmp_checksum = {
            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            pnet::packet::icmp::checksum(&icmp_packet.to_immutable())
        };

        {
            let mut dest_unreach =
                MutableDestinationUnreachablePacket::new(&mut icmp_buffer).unwrap();
            dest_unreach.set_checksum(icmp_checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            let ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);
        }

        ip_buffer
    }

    /// Helper function to build an ICMP time exceeded packet
    pub fn build_time_exceeded(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        code: u8,
        original_packet: &[u8],
    ) -> Vec<u8> {
        use pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket;
        use pnet::packet::icmp::IcmpTypes;
        use pnet::packet::ipv4::checksum;

        // Take first 28 bytes of original packet
        let payload_len = std::cmp::min(original_packet.len(), 28);
        let payload = &original_packet[..payload_len];

        let icmp_size = 8 + payload.len();
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut time_exceeded = MutableTimeExceededPacket::new(&mut icmp_buffer).unwrap();
            time_exceeded.set_icmp_type(IcmpTypes::TimeExceeded);
            time_exceeded.set_icmp_code(IcmpCode::new(code));
            time_exceeded.set_payload(payload);
        }

        // Calculate ICMP checksum
        let icmp_checksum = {
            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            pnet::packet::icmp::checksum(&icmp_packet.to_immutable())
        };

        {
            let mut time_exceeded = MutableTimeExceededPacket::new(&mut icmp_buffer).unwrap();
            time_exceeded.set_checksum(icmp_checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            let ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);
        }

        ip_buffer
    }

    /* TODO: Timestamp support requires pnet to add timestamp_reply packet types
    /// Helper function to build an ICMP timestamp reply packet
    pub fn build_timestamp_reply(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        originate_timestamp: u32,
    ) -> Vec<u8> {
        use pnet::packet::icmp::timestamp_reply::MutableTimestampReplyPacket;
        use pnet::packet::icmp::IcmpTypes;
        use pnet::packet::ipv4::checksum;

        // Get current time in milliseconds since midnight UT
        let now = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32;
        let receive_timestamp = now;
        let transmit_timestamp = now;

        let icmp_size = 20; // Timestamp reply is always 20 bytes
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut ts_reply = MutableTimestampReplyPacket::new(&mut icmp_buffer).unwrap();
            ts_reply.set_icmp_type(IcmpTypes::TimestampReply);
            ts_reply.set_icmp_code(IcmpCode::new(0));
            ts_reply.set_identifier(identifier);
            ts_reply.set_sequence_number(sequence);
            ts_reply.set_originate_timestamp(originate_timestamp);
            ts_reply.set_receive_timestamp(receive_timestamp);
            ts_reply.set_transmit_timestamp(transmit_timestamp);

            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
            ts_reply.set_checksum(checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            let checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        ip_buffer
    }
    */
}

/// Put a finished IPv4 packet into the form the local kernel expects on an `IP_HDRINCL`
/// raw socket, immediately before `send_to`.
///
/// On Linux every field goes out in network byte order, so this is a no-op. On Darwin and
/// FreeBSD the raw-IP output path reads `ip_len` and `ip_off` in **host** byte order — XNU's
/// `rip_output` sanity-checks `ip->ip_len > m->m_pkthdr.len` against the real buffer length, so
/// a network-order length on a 28-byte packet reads as 7168 and the send fails outright with
/// `EINVAL`. `pnet_transport` 0.35 does the same conversion for its Layer3 channel (see
/// `send_to_impl`, `man 4 ip` "Raw IP Sockets"); this is that conversion, without taking on the
/// whole transport channel.
///
/// The header checksum is zeroed rather than recomputed: it was calculated over the
/// network-order fields and cannot be valid once two of them are byte-swapped, and every raw-IP
/// implementation either always fills the checksum in (`man 7 raw` on Linux lists "IP Checksum:
/// always filled in") or fills it when zero. Leaving a stale value is wrong in every case where
/// zeroing is, and wrong in one case where zeroing is not.
///
/// **Not verified against a running kernel.** Nothing in this repo has ever sent on a raw
/// socket; this is derived from the kernel sources and from pnet's long-standing workaround, and
/// `tests/server/icmp/packet_codec_test.rs` asserts only that the bytes come out as intended for
/// the platform being compiled for.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
))]
pub fn prepare_ipv4_for_raw_send(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    // `to_ne_bytes` is a no-op on a big-endian host, which is what "host byte order" means
    // there; only little-endian needs the swap.
    let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    packet[2..4].copy_from_slice(&total_length.to_ne_bytes());
    let flags_and_fragment_offset = u16::from_be_bytes([packet[6], packet[7]]);
    packet[6..8].copy_from_slice(&flags_and_fragment_offset.to_ne_bytes());
    packet[10] = 0;
    packet[11] = 0;
}

/// Linux and everything else: the header already is what the kernel wants.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
)))]
pub fn prepare_ipv4_for_raw_send(_packet: &mut [u8]) {}

/// Convert ICMP type to human-readable string
fn icmp_type_to_string(icmp_type: pnet::packet::icmp::IcmpType) -> &'static str {
    match icmp_type {
        IcmpTypes::EchoReply => "ECHO_REPLY",
        IcmpTypes::EchoRequest => "ECHO_REQUEST",
        IcmpTypes::DestinationUnreachable => "DEST_UNREACHABLE",
        IcmpTypes::SourceQuench => "SOURCE_QUENCH",
        IcmpTypes::RedirectMessage => "REDIRECT",
        IcmpTypes::TimeExceeded => "TIME_EXCEEDED",
        IcmpTypes::ParameterProblem => "PARAMETER_PROBLEM",
        IcmpTypes::Timestamp => "TIMESTAMP",
        IcmpTypes::TimestampReply => "TIMESTAMP_REPLY",
        IcmpTypes::InformationRequest => "INFO_REQUEST",
        IcmpTypes::InformationReply => "INFO_REPLY",
        IcmpTypes::AddressMaskRequest => "ADDRMASK_REQUEST",
        IcmpTypes::AddressMaskReply => "ADDRMASK_REPLY",
        IcmpTypes::Traceroute => "TRACEROUTE",
        _ => "UNKNOWN",
    }
}
