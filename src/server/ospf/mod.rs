//! OSPF protocol simulator - LLM-controlled OSPF responses
//!
//! This is an OSPF protocol simulator that speaks real OSPF (IP protocol 89)
//! but has LLM-generated responses instead of real routing logic.
//!
//! **Use cases**: Testing, honeypots, route injection, OSPF reconnaissance
//! **Requires**: Root/CAP_NET_RAW privileges for raw socket access

pub mod actions;

use crate::utils::clock::Instant;
use anyhow::{anyhow, Result};
use hex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

#[cfg(unix)]
use crate::llm::action_helper::call_llm;
#[cfg(unix)]
use crate::llm::ollama_client::OllamaClient;
#[cfg(unix)]
use crate::logging::emit::Log;
#[cfg(unix)]
use crate::protocol::Event;
#[cfg(unix)]
use crate::server::connection::ConnectionId;
#[cfg(unix)]
use crate::server::socket_helpers::create_ospf_raw_socket;
#[cfg(unix)]
use crate::state::app_state::AppState;
#[cfg(unix)]
use crate::state::server::OspfNeighborState;
#[cfg(unix)]
use actions::{
    OspfInterfaceConfig, OspfProtocol, OSPF_DATABASE_DESCRIPTION_EVENT, OSPF_HELLO_EVENT,
    OSPF_LINK_STATE_ACK_EVENT, OSPF_LINK_STATE_REQUEST_EVENT, OSPF_LINK_STATE_UPDATE_EVENT,
};

// OSPF Constants
const OSPF_VERSION: u8 = 2;
const OSPF_HEADER_LEN: usize = 24;
const IP_HEADER_MIN_LEN: usize = 20;

// OSPF Packet Types
const OSPF_TYPE_HELLO: u8 = 1;
const OSPF_TYPE_DATABASE_DESCRIPTION: u8 = 2;
const OSPF_TYPE_LINK_STATE_REQUEST: u8 = 3;
const OSPF_TYPE_LINK_STATE_UPDATE: u8 = 4;
const OSPF_TYPE_LINK_STATE_ACK: u8 = 5;

// OSPF Multicast addresses
const OSPF_ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
#[allow(dead_code)]
const OSPF_ALL_DROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

/// OSPF neighbor information
#[cfg(unix)]
struct OspfNeighbor {
    #[allow(dead_code)]
    router_id: String,
    #[allow(dead_code)]
    neighbor_ip: Ipv4Addr,
    connection_id: ConnectionId,
    state: OspfNeighborState,
    priority: u8,
    dr: String,
    bdr: String,
    last_hello: Instant,
}

/// Shared OSPF server state
#[cfg(unix)]
struct OspfState {
    socket_fd: i32,
    /// This interface's address: the local end of every neighbour connection published
    /// to AppState.
    interface_ip: Ipv4Addr,
    /// Interface configuration from the startup parameters. Supplies the defaults for
    /// every outgoing packet and the RFC 2328 10.5 acceptance check for incoming Hellos.
    config: OspfInterfaceConfig,
    neighbors: Arc<Mutex<HashMap<String, OspfNeighbor>>>,
}

/// OSPF server
pub struct OspfServer;

#[cfg(unix)]
impl OspfServer {
    /// Spawn OSPF server with LLM control
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract interface IP
        let interface_ip = match listen_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(anyhow!("OSPF only supports IPv4")),
        };

        // Create raw OSPF socket
        let raw_socket = create_ospf_raw_socket(interface_ip, true, false)?;
        let socket_fd = raw_socket.as_raw_fd();

        Log::new(Some(&status_tx)).info(format!("OSPF server on {} (requires root)", interface_ip));

        // Extract interface configuration. Every declared startup parameter is read here
        // and lands in OspfInterfaceConfig, which is consulted on both directions; four of
        // the six used to be advertised to the model and read nowhere at all.
        let mut config = OspfInterfaceConfig {
            router_id: interface_ip.to_string(),
            ..OspfInterfaceConfig::default()
        };

        if let Some(ref params) = startup_params {
            if let Some(v) = params.get_optional_string("router_id")? {
                config.router_id = v;
            }
            if let Some(v) = params.get_optional_string("area_id")? {
                config.area_id = v;
            }
            if let Some(v) = params.get_optional_string("network_mask")? {
                config.network_mask = v;
            }
            if let Some(v) = params.get_optional_i64("hello_interval")? {
                config.hello_interval = u16::try_from(v).map_err(|_| {
                    anyhow!("hello_interval must be between 0 and 65535 seconds, got {v}")
                })?;
            }
            if let Some(v) = params.get_optional_i64("router_dead_interval")? {
                config.router_dead_interval = u32::try_from(v).map_err(|_| {
                    anyhow!(
                        "router_dead_interval must be between 0 and 4294967295 seconds, got {v}"
                    )
                })?;
            }
            if let Some(v) = params.get_optional_i64("router_priority")? {
                config.router_priority = u8::try_from(v)
                    .map_err(|_| anyhow!("router_priority must be between 0 and 255, got {v}"))?;
            }
        }

        // The three dotted-quad parameters are declared "IPv4 format" and were accepted as
        // any string at all. A typo did not fail here: it reached parse_ipv4 at send time,
        // which silently substituted 0.0.0.0, so the server ran happily and advertised a
        // Router ID nobody configured. Fail at startup, where the operator is looking.
        for (name, value) in [
            ("router_id", &config.router_id),
            ("area_id", &config.area_id),
            ("network_mask", &config.network_mask),
        ] {
            if value.parse::<Ipv4Addr>().is_err() {
                return Err(anyhow!(
                    "OSPF startup parameter '{name}' must be in IPv4 dotted-quad form \
                     (e.g. 1.1.1.1), got '{value}'"
                ));
            }
        }

        Log::new(Some(&status_tx)).info(format!(
            "OSPF: router_id={}, area={}, mask={}, hello={}s, dead={}s, priority={}",
            config.router_id,
            config.area_id,
            config.network_mask,
            config.hello_interval,
            config.router_dead_interval,
            config.router_priority
        ));

        let protocol = Arc::new(OspfProtocol::new());
        let neighbors: Arc<Mutex<HashMap<String, OspfNeighbor>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let ospf_state = Arc::new(OspfState {
            socket_fd,
            interface_ip,
            config,
            neighbors: neighbors.clone(),
        });

        // Wrap socket for async I/O
        let async_socket = AsyncFd::new(raw_socket)?;

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];

            loop {
                let mut guard = match async_socket.readable().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        error!("OSPF socket error: {}", e);
                        break;
                    }
                };

                match guard.try_io(|inner| {
                    let fd = inner.as_raw_fd();
                    unsafe {
                        let n = libc::recv(
                            fd,
                            buffer.as_mut_ptr() as *mut libc::c_void,
                            buffer.len(),
                            0,
                        );

                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    }
                }) {
                    Ok(Ok(n)) => {
                        if n == 0 {
                            continue;
                        }

                        // Skip IP header
                        if n < IP_HEADER_MIN_LEN {
                            continue;
                        }

                        let ip_header_len = ((buffer[0] & 0x0F) * 4) as usize;
                        if n < ip_header_len + OSPF_HEADER_LEN {
                            continue;
                        }

                        // Extract source IP from IP header
                        let src_ip = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);

                        // Extract OSPF packet
                        let ospf_data = &buffer[ip_header_len..n];
                        let version = ospf_data[0];
                        let packet_type = ospf_data[1];

                        if version != OSPF_VERSION {
                            continue;
                        }

                        // Extract router ID and area ID
                        let sender_router_id = format!(
                            "{}.{}.{}.{}",
                            ospf_data[4], ospf_data[5], ospf_data[6], ospf_data[7]
                        );

                        let sender_area_id = format!(
                            "{}.{}.{}.{}",
                            ospf_data[8], ospf_data[9], ospf_data[10], ospf_data[11]
                        );

                        debug!(
                            "OSPF type={} from {} ({})",
                            packet_type, src_ip, sender_router_id
                        );

                        // Handle packet
                        let ospf_data_owned = ospf_data.to_vec();
                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let ospf_state_clone = ospf_state.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                if let Err(e) = Self::handle_ospf_packet(
                                    packet_type,
                                    &ospf_data_owned,
                                    src_ip,
                                    sender_router_id,
                                    sender_area_id,
                                    llm_clone,
                                    state_clone,
                                    status_clone,
                                    protocol_clone,
                                    ospf_state_clone,
                                    server_id,
                                )
                                .await
                                {
                                    error!("OSPF packet error: {}", e);
                                }
                            })
                            .await;
                    }
                    Ok(Err(e)) => {
                        error!("OSPF recv error: {}", e);
                    }
                    Err(_would_block) => continue,
                }
            }

            warn!("OSPF receive loop terminated");
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(SocketAddr::new(IpAddr::V4(interface_ip), 0))
    }

    #[cfg(unix)]
    async fn handle_ospf_packet(
        packet_type: u8,
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        // Age out neighbours we have not heard from within RouterDeadInterval, then find or
        // create this one.
        //
        // The ageing is not cosmetic. The key is the sender's Router ID, four bytes chosen
        // by whoever sent the packet, and nothing else ever removed an entry — a peer
        // spraying Hellos with random Router IDs grew this map until the server stopped.
        // RFC 2328 10.5 already says a neighbour silent for RouterDeadInterval is Down, so
        // the bound and the correct behaviour are the same change.
        let dead_after = ospf_state.config.router_dead_interval;
        let existing = {
            let mut neighbors = ospf_state.neighbors.lock().await;
            let now = Instant::now();
            if dead_after > 0 {
                let deadline = std::time::Duration::from_secs(dead_after as u64);
                neighbors.retain(|id, n| {
                    // The sender is alive by definition: this packet is from it.
                    let alive =
                        *id == sender_router_id || now.duration_since(n.last_hello) < deadline;
                    if !alive {
                        info!(
                            "OSPF neighbor {} aged out after {}s without a packet",
                            id, dead_after
                        );
                    }
                    alive
                });
            }
            neighbors.get_mut(&sender_router_id).map(|neighbor| {
                neighbor.last_hello = now;
                neighbor.connection_id
            })
        };

        // A new neighbour needs an id, and `get_next_unified_id` takes the global AppState
        // write lock. Allocating it while still holding the neighbour mutex would be a lock
        // held across an await — the pattern this codebase forbids, and a lock-order
        // inversion against every task that takes AppState first. An id allocated and then
        // lost to a race costs nothing; it is a counter.
        let (connection_id, is_new_neighbor) = match existing {
            Some(id) => (id, false),
            None => {
                let fresh = ConnectionId::new(app_state.get_next_unified_id().await);
                let mut neighbors = ospf_state.neighbors.lock().await;
                match neighbors.get(&sender_router_id) {
                    // Another packet from the same neighbour won the race while we were
                    // outside the lock.
                    Some(raced) => (raced.connection_id, false),
                    None => {
                        neighbors.insert(
                            sender_router_id.clone(),
                            OspfNeighbor {
                                router_id: sender_router_id.clone(),
                                neighbor_ip: src_ip,
                                connection_id: fresh,
                                state: OspfNeighborState::Down,
                                priority: 0,
                                dr: "0.0.0.0".to_string(),
                                bdr: "0.0.0.0".to_string(),
                                last_hello: Instant::now(),
                            },
                        );
                        (fresh, true)
                    }
                }
            }
        };

        // Publish the neighbour to AppState. Until this existed the ConnectionId above was
        // minted, handed to `call_llm` and written into every event, but never registered:
        // `call_llm_inner` resolves the peer address by looking the connection up, so every
        // OSPF event and access-log line recorded a null client address, the dashboard rail
        // showed an OSPF server with no peers however much traffic it took, and the ↓/↑
        // byte counters stayed at zero. The 10s idle sweep reaps these again — see
        // `.connectionless()` in the metadata.
        if is_new_neighbor {
            use crate::state::server::{
                ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
            };
            let now = crate::utils::clock::Instant::now();
            app_state
                .add_connection_to_server(
                    server_id,
                    ServerConnectionState {
                        id: connection_id,
                        remote_addr: SocketAddr::new(IpAddr::V4(src_ip), 0),
                        local_addr: SocketAddr::new(IpAddr::V4(ospf_state.interface_ip), 0),
                        bytes_sent: 0,
                        bytes_received: data.len() as u64,
                        packets_sent: 0,
                        packets_received: 1,
                        last_activity: now,
                        status: ConnectionStatus::Active,
                        status_changed_at: now,
                        protocol_info: ProtocolConnectionInfo::empty(),
                    },
                )
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        } else {
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    Some(data.len() as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;
        }

        match packet_type {
            OSPF_TYPE_HELLO => {
                Self::handle_hello_packet(
                    data,
                    src_ip,
                    sender_router_id,
                    sender_area_id,
                    connection_id,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol,
                    ospf_state,
                    server_id,
                )
                .await?;
            }
            OSPF_TYPE_DATABASE_DESCRIPTION => {
                Self::handle_database_description_packet(
                    data,
                    src_ip,
                    sender_router_id,
                    sender_area_id,
                    connection_id,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol,
                    ospf_state,
                    server_id,
                )
                .await?;
            }
            OSPF_TYPE_LINK_STATE_REQUEST => {
                Self::handle_link_state_request_packet(
                    data,
                    src_ip,
                    sender_router_id,
                    sender_area_id,
                    connection_id,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol,
                    ospf_state,
                    server_id,
                )
                .await?;
            }
            OSPF_TYPE_LINK_STATE_UPDATE => {
                Self::handle_link_state_update_packet(
                    data,
                    src_ip,
                    sender_router_id,
                    sender_area_id,
                    connection_id,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol,
                    ospf_state,
                    server_id,
                )
                .await?;
            }
            OSPF_TYPE_LINK_STATE_ACK => {
                Self::handle_link_state_ack_packet(
                    data,
                    src_ip,
                    sender_router_id,
                    sender_area_id,
                    connection_id,
                    llm_client,
                    app_state,
                    status_tx,
                    protocol,
                    ospf_state,
                    server_id,
                )
                .await?;
            }
            _ => {
                warn!("OSPF unknown type: {}", packet_type);
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    async fn handle_hello_packet(
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        if data.len() < OSPF_HEADER_LEN + 20 {
            return Err(anyhow!("Hello too short"));
        }

        // Parse Hello fields
        let network_mask = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);
        let hello_interval = u16::from_be_bytes([data[28], data[29]]);
        let priority = data[31];
        let router_dead_interval = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let dr = format!("{}.{}.{}.{}", data[36], data[37], data[38], data[39]);
        let bdr = format!("{}.{}.{}.{}", data[40], data[41], data[42], data[43]);

        // Parse neighbors
        let mut neighbor_list = Vec::new();
        let mut offset = 44;
        while offset + 4 <= data.len() {
            let neighbor_id = format!(
                "{}.{}.{}.{}",
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3]
            );
            neighbor_list.push(neighbor_id);
            offset += 4;
        }

        info!(
            "OSPF Hello from {} (priority={}, DR={}, BDR={})",
            sender_router_id, priority, dr, bdr
        );

        // RFC 2328 10.5: HelloInterval, RouterDeadInterval and the network mask must match
        // the receiving interface's, or the Hello is not acceptable and no adjacency can
        // form. The configured values come from the startup parameters.
        let mismatches =
            ospf_state
                .config
                .hello_mismatches(hello_interval, router_dead_interval, &network_mask);

        if !mismatches.is_empty() {
            Log::new(Some(&status_tx)).warn(format!(
                "OSPF Hello from {} does not match this interface: {}",
                sender_router_id,
                mismatches.join("; ")
            ));
        }

        // Update neighbor state
        {
            let mut neighbors = ospf_state.neighbors.lock().await;
            if let Some(neighbor) = neighbors.get_mut(&sender_router_id) {
                neighbor.priority = priority;
                neighbor.dr = dr.clone();
                neighbor.bdr = bdr.clone();
                neighbor.last_hello = Instant::now();

                // State transitions. A Hello that failed the 10.5 check does not advance
                // the machine: a real router would never reach adjacency across such a
                // mismatch, and reporting Init/2-Way here would be a lie the operator
                // acts on.
                if mismatches.is_empty() {
                    match neighbor.state {
                        OspfNeighborState::Down => {
                            neighbor.state = OspfNeighborState::Init;
                            info!("OSPF neighbor {} -> Init", sender_router_id);
                        }
                        OspfNeighborState::Init => {
                            neighbor.state = OspfNeighborState::TwoWay;
                            info!("OSPF neighbor {} -> 2-Way", sender_router_id);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Send structured event to LLM. The event fires even for a rejected Hello, carrying
        // the reason - a refusal the model can see and explain beats one it cannot.
        let event = Event {
            event_type: &OSPF_HELLO_EVENT,
            data: serde_json::json!({
                "connection_id": connection_id.to_string(),
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "network_mask": network_mask,
                "hello_interval": hello_interval,
                "router_dead_interval": router_dead_interval,
                "router_priority": priority,
                "dr": dr,
                "bdr": bdr,
                "neighbors": neighbor_list,
                "local_network_mask": ospf_state.config.network_mask,
                "local_hello_interval": ospf_state.config.hello_interval,
                "local_router_dead_interval": ospf_state.config.router_dead_interval,
                "local_router_priority": ospf_state.config.router_priority,
                "config_mismatches": mismatches,
            }),
        };

        Self::dispatch_event(
            event,
            connection_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
            ospf_state,
            server_id,
        )
        .await
    }

    /// Handle a Database Description packet (RFC 2328 A.3.3).
    ///
    /// Body layout after the 24-byte OSPF header:
    /// InterfaceMTU(2) | Options(1) | Flags(1) | DDSequenceNumber(4) | LSA headers (20 each)
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_database_description_packet(
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        if data.len() < OSPF_HEADER_LEN + 8 {
            return Err(anyhow!("OSPF DD packet too short: {} bytes", data.len()));
        }

        let interface_mtu = u16::from_be_bytes([data[24], data[25]]);
        let options = data[26];
        let flags = data[27];
        let dd_sequence = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let lsa_headers = OspfProtocol::parse_lsa_headers(&data[32..], 32);

        info!(
            "OSPF DD from {} (seq={}, init={}, more={}, master={}, {} LSA headers)",
            sender_router_id,
            dd_sequence,
            flags & 0x04 != 0,
            flags & 0x02 != 0,
            flags & 0x01 != 0,
            lsa_headers.len()
        );

        let event = Event {
            event_type: &OSPF_DATABASE_DESCRIPTION_EVENT,
            data: serde_json::json!({
                "connection_id": connection_id.to_string(),
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "interface_mtu": interface_mtu,
                "options": options,
                "init": flags & 0x04 != 0,
                "more": flags & 0x02 != 0,
                "master": flags & 0x01 != 0,
                "dd_sequence": dd_sequence,
                "lsa_count": lsa_headers.len(),
                "lsa_headers": lsa_headers,
            }),
        };

        Self::dispatch_event(
            event,
            connection_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
            ospf_state,
            server_id,
        )
        .await
    }

    /// Handle a Link State Request packet (RFC 2328 A.3.4).
    ///
    /// Body is a repeating triple: LSType(4) | LinkStateID(4) | AdvertisingRouter(4)
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_link_state_request_packet(
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        let body = data.get(OSPF_HEADER_LEN..).unwrap_or(&[]);
        let mut requests = Vec::new();
        let mut offset = 0;
        while offset + 12 <= body.len() && requests.len() < 64 {
            let r = &body[offset..offset + 12];
            requests.push(serde_json::json!({
                "lsa_type": u32::from_be_bytes([r[0], r[1], r[2], r[3]]),
                "link_state_id": format!("{}.{}.{}.{}", r[4], r[5], r[6], r[7]),
                "advertising_router": format!("{}.{}.{}.{}", r[8], r[9], r[10], r[11]),
            }));
            offset += 12;
        }

        info!(
            "OSPF LSR from {} ({} LSAs requested)",
            sender_router_id,
            requests.len()
        );

        let event = Event {
            event_type: &OSPF_LINK_STATE_REQUEST_EVENT,
            data: serde_json::json!({
                "connection_id": connection_id.to_string(),
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "request_count": requests.len(),
                "requests": requests,
            }),
        };

        Self::dispatch_event(
            event,
            connection_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
            ospf_state,
            server_id,
        )
        .await
    }

    /// Handle a Link State Update packet (RFC 2328 A.3.5).
    ///
    /// Body layout: NumberOfLSAs(4) followed by that many LSAs, each starting with a
    /// 20-byte header whose `length` field covers header plus body.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_link_state_update_packet(
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        if data.len() < OSPF_HEADER_LEN + 4 {
            return Err(anyhow!("OSPF LSU packet too short: {} bytes", data.len()));
        }

        let advertised_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let body = &data[28..];

        // Walk the LSAs using each header's own length field rather than trusting the
        // advertised count, so a peer cannot make us read past the packet.
        let mut lsas = Vec::new();
        let mut offset = 0usize;
        while offset + 20 <= body.len() && lsas.len() < 64 {
            let header = OspfProtocol::parse_lsa_headers(&body[offset..offset + 20], 1);
            let Some(header) = header.into_iter().next() else {
                break;
            };
            let declared = header["length"].as_u64().unwrap_or(0) as usize;
            lsas.push(header);
            // A length below the header size would not advance us; stop rather than spin.
            if declared < 20 {
                break;
            }
            offset += declared;
        }

        info!(
            "OSPF LSU from {} ({} LSAs advertised, {} parsed)",
            sender_router_id,
            advertised_count,
            lsas.len()
        );

        let event = Event {
            event_type: &OSPF_LINK_STATE_UPDATE_EVENT,
            data: serde_json::json!({
                "connection_id": connection_id.to_string(),
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "advertised_lsa_count": advertised_count,
                "lsa_count": lsas.len(),
                "lsas": lsas,
            }),
        };

        Self::dispatch_event(
            event,
            connection_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
            ospf_state,
            server_id,
        )
        .await
    }

    /// Handle a Link State Acknowledgment packet (RFC 2328 A.3.6) - a list of LSA headers.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_link_state_ack_packet(
        data: &[u8],
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        let body = data.get(OSPF_HEADER_LEN..).unwrap_or(&[]);
        let lsa_headers = OspfProtocol::parse_lsa_headers(body, 64);

        trace!(
            "OSPF LSAck from {} ({} LSA headers)",
            sender_router_id,
            lsa_headers.len()
        );

        let event = Event {
            event_type: &OSPF_LINK_STATE_ACK_EVENT,
            data: serde_json::json!({
                "connection_id": connection_id.to_string(),
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "lsa_count": lsa_headers.len(),
                "lsa_headers": lsa_headers,
            }),
        };

        Self::dispatch_event(
            event,
            connection_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
            ospf_state,
            server_id,
        )
        .await
    }

    /// Ask the LLM how to answer an OSPF event and put whatever packets it chooses on the wire.
    ///
    /// Shared by every packet-type handler so they all get identical action handling, logging
    /// and destination resolution.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_event(
        event: Event,
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfProtocol>,
        ospf_state: Arc<OspfState>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        // Whether to engage with an OSPF speaker at all — respond to a Hello, claim DR/BDR, run
        // as a passive listener, or act as a honeypot — is a policy/engagement decision, not
        // something the received packet determines. With no operator policy — no server
        // instruction and no per-event handler — the spec-safe default is to listen passively
        // and not respond, WITHOUT burning an LLM round-trip per received packet. The model is
        // consulted only when the operator opts in with how the router should behave.
        if !operator_wants_dynamic(&app_state, server_id, &event.event_type.id).await {
            Log::new(Some(&status_tx)).debug(format!(
                "OSPF {} observed passively: no operator policy configured (no instruction or handler), no response and no LLM call",
                event.event_type.id
            ));
            return Ok(());
        }

        let event_id = event.event_type.id.clone();

        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                // Log LLM messages
                for message in &execution_result.messages {
                    Log::new(Some(&status_tx)).info(format!("{}", message));
                }

                Log::new(Some(&status_tx)).debug(format!(
                    "OSPF got {} protocol results",
                    execution_result.protocol_results.len()
                ));

                // Distinguish, in the log, the model *choosing* silence from the model
                // returning nothing usable. On the wire the two are identical — OSPF has no
                // response for either — so the log is the only place the difference survives.
                let mut packets_sent = 0usize;
                let mut model_chose_to_wait = false;

                // Process each protocol result (OSPF packets to send)
                for protocol_result in execution_result.protocol_results {
                    if matches!(
                        protocol_result,
                        crate::llm::actions::protocol_trait::ActionResult::WaitForMore
                    ) {
                        model_chose_to_wait = true;
                    }

                    // Check if this is a Custom result with OSPF action
                    if let crate::llm::actions::protocol_trait::ActionResult::Custom {
                        name,
                        data,
                    } = &protocol_result
                    {
                        if name == "ospf_action" {
                            // Extract action type and destination
                            let action_type =
                                data.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            let destination_str = data
                                .get("destination")
                                .and_then(|d| d.as_str())
                                .unwrap_or("multicast");

                            // Fill in whatever the model left out from the interface
                            // configuration. Without this the builders fell back to
                            // hardcoded constants and the operator's hello_interval,
                            // router_dead_interval, network_mask and router_priority
                            // never reached the wire.
                            let mut data = data.clone();
                            ospf_state.config.apply_defaults(&mut data);
                            let data = &data;

                            // Build packet from structured action data (no bytes in JSON!)
                            let packet_result = match action_type {
                                "send_hello" => actions::OspfProtocol::build_hello_packet(data),
                                "send_database_description" => {
                                    actions::OspfProtocol::build_database_description_packet(data)
                                }
                                "send_link_state_request" => {
                                    actions::OspfProtocol::build_link_state_request_packet(data)
                                }
                                "send_link_state_update" => {
                                    actions::OspfProtocol::build_link_state_update_packet(data)
                                }
                                "send_link_state_ack" => {
                                    actions::OspfProtocol::build_link_state_ack_packet(data)
                                }
                                _ => {
                                    warn!("Unknown OSPF action type: {}", action_type);
                                    continue;
                                }
                            };

                            match packet_result {
                                Ok(packet) => {
                                    // Parse destination: "multicast", "dr_multicast", or IP address
                                    let dest_ip = match destination_str {
                                        "multicast" => OSPF_ALL_SPF_ROUTERS,
                                        "dr_multicast" => OSPF_ALL_DROUTERS,
                                        ip_str => match ip_str.parse::<Ipv4Addr>() {
                                            Ok(ip) => ip,
                                            Err(_) => {
                                                warn!(
                                                    "Invalid destination '{}', using multicast",
                                                    ip_str
                                                );
                                                OSPF_ALL_SPF_ROUTERS
                                            }
                                        },
                                    };

                                    // Send packet to destination
                                    match Self::send_ospf_packet(
                                        ospf_state.socket_fd,
                                        dest_ip,
                                        &packet,
                                    ) {
                                        Ok(()) => {
                                            packets_sent += 1;
                                            // The rail's uparrow counter and the
                                            // connection-scoped task prompts read these.
                                            app_state
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    None,
                                                    Some(packet.len() as u64),
                                                    None,
                                                    Some(1),
                                                )
                                                .await;
                                            let log = Log::new(Some(&status_tx));
                                            // Summary + hex payload are FileOnly (hot path).
                                            log.debug(format!(
                                                "OSPF sent {} bytes to {}",
                                                packet.len(),
                                                dest_ip
                                            ));
                                            log.trace(format!(
                                                "OSPF sent (hex): {}",
                                                hex::encode(&packet)
                                            ));
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_tx))
                                                .error(format!("OSPF send error: {}", e));
                                        }
                                    }
                                }
                                Err(e) => {
                                    Log::new(Some(&status_tx))
                                        .error(format!("OSPF packet build error: {}", e));
                                }
                            }
                            continue;
                        }
                    }

                    // Fallback: Check for legacy Output results
                    if let Some(output_data) = protocol_result.get_all_output().first() {
                        // Send to default multicast
                        match Self::send_ospf_packet(
                            ospf_state.socket_fd,
                            OSPF_ALL_SPF_ROUTERS,
                            output_data,
                        ) {
                            Ok(()) => {
                                packets_sent += 1;
                                Log::new(Some(&status_tx)).debug(format!(
                                    "OSPF sent {} bytes to multicast (224.0.0.5)",
                                    output_data.len()
                                ));
                            }
                            Err(e) => {
                                Log::new(Some(&status_tx)).error(format!("OSPF send error: {}", e));
                            }
                        }
                    }
                }

                if packets_sent == 0 {
                    // No packet went out. OSPF has no "I cannot answer" message, so the wire
                    // looks exactly like a passive listener either way; the decision tag is
                    // what tells an operator which of the two happened.
                    let decision = if model_chose_to_wait {
                        "model_wait"
                    } else {
                        "model_no_action"
                    };
                    Log::new(Some(&status_tx)).info(format!(
                        "OSPF {} answered with no packet: decision={} (OSPF has no error \
                         packet type; staying silent is the protocol-correct response)",
                        event_id, decision
                    ));
                }
            }
            Err(e) => {
                // The LLM call failed. OSPF defines no error or NAK packet — the five packet
                // types are Hello, DD, LSR, LSU, LSAck and every one of them is a positive
                // routing assertion. Fabricating any of them to signal "netget is broken"
                // would claim an adjacency, a DR role or database contents we cannot back,
                // which is strictly worse for the peer than silence: its own
                // RouterDeadInterval already handles a router that stops speaking. So this
                // path stays silent on the wire deliberately, and the failure is reported to
                // the operator here. Nothing derived from `e` reaches the socket.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_unavailable"
                };
                Log::new(Some(&status_tx)).error(format!(
                    "OSPF {} not answered: decision={} ({}) — no packet sent, OSPF has no \
                     failure packet type; LLM error: {}",
                    event_id,
                    decision,
                    category.text(),
                    e
                ));
            }
        }

        Ok(())
    }

    /// Send OSPF packet to destination
    #[cfg(unix)]
    pub fn send_ospf_packet(socket_fd: i32, dest_ip: Ipv4Addr, ospf_data: &[u8]) -> Result<()> {
        unsafe {
            let mut dest_addr = std::mem::zeroed::<libc::sockaddr_in>();
            #[cfg(target_os = "macos")]
            {
                dest_addr.sin_family = libc::AF_INET as libc::sa_family_t;
                dest_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            #[cfg(not(target_os = "macos"))]
            {
                dest_addr.sin_family = libc::AF_INET as u16;
            }
            dest_addr.sin_port = 0; // Raw IP, no port
            dest_addr.sin_addr.s_addr = u32::from(dest_ip).to_be();

            let n = libc::sendto(
                socket_fd,
                ospf_data.as_ptr() as *const libc::c_void,
                ospf_data.len(),
                0,
                &dest_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );

            if n < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        Ok(())
    }
}

/// Returns true if the operator opted into dynamic (LLM- or handler-driven) responses for this
/// server: either a non-empty server instruction was given, or an event handler is configured
/// for `event_id`. When false the server observes passively and never consults the model —
/// whether to respond to an OSPF speaker (and how: DR claim, honeypot, ...) is a policy decision
/// with no configured policy to apply.
#[cfg(unix)]
async fn operator_wants_dynamic(
    state: &AppState,
    server_id: crate::state::ServerId,
    event_id: &str,
) -> bool {
    state
        .with_server_mut(server_id, |server| {
            let has_instruction = !server.instruction.trim().is_empty();
            let has_handler = server
                .event_handler_config
                .as_ref()
                .map(|c| c.find_handler(event_id).is_some())
                .unwrap_or(false);
            has_instruction || has_handler
        })
        .await
        .unwrap_or(false)
}
