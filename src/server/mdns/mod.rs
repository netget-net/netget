//! mDNS/DNS-SD server implementation
pub mod actions;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

#[cfg(not(target_arch = "wasm32"))]
use crate::llm::action_helper::call_llm;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ollama_client::OllamaClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::logging::emit::Log;
#[cfg(not(target_arch = "wasm32"))]
use crate::protocol::Event;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::MdnsProtocol;
#[cfg(not(target_arch = "wasm32"))]
use crate::state::app_state::AppState;
use crate::{console_error, console_info};
#[cfg(not(target_arch = "wasm32"))]
use actions::MDNS_SERVER_STARTUP_EVENT;

/// Port advertised in the SRV record when neither the service definition nor
/// the server's own listen address names one.
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_ADVERTISED_PORT: u16 = 8080;

/// The IPv4 multicast group and port mDNS announces on (RFC 6762).
///
/// Reported as *information*, never as this server's endpoint: joining a group is not
/// binding it, and nobody owns it. See the return value of `spawn_with_llm_actions`.
#[cfg(not(target_arch = "wasm32"))]
const MDNS_GROUP: &str = "224.0.0.251:5353";

/// Port component of the "this protocol binds no listening socket" placeholder address.
///
/// `server_startup::is_bound_addr` treats port 0 as exactly that — the OS never resolves a
/// real bind to port 0 — and declines to advertise an endpoint for it.
#[cfg(not(target_arch = "wasm32"))]
const NO_LISTENING_SOCKET_PORT: u16 = 0;

/// mDNS server that advertises services based on LLM instructions
pub struct MdnsServer;

#[cfg(not(target_arch = "wasm32"))]
impl MdnsServer {
    /// Spawn mDNS server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        use mdns_sd::ServiceDaemon;

        // mDNS itself does not bind a listening socket, so the server's own
        // port is only meaningful as the default port to advertise for the
        // service being announced.
        //
        // The `port` startup parameter wins over it, on every path. It used to be read only
        // inside the two `startup_params` registration branches, so a caller that supplied
        // `port` *and* an instruction - no `service_type`, no `services`, so the model does
        // the registering - had the value silently dropped and got `DEFAULT_ADVERTISED_PORT`
        // in the SRV record. The parameter's own description promises it is "the port clients
        // will connect to", which was then untrue in exactly the case where a human wrote a
        // sentence rather than a service definition.
        let param_port = startup_params
            .as_ref()
            .map(|p| p.get_optional_u64("port"))
            .transpose()?
            .flatten()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0);

        let default_port = param_port.unwrap_or(match listen_addr.port() {
            0 => DEFAULT_ADVERTISED_PORT,
            p => p,
        });

        info!("mDNS server (action-based) starting");
        Log::new(Some(&status_tx)).info("mDNS server starting");

        let protocol = Arc::new(MdnsProtocol::new());

        // Create mDNS daemon
        let mdns = ServiceDaemon::new()
            .map_err(|e| anyhow::anyhow!("Failed to create mDNS daemon: {}", e))?;
        info!("mDNS daemon created");

        // Track if we successfully processed startup_params
        let mut used_startup_params = false;

        // If startup_params are provided, register services directly
        if let Some(ref params) = startup_params {
            // Check for multiple services array
            if let Some(services) = params.get_optional_array("services")? {
                info!(
                    "Registering {} services from startup_params",
                    services.len()
                );
                used_startup_params = true;
                let requested = services.len();
                let mut registered = 0usize;
                for service in services {
                    if let Some(service_obj) = service.as_object() {
                        let service_type = service_obj
                            .get("service_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("_http._tcp.local.");
                        let service_name = service_obj
                            .get("service_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Service");
                        let properties = service_obj
                            .get("properties")
                            .and_then(|v| v.as_object())
                            .map(|obj| {
                                obj.iter()
                                    .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();

                        // The advertised port is what discovering clients will
                        // actually connect to; publishing 0 makes the SRV
                        // record useless.
                        let port = service_obj
                            .get("port")
                            .and_then(|v| v.as_u64())
                            .and_then(|p| u16::try_from(p).ok())
                            .unwrap_or(default_port);

                        // Don't fail server startup if registration fails
                        if register_service(
                            &mdns,
                            service_type,
                            service_name,
                            port,
                            &properties,
                            &status_tx,
                        )
                        .is_ok()
                        {
                            registered += 1;
                        }
                    }
                }
                // The operator supplied the service list, so no model was asked. Say so:
                // "advertising nothing" because nobody asked for anything must not read the
                // same as "advertising nothing" because the backend failed.
                Log::new(Some(&status_tx)).info(format!(
                    "mDNS advertising {}/{} service(s) decision=operator_config \
                     (from startup parameters; no model call)",
                    registered, requested
                ));
            }
            // Check for single service parameters
            else if let Some(service_type) = params.get_optional_string("service_type")? {
                info!("Registering single service from startup_params");
                used_startup_params = true;
                let service_name = params
                    .get_optional_string("service_name")?
                    .unwrap_or_else(|| "Service".to_string());
                let properties = params
                    .get_optional_object("properties")?
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let port = params
                    .get_optional_u64("port")?
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(default_port);

                // Don't fail server startup if registration fails
                let registered = register_service(
                    &mdns,
                    &service_type,
                    &service_name,
                    port,
                    &properties,
                    &status_tx,
                )
                .is_ok();
                Log::new(Some(&status_tx)).info(format!(
                    "mDNS advertising {}/1 service(s) decision=operator_config \
                     (from startup parameters; no model call)",
                    usize::from(registered)
                ));
            }
        }

        // Only call LLM if we didn't use startup_params
        if !used_startup_params {
            // `service_name` and `properties` describe a service; without `service_type` or
            // `services` there is nothing to attach them to, so they are dropped. Say so
            // rather than registering something surprising - a caller that got this far
            // supplied half a service definition and would otherwise see the model invent
            // the other half from the instruction.
            if let Some(ref params) = startup_params {
                let mut orphaned: Vec<&str> = Vec::new();
                if params.get_optional_string("service_name")?.is_some() {
                    orphaned.push("service_name");
                }
                if params.get_optional_object("properties")?.is_some() {
                    orphaned.push("properties");
                }
                if !orphaned.is_empty() {
                    console_error!(
                        status_tx,
                        "mDNS ignoring startup parameter(s) {}: they describe a service, and \
                         neither 'service_type' nor 'services' was given to attach them to",
                        orphaned.join(", ")
                    );
                }
            }

            // Create mDNS server startup event
            let event = Event::new(&MDNS_SERVER_STARTUP_EVENT, serde_json::json!({}));

            // Get LLM's service registration instructions
            // mDNS manually processes register_mdns_service actions using raw_actions
            //
            // Silence is the correct answer on failure here, and deliberately so - see the
            // `else` branch below for why. It is *not* correct to swallow the error, which is
            // what `if let Ok(..)` did: the daemon came up announcing nothing and said nothing
            // about why.
            let llm_outcome = call_llm(
                &llm_client,
                &app_state,
                server_id,
                None,
                &event,
                protocol.as_ref(),
            )
            .await;

            // How many services the handler asked for, and how many the daemon accepted.
            // Counted so the three ways of ending up advertising nothing — the backend
            // failed, the handler said nothing, the handler's services were rejected —
            // are three different log lines rather than one absence.
            let mut requested = 0usize;
            let mut registered = 0usize;

            if let Err(ref e) = llm_outcome {
                // Nothing goes on the wire. mDNS has no unicast error frame and no request to
                // answer - this call is a *startup* event asking what services to advertise,
                // not a reply to a querier - so there is no peer waiting on a response and
                // nothing that could be sent.
                //
                // More than that, inventing one would be actively harmful in a way a
                // unicast protocol's error reply is not: an mDNS answer is multicast to the
                // whole link and every listener on it caches the record for its TTL. A
                // fabricated PTR/SRV/A set would propagate a service that does not exist to
                // every machine in the subnet and keep it there after the backend recovered.
                // This is the `udp` case, one step worse.
                //
                // So: announce nothing, and be loud about it on both channels.
                let category = match crate::utils::wire_failure::WireFailure::classify(e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => "overloaded",
                    crate::utils::wire_failure::WireFailure::Unavailable => "unavailable",
                };
                // `console_error!` below logs to `tracing` as well, so the tag lives there
                // and only there: one incident must be one `grep decision=` hit, not two.
                error!(
                    "mDNS service-registration handler failed (category={}); the responder is \
                     running but will advertise nothing: {}",
                    category, e
                );
                console_error!(
                    status_tx,
                    "mDNS advertising nothing: service-registration handler failed \
                     (decision=fail_closed_llm_error category={}): {}",
                    category,
                    e
                );
            }

            if let Ok(execution_result) = llm_outcome {
                // Display messages from LLM
                for message in &execution_result.messages {
                    console_info!(status_tx, "{}", message);
                }

                // Process raw actions for manual mDNS service registration
                for action in execution_result.raw_actions {
                    if let Some(action_type) = action.get("type").and_then(|v| v.as_str()) {
                        if action_type == "register_mdns_service" {
                            // Extract service parameters
                            let service_type = action
                                .get("service_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("_http._tcp.local.");
                            let instance_name = action
                                .get("instance_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("MyService");
                            // `as u16` would silently wrap an out-of-range port
                            // (e.g. 70000 -> 4464) into a wrong SRV record.
                            let port = action
                                .get("port")
                                .and_then(|v| v.as_u64())
                                .and_then(|p| u16::try_from(p).ok())
                                .unwrap_or(default_port);

                            let properties = action
                                .get("properties")
                                .and_then(|v| v.as_object())
                                .map(|obj| {
                                    obj.iter()
                                        .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();

                            // Failures are logged by register_service; one bad
                            // service must not abort the remaining registrations.
                            requested += 1;
                            if register_service(
                                &mdns,
                                service_type,
                                instance_name,
                                port,
                                &properties,
                                &status_tx,
                            )
                            .is_ok()
                            {
                                registered += 1;
                            }
                        }
                    }
                }

                // One grep-able line for what the handler's answer amounted to. mDNS has no
                // refusal action, so there is no `model_reject` here: a handler that wants
                // to advertise nothing and a handler that had nothing to say are the same
                // answer, and `model_silent` is the honest name for both.
                let log = Log::new(Some(&status_tx));
                if registered > 0 {
                    log.info(format!(
                        "mDNS advertising {}/{} service(s) decision=model_answer",
                        registered, requested
                    ));
                } else if requested > 0 {
                    log.error(format!(
                        "mDNS advertising nothing: all {} service(s) the handler asked for \
                         were rejected by the daemon decision=fail_closed_bad_action",
                        requested
                    ));
                } else {
                    log.warn(
                        "mDNS advertising nothing: the handler ran and asked for no services \
                         decision=model_silent",
                    );
                }
            }
        } // Close if !used_startup_params

        // Keep the daemon alive for the lifetime of the server task.
        //
        // `ServiceDaemon` has no `Drop` impl, so simply dropping it leaves the
        // background thread running and the services still being announced on
        // the multicast group. `DaemonGuard` calls `shutdown()` from its own
        // `Drop`, which runs when the task is aborted by `stop_server`.
        let handle = tokio::spawn(async move {
            let _guard = DaemonGuard(mdns);
            std::future::pending::<()>().await;
        });

        // Register the task so stop_server can abort it and stop advertising.
        app_state.register_server_task(server_id, handle).await;

        // The group is real information, but it is not this server's endpoint —
        // so it is reported as what it is, on the status stream, rather than
        // smuggled into `local_addr`.
        info!(
            "mDNS announcing on the {MDNS_GROUP} multicast group; this server binds no \
             listening socket of its own"
        );
        Log::new(Some(&status_tx)).info(format!(
            "mDNS announcing on the {MDNS_GROUP} multicast group (not a listening \
             endpoint: mdns-sd owns its sockets and does not expose them)"
        ));

        // No socket of our own to report.
        //
        // This used to return `224.0.0.251:5353`, the group it announces on, which the TUI
        // and `server_status` then displayed as if it were the server's listening endpoint.
        // It is not an endpoint at all: joining a multicast group is not binding it, nobody
        // owns it, and a stray `zeroconf` on the same machine makes it look occupied whether
        // or not NetGet is running. `mdns_sd::ServiceDaemon` binds its sockets internally and
        // exposes none of them, so there is no real address to substitute — and
        // `0.0.0.0:0` is this codebase's established "I listen on nothing" placeholder, which
        // `server_startup::is_bound_addr` recognises and declines to advertise (WebRTC, the
        // device-backed protocols and others already return it). Showing no endpoint is the
        // truth; showing a group address was not.
        Ok(SocketAddr::from((
            std::net::Ipv4Addr::UNSPECIFIED,
            NO_LISTENING_SOCKET_PORT,
        )))
    }
}

/// Shuts the mDNS daemon down when the owning task is dropped or aborted.
#[cfg(not(target_arch = "wasm32"))]
struct DaemonGuard(mdns_sd::ServiceDaemon);

#[cfg(not(target_arch = "wasm32"))]
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        match self.0.shutdown() {
            Ok(_) => info!("mDNS daemon shutdown requested"),
            Err(e) => error!("Failed to shut down mDNS daemon: {}", e),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;

    // Determine which local address the default route would use. `connect` on
    // a UDP socket only performs a routing-table lookup - no packets are sent
    // and the peer is never contacted - so the destination is a documentation
    // address (RFC 5737 TEST-NET-1) rather than a real third-party host.
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("192.0.2.1:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return Some(addr.ip().to_string());
            }
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn register_service(
    mdns: &mdns_sd::ServiceDaemon,
    service_type: &str,
    instance_name: &str,
    port: u16,
    properties: &[(&str, &str)],
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<()> {
    use mdns_sd::ServiceInfo;

    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let host_name = format!("{}.local.", instance_name.replace(" ", "-"));

    // Create ServiceInfo
    match ServiceInfo::new(
        service_type,
        instance_name,
        &host_name,
        &local_ip,
        port,
        properties,
    ) {
        Ok(service_info) => {
            // Register service
            match mdns.register(service_info) {
                Ok(_) => {
                    info!(
                        "mDNS registered service: {} ({}:{})",
                        instance_name, local_ip, port
                    );
                    Log::new(Some(status_tx)).info(format!(
                        "→ mDNS registered service: {} ({}:{})",
                        instance_name, local_ip, port
                    ));
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to register mDNS service: {}", e);
                    Log::new(Some(status_tx))
                        .error(format!("✗ Failed to register mDNS service: {}", e));
                    Err(anyhow::anyhow!("Failed to register mDNS service: {}", e))
                }
            }
        }
        Err(e) => {
            error!("Failed to create ServiceInfo: {}", e);
            Log::new(Some(status_tx)).error(format!("✗ Failed to create ServiceInfo: {}", e));
            Err(anyhow::anyhow!("Failed to create ServiceInfo: {}", e))
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl MdnsServer {
    pub async fn spawn_with_llm_actions(
        _listen_addr: SocketAddr,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        anyhow::bail!("mDNS feature not enabled")
    }
}
