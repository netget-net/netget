//! RIP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub struct RipProtocol;

impl RipProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for RipProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_rip_response_action(),
            send_rip_request_action(),
            ignore_request_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "RIP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_rip_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RIP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rip"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            // Deliberately silent: A RIP response asserts routes. A fabricated one is
            // installed in a real routing table.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(520))
            .well_known_udp_port(520)
            .implementation("Manual RIPv2 packet construction (RFC 2453)")
            .llm_control("Optional: which routes to advertise is a policy decision (LLM); with no policy configured the server stays silent with no LLM call")
            .e2e_testing("Manual RIP packet construction with route entries")
            .notes("Distance-vector routing protocol, 15 hop limit. A RIP response is NOT wire-determined — which routes to advertise (and their metrics, incl. 16=withdraw) is routing policy, like DNS/DHCP. So with no operator policy (no instruction, no handler) the server applies the spec-safe STATIC default of advertising nothing and answers with NO LLM round-trip; the LLM is consulted only when the operator supplies the routing policy. There is no mechanical RIP reply to synthesise (RIP has no Hello/keepalive machinery)")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Routing Information Protocol v2 for dynamic routing"
    }
    fn example_prompt(&self) -> &'static str {
        "listen on port 520 via rip. Advertise routes for 192.168.1.0/24 (metric 1) and 10.0.0.0/8 (metric 5)"
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 520,
                "base_stack": "rip",
                "instruction": "RIPv2 routing server. Advertise routes for 192.168.1.0/24 (metric 1) and 10.0.0.0/8 (metric 5). Respond to route requests."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 520,
                "base_stack": "rip",
                "event_handlers": [{
                    "event_pattern": "rip_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "if event.message_type == 'request' then return {type='send_rip_response', routes={{ip_address='192.168.1.0', subnet_mask='255.255.255.0', next_hop='0.0.0.0', metric=1}, {ip_address='10.0.0.0', subnet_mask='255.0.0.0', next_hop='0.0.0.0', metric=5}}} else return {type='ignore_request'} end"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 520,
                "base_stack": "rip",
                "event_handlers": [{
                    "event_pattern": "rip_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_rip_response",
                            "routes": [{
                                "ip_address": "192.168.1.0",
                                "subnet_mask": "255.255.255.0",
                                "next_hop": "0.0.0.0",
                                "metric": 1
                            }]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for RipProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::rip::RipServer;
            RipServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_rip_response" => self.execute_send_rip_response(action),
            "send_rip_request" => self.execute_send_rip_request(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown RIP action: {}", action_type)),
        }
    }
}

impl RipProtocol {
    fn execute_send_rip_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract routes from action
        let routes = action
            .get("routes")
            .and_then(|v| v.as_array())
            .context("Missing or invalid 'routes' field")?;

        if routes.len() > 25 {
            return Err(anyhow::anyhow!("Too many routes (max 25 per packet)"));
        }

        // Build RIP response packet
        let mut packet = Vec::new();

        // Header (4 bytes)
        packet.push(2); // Command: Response
        packet.push(2); // Version: RIPv2
        packet.push(0); // Unused
        packet.push(0); // Unused

        // Route entries (20 bytes each)
        for route in routes {
            // Each of these is a fixed-width wire field. Truncating with `as` would put a
            // different number on the wire than the model asked for and say nothing, so an
            // out-of-range value is refused instead.
            let afi = Self::wire_u16(route, "afi", 2)?; // IPv4 = 2
            let route_tag = Self::wire_u16(route, "route_tag", 0)?;
            let ip_str = route
                .get("ip_address")
                .and_then(|v| v.as_str())
                .context("Missing 'ip_address' in route")?;
            let subnet_mask_str = route
                .get("subnet_mask")
                .and_then(|v| v.as_str())
                .unwrap_or("255.255.255.0");
            let next_hop_str = route
                .get("next_hop")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0");
            // RFC 2453 §3.4.2: 1-15 is a reachable distance, 16 is infinity (withdraw).
            // Nothing above 16 is meaningful, and a value that overflowed a u32 used to be
            // silently truncated into one that was.
            let metric = route.get("metric").and_then(|v| v.as_u64()).unwrap_or(1);
            if !(1..=16).contains(&metric) {
                return Err(anyhow::anyhow!(
                    "Invalid RIP metric {} for {}: must be 1-15 (reachable) or 16 (unreachable)",
                    metric,
                    ip_str
                ));
            }
            let metric = metric as u32;

            // Parse IP addresses
            let ip_parts = Self::parse_ipv4(ip_str)?;
            let subnet_parts = Self::parse_ipv4(subnet_mask_str)?;
            let next_hop_parts = Self::parse_ipv4(next_hop_str)?;

            // Build route entry
            packet.extend_from_slice(&afi.to_be_bytes());
            packet.extend_from_slice(&route_tag.to_be_bytes());
            packet.extend_from_slice(&ip_parts);
            packet.extend_from_slice(&subnet_parts);
            packet.extend_from_slice(&next_hop_parts);
            packet.extend_from_slice(&metric.to_be_bytes());
        }

        Ok(ActionResult::Output(packet))
    }

    fn execute_send_rip_request(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract optional specific routes to request
        let routes = action.get("routes").and_then(|v| v.as_array());

        let mut packet = Vec::new();

        // Header (4 bytes)
        packet.push(1); // Command: Request
        packet.push(2); // Version: RIPv2
        packet.push(0); // Unused
        packet.push(0); // Unused

        if let Some(routes_array) = routes {
            // Same 25-entry ceiling as a Response: RFC 2453 §3.6 sizes a RIP datagram at
            // 4 + 25*20 = 504 bytes. This was checked on the Response path only, so a Request
            // could be built oversize.
            if routes_array.len() > 25 {
                return Err(anyhow::anyhow!("Too many routes (max 25 per packet)"));
            }
            // Request specific routes
            for route in routes_array {
                let afi = Self::wire_u16(route, "afi", 2)?;
                let ip_str = route
                    .get("ip_address")
                    .and_then(|v| v.as_str())
                    .context("Missing 'ip_address' in route")?;

                let ip_parts = Self::parse_ipv4(ip_str)?;

                // Build route entry (metric 16 = infinity for requests)
                packet.extend_from_slice(&afi.to_be_bytes());
                packet.extend_from_slice(&[0, 0]); // Route tag
                packet.extend_from_slice(&ip_parts);
                packet.extend_from_slice(&[0, 0, 0, 0]); // Subnet mask
                packet.extend_from_slice(&[0, 0, 0, 0]); // Next hop
                packet.extend_from_slice(&16u32.to_be_bytes()); // Metric = 16
            }
        } else {
            // Request entire routing table (AFI=0, metric=16)
            packet.extend_from_slice(&[0, 0]); // AFI = 0 (special)
            packet.extend_from_slice(&[0, 0]); // Route tag
            packet.extend_from_slice(&[0, 0, 0, 0]); // IP
            packet.extend_from_slice(&[0, 0, 0, 0]); // Subnet mask
            packet.extend_from_slice(&[0, 0, 0, 0]); // Next hop
            packet.extend_from_slice(&16u32.to_be_bytes()); // Metric = 16
        }

        Ok(ActionResult::Output(packet))
    }

    /// Read a fixed-width 16-bit wire field, refusing a value that would not survive the cast.
    fn wire_u16(route: &serde_json::Value, field: &str, default: u16) -> Result<u16> {
        match route.get(field) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(v) => {
                let n = v
                    .as_u64()
                    .with_context(|| format!("'{field}' must be a non-negative number"))?;
                u16::try_from(n)
                    .with_context(|| format!("'{field}' value {n} does not fit in 16 bits"))
            }
        }
    }

    fn parse_ipv4(ip_str: &str) -> Result<[u8; 4]> {
        let parts: Vec<&str> = ip_str.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!("Invalid IPv4 address: {}", ip_str));
        }

        Ok([
            parts[0].parse().context("Invalid IP octet")?,
            parts[1].parse().context("Invalid IP octet")?,
            parts[2].parse().context("Invalid IP octet")?,
            parts[3].parse().context("Invalid IP octet")?,
        ])
    }
}

// Event types
pub static RIP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rip_request",
        "A RIP message arrived. Answer a 'request' with send_rip_response carrying the routes \
         you want to advertise; a peer's unsolicited 'response' is usually best answered with \
         ignore_request, or with send_rip_request to ask for its table.",
        json!({
            "type": "send_rip_response",
            "routes": [
                {"ip_address": "192.168.1.0", "subnet_mask": "255.255.255.0", "next_hop": "0.0.0.0", "metric": 1}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "number".to_string(),
            description: "RIP command type (1=request, 2=response)".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description: "RIP version (typically 2 for RIPv2)".to_string(),
            required: true,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Message type: 'request' or 'response'".to_string(),
            required: true,
        },
        Parameter {
            name: "routes".to_string(),
            type_hint: "array".to_string(),
            description: "Array of route entries (ip_address, subnet_mask, next_hop, metric)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address of the RIP peer".to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_received".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the received packet".to_string(),
            required: true,
        },
    ])
    // All three sync actions answer this event, which is the protocol's only one. `call_llm`
    // builds the model's tool list from the event type rather than from get_sync_actions(), so
    // without this list the model had no way to reply to a RIP message at all.
    .with_actions(vec![
        send_rip_response_action(),
        send_rip_request_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("RIP {message_type} from {peer_address} ({bytes_received}B)")
            .with_debug("RIPv{version} {message_type} from {peer_address}, {routes_len} routes")
            .with_trace("RIP message: {json_pretty(.)}"),
    )
});

fn get_rip_event_types() -> Vec<EventType> {
    vec![RIP_REQUEST_EVENT.clone()]
}

// Action definitions
fn send_rip_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rip_response".to_string(),
        description: "Send RIP response with routing table entries".to_string(),
        parameters: vec![
            Parameter {
                name: "routes".to_string(),
                type_hint: "array".to_string(),
                description: "Array of route entries to advertise, at most 25. Each route must have: ip_address (string), subnet_mask (string, default 255.255.255.0), next_hop (string, default 0.0.0.0), metric (number 1-15 = hop count, or 16 = unreachable/withdraw the route; default 1), afi (number, default 2 for IPv4), route_tag (number 0-65535, default 0)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_rip_response",
            "routes": [
                {
                    "ip_address": "192.168.1.0",
                    "subnet_mask": "255.255.255.0",
                    "next_hop": "0.0.0.0",
                    "metric": 1
                },
                {
                    "ip_address": "10.0.0.0",
                    "subnet_mask": "255.0.0.0",
                    "next_hop": "192.168.1.1",
                    "metric": 5
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RIP response ({routes_len} routes)")
                .with_debug("RIP send_rip_response: routes={routes_len}"),
        ),
    }
}

fn send_rip_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rip_request".to_string(),
        description: "Send RIP request to query routing table. If routes array is omitted, requests entire routing table.".to_string(),
        parameters: vec![
            Parameter {
                name: "routes".to_string(),
                type_hint: "array".to_string(),
                description: "Optional array of specific routes to request, at most 25, each with an ip_address (string). Omit to request the entire table.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_rip_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RIP request")
                .with_debug("RIP send_rip_request"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Ignore the RIP message and send no response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RIP ignore")
                .with_debug("RIP ignore_request"),
        ),
    }
}
