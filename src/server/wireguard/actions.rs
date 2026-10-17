//! WireGuard protocol actions implementation
//!
//! Defines LLM-controllable actions for WireGuard VPN server

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

/// WireGuard peer connected event.
///
/// Raised by the peer monitoring loop the first time a peer shows up on the
/// WireGuard interface, i.e. *after* its cryptographic handshake has already
/// succeeded (WireGuard performs the handshake in the kernel/userspace backend,
/// so it cannot be gated beforehand). Event data fields:
/// `public_key`, `endpoint`, `allowed_ips`, `server_public_key`, `listen_port`.
pub static WIREGUARD_PEER_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wireguard_peer_connected",
        "WireGuard peer completed its handshake and appeared on the interface. \
         Respond with authorize_peer to (re)configure its allowed IPs, or with \
         disconnect_peer/reject_peer to remove it. Return no actions at all to leave the peer \
         as-is.",
        json!({
            "type": "authorize_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": ["10.0.0.2/32"]
        }),
    )
    .with_alternative_example(json!({
        "type": "disconnect_peer",
        "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        "reason": "not on the allow list"
    }))
    // The three actions that actually change the interface. `set_peer_traffic_limit` is
    // deliberately left out: it is a documented no-op (see mod.rs and CLAUDE.md - no tc/iptables
    // configuration is performed), so advertising it would promise enforcement that never
    // happens. Without this list `call_llm` offered the model none of them, because it builds
    // the model's tool list from the event type rather than from get_sync_actions().
    .with_actions(vec![
        authorize_peer_action(),
        reject_peer_action(),
        disconnect_peer_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WireGuard {client_ip} connected")
            .with_debug("WireGuard peer connected from {client_ip}:{client_port}")
            .with_trace("WireGuard: {json_pretty(.)}"),
    )
});

/// Get all WireGuard event types
pub fn get_wireguard_event_types() -> Vec<EventType> {
    vec![WIREGUARD_PEER_CONNECTED_EVENT.clone()]
}

/// WireGuard protocol implementation
pub struct WireguardProtocol {
    // Protocol instance doesn't need state - server handle is managed separately
}

impl WireguardProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (base trait for all protocols)
impl Protocol for WireguardProtocol {
    /// One user-triggered action: `wireguard_add_peer`.
    ///
    /// This is what makes the authorize/reject flow reachable at all. A WireGuard
    /// responder drops a handshake whose static public key is not ALREADY a
    /// configured peer, and NetGet otherwise only learns of a peer by polling
    /// *after* it appears - so an unconfigured peer never appears and
    /// `wireguard_peer_connected` never fires for a genuinely new key. Pre-adding
    /// the key up front (via this action) is what lets the subsequent handshake
    /// succeed and the event fire. It reaches the running server through
    /// [`Server::execute_action_with_state`] + the handle registered in `spawn`.
    ///
    /// `list_peers`, `remove_peer` and `get_server_info` are still NOT advertised:
    /// they were dead no-ops that promised data the stateless executor never had.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![add_peer_action()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            authorize_peer_action(),
            reject_peer_action(),
            set_peer_traffic_limit_action(),
            disconnect_peer_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "WireGuard"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_wireguard_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>WG"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["wireguard", "wg"]
    }

    /// On macOS `defguard_wireguard_rs` brings the interface up by running `wireguard-go`.
    ///
    /// The kernel implements WireGuard on Linux, FreeBSD and Windows, so there is no external
    /// binary to want there and this declares nothing extra. macOS has no kernel module:
    /// defguard shells out to a userspace `wireguard-go` that must be installed separately,
    /// and without it the interface cannot come up however much privilege the process has.
    ///
    /// This sits behind the `Root` requirement the metadata already declares, and that is the
    /// point — they are two different missing pieces, and a user who fixes one still needs to
    /// be told about the other.
    #[cfg(target_os = "macos")]
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("wireguard-go"));
        deps
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Experimental. The earlier Stable->Beta demotion undershot: the stated reason was
            // that this has never been validated end-to-end against a real WireGuard client —
            // but that is also precisely what Beta requires ("human-reviewed, works against
            // real clients"), so the same evidence rules Beta out too.
            //
            // There is still no real peer. `boringtun` was evaluated as an in-test client and
            // deliberately not adopted; what remains is one #[ignore]d, root-gated harness that
            // asserts on NetGet's own log line rather than on anything a WireGuard peer did.
            // NetGet also implements none of the protocol itself and, on macOS, cannot bring an
            // interface up at all without an external wireguard-go binary — so nothing here has
            // completed a handshake in this environment.
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::Root)
            .well_known_udp_port(51820)
            .implementation(
                "Thin orchestration layer over defguard_wireguard_rs v0.7 - NetGet \
                 implements NONE of the WireGuard protocol itself (no Noise_IK, no crypto, \
                 no packet handling). All of that lives in the platform backend: the kernel \
                 module on Linux/FreeBSD/Windows, and the EXTERNAL wireguard-go binary on \
                 macOS (defguard shells out to `wireguard-go`, which must be installed).",
            )
            .llm_control(
                "Two levers. Up front: wireguard_add_peer (user-triggered async action) \
                 pre-authorizes a peer's public key + allowed IPs on the live interface, so a \
                 subsequent handshake from that key is accepted - this is what makes the \
                 authorize decision reachable, since a WireGuard responder drops a handshake \
                 from an unconfigured key. Post-handshake: on wireguard_peer_connected the LLM \
                 can (re)set allowed IPs (authorize_peer) or remove the peer \
                 (disconnect_peer/reject_peer). The handshake crypto itself happens inside the \
                 backend and cannot be gated; fail-closed - with no pre-add, an unknown peer's \
                 handshake is dropped.",
            )
            .e2e_testing(
                "Non-root tests exercise NetGet's own logic: the pre-add config-mutation path \
                 (build_peer_config - right key + allowed IPs, malformed key rejected), the \
                 wireguard_add_peer executor wiring through execute_action_with_state \
                 (fail-closed with no server/no ips), the authorize/reject/disconnect executors, \
                 and the event/action declarations. A real handshake needs root + a WireGuard \
                 backend (kernel, or wireguard-go on macOS) and has never been run; it is a \
                 root-gated #[ignore]d harness only.",
            )
            .notes(
                "Real data plane (via the platform backend), but EXPERIMENTAL because it has \
                 never been validated against a real client and cannot be in CI: creating the \
                 interface needs root, and on macOS also the external wireguard-go binary. \
                 That is also the definition of Beta, which is why this is not Beta either. \
                 Caveat (1) - the reactive-only authorize flow being unreachable for a \
                 genuinely new peer - is now ADDRESSED: wireguard_add_peer lets the operator/LLM \
                 pre-authorize a peer's public key before it handshakes, which is what a \
                 WireGuard responder requires (it drops a handshake from an unconfigured key). \
                 The pre-add path (validation + configure_peer wiring) is unit-tested; what is \
                 STILL UNVERIFIED here - no root, no wireguard-go - is that a real client then \
                 completes a handshake, that wireguard_peer_connected fires for the pre-added \
                 key, and the exact timing of the event relative to config vs handshake. (2) \
                 set_peer_traffic_limit is recorded but NOT enforced (no tc/iptables). Still the \
                 closest thing to a working tunnel in NetGet - openvpn/ipsec do not carry \
                 traffic at all.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WireGuard VPN server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a WireGuard VPN server on port 51820"
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: authorize every peer that connects, echoing its public
        // key and allowed IPs, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "wireguard_peer_connected":
    actions = [{"type": "authorize_peer",
                "public_key": event.get("public_key", ""),
                "allowed_ips": event.get("allowed_ips", ["0.0.0.0/0"])}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM controls peer authorization
            json!({
                "type": "open_server",
                "port": 51820,
                "base_stack": "wireguard",
                "instruction": "Accept VPN clients and authorize peers with 10.20.30.x addresses"
            }),
            // Script mode: Code-based peer authorization
            json!({
                "type": "open_server",
                "port": 51820,
                "base_stack": "wireguard",
                "event_handlers": [{
                    "event_pattern": "wireguard_peer_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed peer authorization
            json!({
                "type": "open_server",
                "port": 51820,
                "base_stack": "wireguard",
                "event_handlers": [
                    {
                        "event_pattern": "wireguard_peer_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "authorize_peer",
                                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                                "allowed_ips": ["10.20.30.2/32"],
                                "message": "Peer authorized"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for WireguardProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::wireguard::WireguardServer;
            use std::sync::Arc;
            WireguardServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                Arc::new(ctx.llm_client),
                ctx.state,
                ctx.server_id,
                ctx.status_tx,
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
            "authorize_peer" => self.execute_authorize_peer(action),
            "reject_peer" => self.execute_reject_peer(action),
            "set_peer_traffic_limit" => self.execute_set_peer_traffic_limit(action),
            "disconnect_peer" => self.execute_disconnect_peer(action),
            "list_peers" => Ok(ActionResult::NoAction), // Handled by async action executor
            "remove_peer" => Ok(ActionResult::NoAction), // Handled by async action executor
            "get_server_info" => Ok(ActionResult::NoAction), // Handled by async action executor
            // wireguard_add_peer needs the running server instance; it is dispatched
            // through execute_action_with_state, never here. If it lands here there is
            // no server context, so say so rather than silently succeeding.
            "wireguard_add_peer" => Err(anyhow::anyhow!(
                "wireguard_add_peer is server-scoped and must be dispatched through \
                 execute_action_with_state (no running server in context)"
            )),
            _ => Err(anyhow::anyhow!("Unknown WireGuard action: {}", action_type)),
        }
    }

    /// Reach the live server for `wireguard_add_peer`; delegate everything else.
    ///
    /// `wireguard_add_peer` pre-authorizes a peer's public key on the live interface
    /// so a subsequent handshake from that key is accepted (WireGuard drops a
    /// handshake from an unconfigured key). This is the action that turns the
    /// reactive-only model into one where the operator/LLM can authorize a key up
    /// front. It stays FAIL-CLOSED: it adds exactly the key it was given and nothing
    /// else, and with no such call no peer is added and the handshake is dropped.
    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        Box::pin(async move {
            let action_type = action
                .get("type")
                .and_then(|v| v.as_str())
                .context("Missing 'type' field in action")?;

            if action_type != "wireguard_add_peer" {
                // Not live-state; the stateless executor handles it verbatim.
                return self.execute_action(action);
            }

            let public_key = action
                .get("public_key")
                .and_then(|v| v.as_str())
                .context("Missing public_key in wireguard_add_peer")?
                .to_string();

            let allowed_ips = action
                .get("allowed_ips")
                .and_then(|v| v.as_array())
                .context("Missing allowed_ips in wireguard_add_peer")?
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>();

            if allowed_ips.is_empty() {
                return Err(anyhow::anyhow!(
                    "allowed_ips must not be empty - a peer with no allowed IPs can route nothing"
                ));
            }

            let endpoint = action
                .get("endpoint")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok());

            let server_id = server_id.context(
                "wireguard_add_peer is server-scoped and cannot run without a server id",
            )?;

            let server: std::sync::Arc<crate::server::wireguard::WireguardServer> =
                state.server_handle(server_id).await.ok_or_else(|| {
                    anyhow::anyhow!("no running WireGuard server for id {server_id:?}")
                })?;

            // build_peer_config (inside add_peer) fail-closes on a malformed key or
            // bad/empty allowed IPs, so a bad key returns Err rather than touching
            // the interface.
            server
                .add_peer(public_key.clone(), allowed_ips.clone(), endpoint)
                .await?;

            Ok(ActionResult::Custom {
                name: "wireguard_peer_connected".to_string(),
                data: json!({
                    "public_key": public_key,
                    "allowed_ips": allowed_ips,
                    "endpoint": endpoint.map(|e| e.to_string()),
                }),
            })
        })
    }
}

impl WireguardProtocol {
    /// Execute authorize_peer action - allow peer to connect and create tunnel
    fn execute_authorize_peer(&self, action: serde_json::Value) -> Result<ActionResult> {
        let public_key = action
            .get("public_key")
            .and_then(|v| v.as_str())
            .context("Missing public_key in authorize_peer")?
            .to_string();

        let allowed_ips = action
            .get("allowed_ips")
            .and_then(|v| v.as_array())
            .context("Missing allowed_ips in authorize_peer")?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<String>>();

        if allowed_ips.is_empty() {
            return Err(anyhow::anyhow!("allowed_ips must not be empty"));
        }

        let endpoint = action
            .get("endpoint")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Peer authorized");

        // Return authorization details to be executed by server
        Ok(ActionResult::Output(serde_json::to_vec(&json!({
            "action": "authorize_peer",
            "public_key": public_key,
            "allowed_ips": allowed_ips,
            "endpoint": endpoint.map(|e: std::net::SocketAddr| e.to_string()),
            "message": message,
        }))?))
    }

    /// Execute reject_peer action - deny peer connection
    fn execute_reject_peer(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _public_key = action
            .get("public_key")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let _reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Unauthorized");

        // Return rejection notification (no actual action needed for honeypot-style rejection)
        Ok(ActionResult::NoAction)
    }

    /// Execute set_peer_traffic_limit action - configure traffic limits for peer
    fn execute_set_peer_traffic_limit(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _public_key = action
            .get("public_key")
            .and_then(|v| v.as_str())
            .context("Missing public_key")?;

        let _limit_mbps = action.get("limit_mbps").and_then(|v| v.as_u64());

        let _limit_total_mb = action.get("limit_total_mb").and_then(|v| v.as_u64());

        // Note: Traffic limiting would require iptables/tc configuration
        Ok(ActionResult::NoAction)
    }

    /// Execute disconnect_peer action - immediately disconnect a peer
    fn execute_disconnect_peer(&self, action: serde_json::Value) -> Result<ActionResult> {
        let public_key = action
            .get("public_key")
            .and_then(|v| v.as_str())
            .context("Missing public_key")?
            .to_string();

        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Disconnected by admin");

        // Return disconnect command to be executed by server
        Ok(ActionResult::Output(serde_json::to_vec(&json!({
            "action": "disconnect_peer",
            "public_key": public_key,
            "reason": reason,
        }))?))
    }
}

/// Action: Pre-authorize (add) a peer up front, before it handshakes.
///
/// User-triggered (async). This is the action that makes the WireGuard
/// authorize/reject flow reachable: a responder drops a handshake whose static
/// public key is not already configured, so the operator/LLM must add the key
/// first for the handshake to succeed and `wireguard_peer_connected` to fire.
fn add_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "wireguard_add_peer".to_string(),
        description: "Pre-authorize a WireGuard peer by adding its public key and allowed IPs to \
                      the live interface BEFORE it connects. WireGuard drops any handshake from a \
                      key that is not already configured, so use this to authorize a client up \
                      front; the peer's subsequent handshake will then be accepted and raise \
                      wireguard_peer_connected. Fail-closed: without this, an unknown peer's \
                      handshake is dropped and it never appears."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "public_key".to_string(),
                type_hint: "string".to_string(),
                description: "Peer's public key (base64, 44 chars)".to_string(),
                required: true,
            },
            Parameter {
                name: "allowed_ips".to_string(),
                type_hint: "array".to_string(),
                description:
                    "List of allowed IP ranges for this peer (CIDR notation, e.g. 10.20.30.2/32)"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "endpoint".to_string(),
                type_hint: "string".to_string(),
                description: "Optional peer endpoint address (IP:port) for a roaming-fixed peer"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "wireguard_add_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": ["10.20.30.2/32"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WG add_peer {public_key}")
                .with_debug("WG wireguard_add_peer: pubkey={public_key} ips={allowed_ips}"),
        ),
    }
}

/// Action: Authorize peer to connect
fn authorize_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "authorize_peer".to_string(),
        description: "Configure a WireGuard peer on the live interface with the given allowed \
                      IPs. Use this in response to wireguard_peer_connected to pin which VPN \
                      addresses the peer may use. Note: the peer's handshake has already \
                      succeeded by the time this runs - this sets policy, it does not grant \
                      or deny the initial connection."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "public_key".to_string(),
                type_hint: "string".to_string(),
                description: "Peer's public key (base64)".to_string(),
                required: true,
            },
            Parameter {
                name: "allowed_ips".to_string(),
                type_hint: "array".to_string(),
                description:
                    "List of allowed IP ranges for this peer (CIDR notation, e.g. 10.20.30.2/32)"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "endpoint".to_string(),
                type_hint: "string".to_string(),
                description: "Optional peer endpoint address (IP:port)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional authorization message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "authorize_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": ["10.20.30.2/32"],
            "endpoint": "203.0.113.45:51820",
            "message": "Legitimate VPN client authorized"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WG authorize {public_key}")
                .with_debug("WG authorize_peer: pubkey={public_key} ips={allowed_ips}"),
        ),
    }
}

/// Action: Reject peer connection request
fn reject_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_peer".to_string(),
        description: "Remove a WireGuard peer from the interface, refusing it access to the \
                      VPN. Identical in effect to disconnect_peer; use this when the peer \
                      should never have been allowed on."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "public_key".to_string(),
                type_hint: "string".to_string(),
                description: "Peer's public key (base64)".to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Reason for rejection".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "reject_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "reason": "Unauthorized client - unknown public key"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WG reject {public_key}: {reason}")
                .with_debug("WG reject_peer: pubkey={public_key} reason={reason}"),
        ),
    }
}

/// Action: Set traffic limits for a peer
fn set_peer_traffic_limit_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_peer_traffic_limit".to_string(),
        description: "Record an intended traffic limit for a peer. NOT ENFORCED: NetGet only \
                      logs the limit, it does not configure tc/iptables, so the peer's traffic \
                      is unaffected. Use disconnect_peer if the peer must actually be stopped."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "public_key".to_string(),
                type_hint: "string".to_string(),
                description: "Peer's public key (base64)".to_string(),
                required: true,
            },
            Parameter {
                name: "limit_mbps".to_string(),
                type_hint: "number".to_string(),
                description: "Maximum bandwidth in Mbps".to_string(),
                required: false,
            },
            Parameter {
                name: "limit_total_mb".to_string(),
                type_hint: "number".to_string(),
                description: "Total data transfer limit in MB".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "set_peer_traffic_limit",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "limit_mbps": 100,
            "limit_total_mb": 10000
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WG traffic limit {public_key}")
                .with_debug("WG set_peer_traffic_limit: pubkey={public_key} mbps={limit_mbps}"),
        ),
    }
}

/// Action: Disconnect peer immediately
fn disconnect_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect_peer".to_string(),
        description: "Immediately remove a WireGuard peer from the interface, tearing down its \
                      tunnel. The peer can re-handshake unless it is also kept out by policy."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "public_key".to_string(),
                type_hint: "string".to_string(),
                description: "Peer's public key (base64)".to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Reason for disconnection".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "disconnect_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "reason": "Suspicious traffic detected"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WG disconnect {public_key}")
                .with_debug("WG disconnect_peer: pubkey={public_key} reason={reason}"),
        ),
    }
}
