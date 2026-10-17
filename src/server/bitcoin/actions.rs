//! Bitcoin P2P protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use bitcoin::consensus::Encodable;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use serde_json::json;
use std::sync::LazyLock;

/// Bitcoin protocol action handler
/// The network magic for a name the model supplied, or an error naming the accepted values.
///
/// Five executors each carried their own copy of this match, and every copy ended
/// `_ => Magic::BITCOIN`. So `"testnet4"`, `"Testnet"` or any typo produced **mainnet**
/// magic silently: the reply went out with the wrong four leading bytes, the peer dropped it
/// as a foreign network, and nothing anywhere said why. Refusing names the mistake and gives
/// the model something to correct — and refusing is the safe direction here, because the
/// failure it replaces is "answer on mainnet when asked for anything else".
///
/// A *missing* `network` still defaults to mainnet; the parameter is `required: false` and
/// its description says so. It is only an unrecognised value that is an error.
fn magic_for_network(network: &str) -> Result<Magic> {
    match network {
        "mainnet" | "main" => Ok(Magic::BITCOIN),
        "testnet" | "test" => Ok(Magic::TESTNET3),
        "signet" => Ok(Magic::SIGNET),
        "regtest" => Ok(Magic::REGTEST),
        other => Err(anyhow::anyhow!(
            "unknown Bitcoin network '{}': expected one of mainnet (or main), testnet (or \
             test), signet, regtest",
            other
        )),
    }
}

pub struct BitcoinProtocol;

impl BitcoinProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BitcoinProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "network".to_string(),
            type_hint: "string".to_string(),
            description:
                "Bitcoin network: 'mainnet', 'testnet', 'signet', or 'regtest' (default: mainnet)"
                    .to_string(),
            required: false,
            example: json!("mainnet"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_bitcoin_message_action(),
            send_version_action(),
            send_verack_action(),
            send_ping_action(),
            send_pong_action(),
            send_getaddr_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Bitcoin P2P"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_bitcoin_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Bitcoin"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bitcoin", "btc", "p2p", "blockchain"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .well_known_port(8333)
                .implementation("Bitcoin P2P protocol using rust-bitcoin crate for message parsing")
                .llm_control("LLM decides how to respond to all P2P messages (version, getdata, ping, etc.)")
                .e2e_testing("tests/server/bitcoin/{e2e_test,peer_inject_test}.rs, 17 LLM calls, none #[ignore]d. The peer is a raw TcpStream; the `bitcoin` crate encodes and decodes the messages on the test's side, which makes it a **codec, not a peer completing a session** - the same situation as dhcp's in-test RFC 2131 decoder, and why this is not Beta. No bitcoind, no third-party node. This field read 'Bitcoin P2P client (TBD)'. Covered: version/verack handshake, ping/pong, getaddr, a testnet magic check, and the dashboard's injected message and disconnect. Not tested: a real Bitcoin node, block or transaction relay, anything past the handshake.")
                .notes("Not a real full node - LLM controls all responses. Supports mainnet/testnet/signet/regtest; an unrecognised network name is now an error rather than silently answering on mainnet. Stores nothing: no chain, no mempool, no peer database. Message framing is bounded (24-byte header validated before the length field is trusted, 4 MB body cap matching Bitcoin Core), and the `bitcoin` crate's consensus decoding caps its own var-int-counted allocations.")
                .max_inbound_bytes(crate::server::bitcoin::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Bitcoin P2P protocol server (LLM-controlled, not a real full node)"
    }
    fn example_prompt(&self) -> &'static str {
        "Run Bitcoin P2P server on port 8333; respond to version with our own version, handle ping/pong"
    }
    fn group_name(&self) -> &'static str {
        "Blockchain"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: complete the version/verack handshake on connect, no
        // LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "bitcoin_connection_opened":
    actions = [{"type": "send_version", "user_agent": "/NetGet:0.1/"},
               {"type": "send_verack"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles Bitcoin P2P protocol
            json!({
                "type": "open_server",
                "port": 8333,
                "base_stack": "bitcoin",
                "instruction": "Act as Bitcoin P2P node. Respond to version with our version, handle ping/pong",
                "startup_params": {
                    "network": "mainnet"
                }
            }),
            // Script mode: Code-based Bitcoin P2P handling
            json!({
                "type": "open_server",
                "port": 8333,
                "base_stack": "bitcoin",
                "startup_params": {
                    "network": "mainnet"
                },
                "event_handlers": [{
                    "event_pattern": "bitcoin_connection_opened",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed Bitcoin P2P responses
            json!({
                "type": "open_server",
                "port": 8333,
                "base_stack": "bitcoin",
                "startup_params": {
                    "network": "mainnet"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bitcoin_message_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_verack",
                                "network": "mainnet"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for BitcoinProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Extract network from startup_params (default: mainnet)
            let network = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("network"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| "mainnet".to_string());

            use crate::server::bitcoin::BitcoinServer;
            BitcoinServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                network,
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
            "send_bitcoin_message" => self.execute_send_bitcoin_message(action),
            "send_version" => self.execute_send_version(action),
            "send_verack" => self.execute_send_verack(action),
            "send_ping" => self.execute_send_ping(action),
            "send_pong" => self.execute_send_pong(action),
            "send_getaddr" => self.execute_send_getaddr(action),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            // Not offered to the model (it has `close_this_connection`), but the dashboard's
            // "disconnect this peer" injects this generic name through the peer command task,
            // which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Bitcoin action: {}", action_type)),
        }
    }
}

impl BitcoinProtocol {
    /// Execute send_bitcoin_message action (send raw hex-encoded message)
    fn execute_send_bitcoin_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let hex_data = action
            .get("hex_data")
            .and_then(|v| v.as_str())
            .context("Missing 'hex_data' parameter")?;

        let bytes = hex::decode(hex_data).context("Invalid hex data")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Execute send_version action
    fn execute_send_version(&self, action: serde_json::Value) -> Result<ActionResult> {
        let network = action
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet");

        let magic = magic_for_network(network)?;

        // Get optional parameters with defaults
        let version = action
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(70015) as u32;

        let services = action.get("services").and_then(|v| v.as_u64()).unwrap_or(0);

        let timestamp = action
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| {
                crate::utils::clock::SystemTime::now()
                    .duration_since(crate::utils::clock::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            });

        let user_agent = action
            .get("user_agent")
            .and_then(|v| v.as_str())
            .unwrap_or("/NetGet:0.1.0/");

        let start_height = action
            .get("start_height")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        let relay = action
            .get("relay")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Create version message
        let receiver = Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            ServiceFlags::NONE,
        );
        let sender = Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            ServiceFlags::from(services),
        );

        let version_msg = NetworkMessage::Version(VersionMessage {
            version,
            services: ServiceFlags::from(services),
            timestamp,
            receiver,
            sender,
            nonce: rand::random(),
            user_agent: user_agent.to_string(),
            start_height,
            relay,
        });

        // Encode to bytes
        let raw_msg = RawNetworkMessage::new(magic, version_msg);
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .context("Failed to encode version message")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Execute send_verack action
    fn execute_send_verack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let network = action
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet");

        let magic = magic_for_network(network)?;

        let raw_msg = RawNetworkMessage::new(magic, NetworkMessage::Verack);
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .context("Failed to encode verack message")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Execute send_ping action
    fn execute_send_ping(&self, action: serde_json::Value) -> Result<ActionResult> {
        let network = action
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet");

        let magic = magic_for_network(network)?;

        let nonce = action
            .get("nonce")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| rand::random());

        let raw_msg = RawNetworkMessage::new(magic, NetworkMessage::Ping(nonce));
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .context("Failed to encode ping message")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Execute send_pong action
    fn execute_send_pong(&self, action: serde_json::Value) -> Result<ActionResult> {
        let network = action
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet");

        let magic = magic_for_network(network)?;

        let nonce = action
            .get("nonce")
            .and_then(|v| v.as_u64())
            .context("Missing 'nonce' parameter for pong")?;

        let raw_msg = RawNetworkMessage::new(magic, NetworkMessage::Pong(nonce));
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .context("Failed to encode pong message")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Execute send_getaddr action
    fn execute_send_getaddr(&self, action: serde_json::Value) -> Result<ActionResult> {
        let network = action
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet");

        let magic = magic_for_network(network)?;

        let raw_msg = RawNetworkMessage::new(magic, NetworkMessage::GetAddr);
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .context("Failed to encode getaddr message")?;

        Ok(ActionResult::Output(bytes))
    }
}

/// Action definition for send_bitcoin_message
fn send_bitcoin_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bitcoin_message".to_string(),
        description: "ESCAPE HATCH - prefer send_version/send_verack/send_ping/send_pong/\
                      send_getaddr. Sends bytes you supply verbatim, including the 24-byte \
                      header, magic and payload checksum, none of which are computed for you. \
                      Only use this for a message type with no dedicated action."
            .to_string(),
        parameters: vec![Parameter {
            name: "hex_data".to_string(),
            type_hint: "string".to_string(),
            description: "Complete hex-encoded Bitcoin message: magic(4) + command(12) + \
                          length(4) + checksum(4) + payload. Written to the socket as-is."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_bitcoin_message",
            "hex_data": "f9beb4d976657261636b000000000000000000005df6e0e2"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC raw message")
                .with_debug("BTC send_bitcoin_message"),
        ),
    }
}

/// Action definition for send_version
fn send_version_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_version".to_string(),
        description: "Send a Bitcoin version message (handshake)".to_string(),
        parameters: vec![
            Parameter {
                name: "network".to_string(),
                type_hint: "string".to_string(),
                description: "Network: 'mainnet', 'testnet', 'signet', 'regtest'".to_string(),
                required: false,
            },
            Parameter {
                name: "version".to_string(),
                type_hint: "number".to_string(),
                description: "Protocol version (default: 70015)".to_string(),
                required: false,
            },
            Parameter {
                name: "services".to_string(),
                type_hint: "number".to_string(),
                description: "Service flags (default: 0)".to_string(),
                required: false,
            },
            // Read by the executor but declared nowhere, so the model could not control it and
            // every version message claimed the current wall-clock time.
            Parameter {
                name: "timestamp".to_string(),
                type_hint: "number".to_string(),
                description: "Unix timestamp for the version message (default: now). Peers use \
                    it to estimate network-adjusted time."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "user_agent".to_string(),
                type_hint: "string".to_string(),
                description: "User agent string (default: '/NetGet:0.1.0/')".to_string(),
                required: false,
            },
            Parameter {
                name: "start_height".to_string(),
                type_hint: "number".to_string(),
                description: "Blockchain height (default: 0)".to_string(),
                required: false,
            },
            Parameter {
                name: "relay".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to relay transactions (default: false)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_version",
            "network": "mainnet",
            "version": 70015,
            "user_agent": "/NetGet:0.1.0/",
            "start_height": 0,
            "relay": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC version v{version} {user_agent}")
                .with_debug("BTC send_version: version={version} user_agent={user_agent} height={start_height}"),
        ),
    }
}

/// Action definition for send_verack
fn send_verack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_verack".to_string(),
        description: "Send a Bitcoin verack message (acknowledge version)".to_string(),
        parameters: vec![Parameter {
            name: "network".to_string(),
            type_hint: "string".to_string(),
            description: "Network: 'mainnet', 'testnet', 'signet', 'regtest'".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_verack",
            "network": "mainnet"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC verack")
                .with_debug("BTC send_verack: network={network}"),
        ),
    }
}

/// Action definition for send_ping
fn send_ping_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ping".to_string(),
        description: "Send a Bitcoin ping message".to_string(),
        parameters: vec![
            Parameter {
                name: "network".to_string(),
                type_hint: "string".to_string(),
                description: "Network: 'mainnet', 'testnet', 'signet', 'regtest'".to_string(),
                required: false,
            },
            Parameter {
                name: "nonce".to_string(),
                type_hint: "number".to_string(),
                description: "Ping nonce (default: random)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_ping",
            "network": "mainnet",
            "nonce": 123456789
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC ping nonce={nonce}")
                .with_debug("BTC send_ping: nonce={nonce} network={network}"),
        ),
    }
}

/// Action definition for send_pong
fn send_pong_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pong".to_string(),
        description: "Send a Bitcoin pong message (response to ping)".to_string(),
        parameters: vec![
            Parameter {
                name: "network".to_string(),
                type_hint: "string".to_string(),
                description: "Network: 'mainnet', 'testnet', 'signet', 'regtest'".to_string(),
                required: false,
            },
            Parameter {
                name: "nonce".to_string(),
                type_hint: "number".to_string(),
                description: "Nonce from ping message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_pong",
            "network": "mainnet",
            "nonce": 123456789
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC pong nonce={nonce}")
                .with_debug("BTC send_pong: nonce={nonce} network={network}"),
        ),
    }
}

/// Action definition for send_getaddr
fn send_getaddr_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_getaddr".to_string(),
        description: "Send a Bitcoin getaddr message (request peer addresses)".to_string(),
        parameters: vec![Parameter {
            name: "network".to_string(),
            type_hint: "string".to_string(),
            description: "Network: 'mainnet', 'testnet', 'signet', 'regtest'".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_getaddr",
            "network": "mainnet"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC getaddr")
                .with_debug("BTC send_getaddr: network={network}"),
        ),
    }
}

/// Action definition for close_this_connection
fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current Bitcoin P2P connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_this_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BTC close")
                .with_debug("BTC close_this_connection"),
        ),
    }
}

// ============================================================================
// Bitcoin Event Type Constants
// ============================================================================

/// Bitcoin connection opened event
pub static BITCOIN_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bitcoin_connection_opened",
        "New Bitcoin P2P connection established (decide whether to send version or wait)",
        json!({
            "type": "send_version",
            "network": "mainnet",
            "version": 70015
        }),
    )
    .with_actions(vec![send_version_action(), close_this_connection_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("Bitcoin P2P connection opened from {client_ip}")
            .with_debug("Bitcoin P2P connection from {client_ip}:{client_port}")
            .with_trace("Bitcoin connection: {json_pretty(.)}"),
    )
});

/// Bitcoin message received event
pub static BITCOIN_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bitcoin_message_received",
        "Bitcoin P2P message received. Reply with the message this peer expects: verack \
         after their version, pong echoing a ping's nonce, and so on.",
        json!({
            "type": "send_verack",
            "network": "mainnet"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_pong",
        "network": "mainnet",
        "nonce": 123456789
    }))
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of message (version, verack, ping, pong, getdata, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "object".to_string(),
            description: "Parsed message data (structure depends on message type)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_bitcoin_message_action(),
        send_version_action(),
        send_verack_action(),
        send_ping_action(),
        send_pong_action(),
        send_getaddr_action(),
        close_this_connection_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BTC {message_type}")
            .with_debug("Bitcoin {message_type} from {client_ip}:{client_port}")
            .with_trace("Bitcoin message: {json_pretty(.)}"),
    )
});

/// Get Bitcoin event types
pub fn get_bitcoin_event_types() -> Vec<EventType> {
    vec![
        BITCOIN_CONNECTION_OPENED_EVENT.clone(),
        BITCOIN_MESSAGE_RECEIVED_EVENT.clone(),
    ]
}
