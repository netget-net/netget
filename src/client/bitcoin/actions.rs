//! Bitcoin RPC client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Bitcoin RPC client connected event
pub static BITCOIN_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bitcoin_connected",
        "Bitcoin RPC client initialized and ready to execute commands",
        json!({"type": "execute_rpc", "method": "getblockchaininfo", "params": []}),
    )
    .with_parameters(vec![Parameter {
        name: "rpc_url".to_string(),
        type_hint: "string".to_string(),
        description: "Bitcoin Core RPC URL".to_string(),
        required: true,
    }])
});

/// Bitcoin RPC client response received event
pub static BITCOIN_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bitcoin_response_received",
        "Response received from Bitcoin Core RPC",
        json!({"type": "execute_rpc", "method": "getblock", "params": ["00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"]}),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "RPC method that was called".to_string(),
            required: true,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "any".to_string(),
            description: "The result from the RPC call".to_string(),
            required: false,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "any".to_string(),
            description: "Error message if the RPC call failed".to_string(),
            required: false,
        },
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code".to_string(),
            required: true,
        },
    ])
});

/// Bitcoin RPC client protocol action handler
pub struct BitcoinClientProtocol;

impl BitcoinClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BitcoinClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "rpc_user".to_string(),
                description: "Bitcoin RPC username".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("bitcoinrpc"),
                default: None,
            },
            ParameterDefinition {
                name: "rpc_password".to_string(),
                description: "Bitcoin RPC password".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("password123"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            // Blockchain queries
            ActionDefinition {
                name: "get_blockchain_info".to_string(),
                description: "Get blockchain information (chain, blocks, difficulty, etc.)"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_blockchain_info"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_block_hash".to_string(),
                description: "Get block hash by height".to_string(),
                parameters: vec![Parameter {
                    name: "height".to_string(),
                    type_hint: "number".to_string(),
                    description: "Block height".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_block_hash",
                    "height": 700000
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_block".to_string(),
                description: "Get block details by hash".to_string(),
                parameters: vec![
                    Parameter {
                        name: "block_hash".to_string(),
                        type_hint: "string".to_string(),
                        description: "Block hash (hex)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "verbosity".to_string(),
                        type_hint: "number".to_string(),
                        description: "Verbosity level (0=hex, 1=json, 2=json with tx details)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "get_block",
                    "block_hash": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                    "verbosity": 1
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_transaction".to_string(),
                description: "Get transaction details by txid".to_string(),
                parameters: vec![Parameter {
                    name: "txid".to_string(),
                    type_hint: "string".to_string(),
                    description: "Transaction ID (hex)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_transaction",
                    "txid": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_mempool_info".to_string(),
                description: "Get mempool information (size, bytes, usage, etc.)".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_mempool_info"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_raw_mempool".to_string(),
                description: "Get list of transaction IDs in mempool".to_string(),
                parameters: vec![Parameter {
                    name: "verbose".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Return verbose object for each transaction".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "get_raw_mempool",
                    "verbose": false
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_mining_info".to_string(),
                description: "Get mining information (network hashrate, difficulty, etc.)"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_mining_info"
                }),
                log_template: None,
            },
            // Network queries
            ActionDefinition {
                name: "get_network_info".to_string(),
                description: "Get network information (version, connections, protocols, etc.)"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_network_info"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_peer_info".to_string(),
                description: "Get information about connected peers".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_peer_info"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_connection_count".to_string(),
                description: "Get number of connections to other nodes".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_connection_count"
                }),
                log_template: None,
            },
            // Wallet operations
            ActionDefinition {
                name: "get_wallet_info".to_string(),
                description: "Get wallet information (balance, txcount, etc.)".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_wallet_info"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_balance".to_string(),
                description: "Get wallet balance".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_balance"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_transactions".to_string(),
                description: "List wallet transactions".to_string(),
                parameters: vec![Parameter {
                    name: "count".to_string(),
                    type_hint: "number".to_string(),
                    description: "Number of transactions to list".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "list_transactions",
                    "count": 10
                }),
                log_template: None,
            },
            // Generic RPC call
            ActionDefinition {
                name: "execute_rpc".to_string(),
                description: "Execute a custom Bitcoin RPC command".to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "RPC method name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "params".to_string(),
                        type_hint: "array".to_string(),
                        description: "RPC parameters (array)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "execute_rpc",
                    "method": "getbestblockhash",
                    "params": []
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the Bitcoin RPC server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "execute_rpc".to_string(),
            description: "Execute another RPC command in response to received data".to_string(),
            parameters: vec![
                Parameter {
                    name: "method".to_string(),
                    type_hint: "string".to_string(),
                    description: "RPC method name".to_string(),
                    required: true,
                },
                Parameter {
                    name: "params".to_string(),
                    type_hint: "array".to_string(),
                    description: "RPC parameters".to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "execute_rpc",
                "method": "getblock",
                "params": ["00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"]
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> Bitcoin RPC {method}")
                    .with_debug("Bitcoin execute_rpc: method={method}"),
            ),
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "Bitcoin"
    }
    /// Clone the statics the client actually emits, rather than rebuilding them.
    ///
    /// This used to construct a second, parameterless pair. `get_event_types()` is the copy
    /// the model is shown — the statics are used only at the emit site — so every field
    /// `with_parameters` declares on them was invisible to it. Two definitions of one event
    /// drift; one cannot. (`torrent_tracker`'s client is the protocol that already had this
    /// right, and says so in its own comment.)
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BITCOIN_CLIENT_CONNECTED_EVENT.clone(),
            BITCOIN_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>JSON-RPC>Bitcoin"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bitcoin",
            "btc",
            "bitcoin rpc",
            "bitcoin client",
            "blockchain",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("JSON-RPC over HTTP to Bitcoin Core")
            .llm_control(
                "Full control over Bitcoin RPC commands (blockchain, wallet, network queries)",
            )
            .e2e_testing("Bitcoin Core regtest node or testnet")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Bitcoin RPC client for blockchain queries and wallet operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Bitcoin Core at http://user:pass@localhost:8332 and get blockchain info"
    }
    fn group_name(&self) -> &'static str {
        "Blockchain"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles Bitcoin RPC queries
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8332",
                "base_stack": "bitcoin",
                "instruction": "Connect to Bitcoin Core and get blockchain info",
                "startup_params": {
                    "rpc_user": "bitcoinrpc",
                    "rpc_password": "password"
                }
            }),
            // Script mode: Code-based Bitcoin RPC handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8332",
                "base_stack": "bitcoin",
                "startup_params": {
                    "rpc_user": "bitcoinrpc",
                    "rpc_password": "password"
                },
                "event_handlers": [{
                    "event_pattern": "bitcoin_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<bitcoin_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed Bitcoin RPC action
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8332",
                "base_stack": "bitcoin",
                "startup_params": {
                    "rpc_user": "bitcoinrpc",
                    "rpc_password": "password"
                },
                "event_handlers": [{
                    "event_pattern": "bitcoin_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "get_blockchain_info"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for BitcoinClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::bitcoin::BitcoinClient;
            // Declared and, until now, read by nothing. bitcoind's RPC is auth-mandatory, so
            // a client that never sends a credential cannot complete a single call against a
            // real node.
            let rpc_user = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("rpc_user"))
                .transpose()?
                .flatten();
            let rpc_password = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("rpc_password"))
                .transpose()?
                .flatten();

            BitcoinClient::connect_with_llm_actions(
                ctx.remote_addr,
                rpc_user,
                rpc_password,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "get_blockchain_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getblockchaininfo",
                    "params": []
                }),
            }),
            "get_block_hash" => {
                let height = action
                    .get("height")
                    .and_then(|v| v.as_u64())
                    .context("Missing or invalid 'height' field")?;

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": "getblockhash",
                        "params": [height]
                    }),
                })
            }
            "get_block" => {
                let block_hash = action
                    .get("block_hash")
                    .and_then(|v| v.as_str())
                    .context("Missing 'block_hash' field")?;

                let verbosity = action
                    .get("verbosity")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": "getblock",
                        "params": [block_hash, verbosity]
                    }),
                })
            }
            "get_transaction" => {
                let txid = action
                    .get("txid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'txid' field")?;

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": "getrawtransaction",
                        "params": [txid, true]
                    }),
                })
            }
            "get_mempool_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getmempoolinfo",
                    "params": []
                }),
            }),
            "get_raw_mempool" => {
                let verbose = action
                    .get("verbose")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": "getrawmempool",
                        "params": [verbose]
                    }),
                })
            }
            "get_mining_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getmininginfo",
                    "params": []
                }),
            }),
            "get_network_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getnetworkinfo",
                    "params": []
                }),
            }),
            "get_peer_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getpeerinfo",
                    "params": []
                }),
            }),
            "get_connection_count" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getconnectioncount",
                    "params": []
                }),
            }),
            "get_wallet_info" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getwalletinfo",
                    "params": []
                }),
            }),
            "get_balance" => Ok(ClientActionResult::Custom {
                name: "bitcoin_rpc".to_string(),
                data: json!({
                    "method": "getbalance",
                    "params": []
                }),
            }),
            "list_transactions" => {
                let count = action.get("count").and_then(|v| v.as_u64()).unwrap_or(10);

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": "listtransactions",
                        "params": ["*", count]
                    }),
                })
            }
            "execute_rpc" => {
                let method = action
                    .get("method")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method' field")?
                    .to_string();

                let params = action
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                Ok(ClientActionResult::Custom {
                    name: "bitcoin_rpc".to_string(),
                    data: json!({
                        "method": method,
                        "params": params
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Bitcoin RPC client action: {}",
                action_type
            )),
        }
    }
}
