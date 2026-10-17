//! BitTorrent DHT protocol actions implementation

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

pub struct TorrentDhtProtocol;

impl TorrentDhtProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentDhtProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            SEND_PING_RESPONSE_ACTION.clone(),
            SEND_FIND_NODE_RESPONSE_ACTION.clone(),
            SEND_GET_PEERS_RESPONSE_ACTION.clone(),
            SEND_ANNOUNCE_PEER_RESPONSE_ACTION.clone(),
            SEND_DHT_ERROR_RESPONSE_ACTION.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Torrent-DHT"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DHT_PING_QUERY_EVENT.clone(),
            DHT_FIND_NODE_QUERY_EVENT.clone(),
            DHT_GET_PEERS_QUERY_EVENT.clone(),
            DHT_ANNOUNCE_PEER_QUERY_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BitTorrent-DHT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["torrent-dht", "dht", "kademlia"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: a BEP 5 KRPC error carrying the fixed WireFailure category text.
            .answers_on_failure()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(6881)
            .implementation("UDP KRPC protocol with bencode encoding")
            .llm_control("DHT query responses (ping, find_node, get_peers)")
            .e2e_testing("tests/server/torrent_dht/{e2e_test,llm_failure_test,bencode_depth_guard_test}.rs, 7 LLM calls, none #[ignore]d. NO third-party DHT client is involved: every query is bencode hand-built with serde_bencode over a raw UdpSocket, which is an independent *reading* of BEP 5 rather than an independent implementation. This field claimed 'Real BitTorrent clients with DHT' and no such client appears anywhere in the tree. Covered: ping/find_node/get_peers round trips, the KRPC error reply on an LLM failure (code 201 vs 202, asserted to leak nothing from netget's internals), and that a bencode depth bomb no longer kills the process. Not tested: a real DHT node, iterative lookup, token validation, IPv6/BEP 32.")
            .notes("Kademlia DHT, BEP 5. Stores nothing - no routing table, no peer table, no announced-peer record; the model answers every query, so a get_peers after an announce_peer knows nothing about it unless the model remembers. A small query can be answered with a large `nodes` or `values` list, so this is a UDP amplifier by construction: replies go only to the datagram's source address, which bounds it to whoever can receive at that address, but the amplification factor itself is whatever the model returns.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent DHT server for distributed peer discovery"
    }
    fn example_prompt(&self) -> &'static str {
        "start a bittorrent dht node on port 6881"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every DHT ping with a pong, no LLM call.
        //
        // `transaction_id` is echoed from the event, and both halves of that matter. It is
        // `required: true`, so `{"type": "send_ping_response"}` — which is what this example
        // used to be — is rejected outright by `execute_send_ping_response` and the script
        // answers nothing at all. And because KRPC correlates only on `t`, a reply carrying
        // anything other than the querying node's own value is discarded by it, so the node
        // waits out its own timeout exactly as if we had stayed silent. This is the
        // UDP-protocol echo rule the root CLAUDE.md states for DNS, STUN and NTP; it applies
        // here for the same reason.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "dht_ping_query":
    actions = [{
        "type": "send_ping_response",
        "transaction_id": event["transaction_id"],
        "node_id": "0123456789abcdef0123456789abcdef01234567",
    }]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles BitTorrent DHT
            json!({
                "type": "open_server",
                "port": 6881,
                "base_stack": "torrent-dht",
                "instruction": "Act as BitTorrent DHT node. Respond to ping, find_node, and get_peers queries"
            }),
            // Script mode: Code-based DHT handling
            json!({
                "type": "open_server",
                "port": 6881,
                "base_stack": "torrent-dht",
                "event_handlers": [{
                    "event_pattern": "dht_ping_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed DHT responses
            json!({
                "type": "open_server",
                "port": 6881,
                "base_stack": "torrent-dht",
                "event_handlers": [{
                    "event_pattern": "dht_ping_query",
                    "handler": {
                        // `{{event.transaction_id}}`, not a hardcoded "aa". A static
                        // handler IS interpolated, and a KRPC reply that does not echo the
                        // querying node's own `t` is discarded by it — so a fixed id means
                        // every client times out, which looks like the server never
                        // answered rather than like a wrong answer.
                        "type": "static",
                        "actions": [{
                            "type": "send_ping_response",
                            "transaction_id": "{{event.transaction_id}}",
                            "node_id": "0123456789abcdef0123456789abcdef01234567"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TorrentDhtProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::torrent_dht::TorrentDhtServer;
            TorrentDhtServer::spawn_with_llm_actions(
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
            .context("Missing 'type' field")?;

        match action_type {
            // announce_peer's reply is a bare `{"id": ...}`, exactly like ping's (BEP 5).
            // It gets its own name so the model is not told to answer an announce with a
            // "ping response".
            "send_ping_response" | "send_announce_peer_response" => {
                self.execute_send_ping_response(action)
            }
            "send_find_node_response" => self.execute_send_find_node_response(action),
            "send_get_peers_response" => self.execute_send_get_peers_response(action),
            "send_dht_error_response" => self.execute_send_error_response(action),
            _ => Err(anyhow::anyhow!("Unknown DHT action: {}", action_type)),
        }
    }
}

impl TorrentDhtProtocol {
    fn execute_send_ping_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = hex::decode(
            action
                .get("transaction_id")
                .and_then(|v| v.as_str())
                .context("Missing transaction_id")?,
        )?;
        let node_id = hex::decode(
            action
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("0000000000000000000000000000000000000000"),
        )?;

        let mut response = std::collections::HashMap::new();
        response.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(transaction_id),
        );
        response.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"r".to_vec()),
        );

        let mut r_dict = std::collections::HashMap::new();
        r_dict.insert(b"id".to_vec(), serde_bencode::value::Value::Bytes(node_id));
        response.insert(b"r".to_vec(), serde_bencode::value::Value::Dict(r_dict));

        let bencode_data = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response))?;
        Ok(ActionResult::Output(bencode_data))
    }

    fn execute_send_find_node_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = hex::decode(
            action
                .get("transaction_id")
                .and_then(|v| v.as_str())
                .context("Missing transaction_id")?,
        )?;
        let node_id = hex::decode(
            action
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("0000000000000000000000000000000000000000"),
        )?;

        let nodes = action
            .get("nodes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|node| {
                        let id = hex::decode(node.get("id")?.as_str()?).ok()?;
                        let ip = node.get("ip")?.as_str()?;
                        // A compact node entry is four IP bytes and a big-endian port, and
                        // the querying client dials whatever it is handed. `as u16` wraps, so
                        // 65536 became 0 and 66079 became 543 - a contact on a port nobody
                        // named. Drop the entry instead; the combinator is already a
                        // filter_map, so one bad node does not cost the whole response.
                        let port = u16::try_from(node.get("port")?.as_u64()?).ok()?;
                        if port == 0 {
                            return None;
                        }
                        let ip_parts: Vec<u8> =
                            ip.split('.').filter_map(|s| s.parse().ok()).collect();
                        if ip_parts.len() != 4 || id.len() != 20 {
                            return None;
                        }

                        let mut compact = id;
                        compact.extend_from_slice(&ip_parts);
                        compact.extend_from_slice(&port.to_be_bytes());
                        Some(compact)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let nodes_bytes: Vec<u8> = nodes.into_iter().flatten().collect();

        let mut response = std::collections::HashMap::new();
        response.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(transaction_id),
        );
        response.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"r".to_vec()),
        );

        let mut r_dict = std::collections::HashMap::new();
        r_dict.insert(b"id".to_vec(), serde_bencode::value::Value::Bytes(node_id));
        r_dict.insert(
            b"nodes".to_vec(),
            serde_bencode::value::Value::Bytes(nodes_bytes),
        );
        response.insert(b"r".to_vec(), serde_bencode::value::Value::Dict(r_dict));

        let bencode_data = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response))?;
        Ok(ActionResult::Output(bencode_data))
    }

    fn execute_send_get_peers_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = hex::decode(
            action
                .get("transaction_id")
                .and_then(|v| v.as_str())
                .context("Missing transaction_id")?,
        )?;
        let node_id = hex::decode(
            action
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("0000000000000000000000000000000000000000"),
        )?;
        let token = action
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or("token")
            .as_bytes()
            .to_vec();

        let mut response = std::collections::HashMap::new();
        response.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(transaction_id),
        );
        response.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"r".to_vec()),
        );

        let mut r_dict = std::collections::HashMap::new();
        r_dict.insert(b"id".to_vec(), serde_bencode::value::Value::Bytes(node_id));
        r_dict.insert(b"token".to_vec(), serde_bencode::value::Value::Bytes(token));

        if let Some(peers_arr) = action.get("peers").and_then(|v| v.as_array()) {
            let peers_bytes: Vec<u8> = peers_arr
                .iter()
                .filter_map(|peer| {
                    let ip = peer.get("ip")?.as_str()?;
                    // Same as send_find_node_response above: a wrapped port is a contact the
                    // peer will dial and nobody is listening on.
                    let port = u16::try_from(peer.get("port")?.as_u64()?).ok()?;
                    if port == 0 {
                        return None;
                    }
                    let ip_parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
                    if ip_parts.len() != 4 {
                        return None;
                    }
                    let mut compact = ip_parts;
                    compact.extend_from_slice(&port.to_be_bytes());
                    Some(compact)
                })
                .flatten()
                .collect();
            r_dict.insert(
                b"values".to_vec(),
                serde_bencode::value::Value::Bytes(peers_bytes),
            );
        }

        response.insert(b"r".to_vec(), serde_bencode::value::Value::Dict(r_dict));

        let bencode_data = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response))?;
        Ok(ActionResult::Output(bencode_data))
    }

    /// KRPC error reply (`y=e`, BEP 5): `{"t": <txn>, "y": "e", "e": [code, message]}`.
    fn execute_send_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let transaction_id = hex::decode(
            action
                .get("transaction_id")
                .and_then(|v| v.as_str())
                .context("Missing transaction_id")?,
        )?;
        let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(201) as i64;
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Generic Error");

        let mut response = std::collections::HashMap::new();
        response.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(transaction_id),
        );
        response.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"e".to_vec()),
        );
        response.insert(
            b"e".to_vec(),
            serde_bencode::value::Value::List(vec![
                serde_bencode::value::Value::Int(code),
                serde_bencode::value::Value::Bytes(message.as_bytes().to_vec()),
            ]),
        );

        let bencode_data = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response))?;
        Ok(ActionResult::Output(bencode_data))
    }
}

/// Fields present on every KRPC query event.
///
/// `transaction_id` is the correlation id: a reply that does not echo it verbatim is
/// discarded by the querying node and the client hangs until its own timeout. It is
/// hex-encoded because the two bytes a client picks are arbitrary and usually not text.
fn common_query_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded KRPC transaction id (`t`). MUST be echoed back \
                          verbatim in the response or the querying node drops the reply."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "The `q` method name as it appeared on the wire (ping, find_node, \
                          get_peers, announce_peer, or something unrecognised)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "id".to_string(),
            type_hint: "string".to_string(),
            description: "Querying node's 20-byte node ID, hex-encoded".to_string(),
            required: false,
        },
    ]
}

pub static DHT_PING_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dht_ping_query",
        "DHT node is checking whether we are alive",
        json!({
            "type": "send_ping_response",
            "transaction_id": "6161",
            "node_id": "0123456789abcdef0123456789abcdef01234567"
        }),
    )
    .with_parameters(common_query_parameters())
    .with_actions(vec![
        SEND_PING_RESPONSE_ACTION.clone(),
        SEND_DHT_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} DHT ping ({duration_ms}ms)")
            .with_debug("DHT ping from {client_ip}")
            .with_trace("DHT ping: {json_pretty(.)}"),
    )
});

pub static DHT_FIND_NODE_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_query_parameters();
    parameters.push(Parameter {
        name: "target".to_string(),
        type_hint: "string".to_string(),
        description: "20-byte node ID being looked up, hex-encoded".to_string(),
        required: false,
    });

    EventType::new(
        "dht_find_node_query",
        "DHT node is asking for the nodes closest to a target ID",
        json!({
            "type": "send_find_node_response",
            "transaction_id": "6161",
            "node_id": "0123456789abcdef0123456789abcdef01234567",
            "nodes": []
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_FIND_NODE_RESPONSE_ACTION.clone(),
        SEND_DHT_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} DHT find_node ({duration_ms}ms)")
            .with_debug("DHT find_node from {client_ip}: target={target}")
            .with_trace("DHT find_node: {json_pretty(.)}"),
    )
});

pub static DHT_GET_PEERS_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_query_parameters();
    parameters.push(Parameter {
        name: "info_hash".to_string(),
        type_hint: "string".to_string(),
        description: "20-byte torrent info hash being looked up, hex-encoded".to_string(),
        required: false,
    });

    EventType::new(
        "dht_get_peers_query",
        "DHT node is asking which peers are downloading a torrent",
        json!({
            "type": "send_get_peers_response",
            "transaction_id": "6161",
            "node_id": "0123456789abcdef0123456789abcdef01234567",
            "token": "aoeusnth",
            "peers": [{"ip": "127.0.0.1", "port": 51413}]
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_GET_PEERS_RESPONSE_ACTION.clone(),
        SEND_DHT_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} DHT get_peers ({duration_ms}ms)")
            .with_debug("DHT get_peers from {client_ip}: info_hash={info_hash}")
            .with_trace("DHT get_peers: {json_pretty(.)}"),
    )
});

pub static DHT_ANNOUNCE_PEER_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_query_parameters();
    parameters.extend(vec![
        Parameter {
            name: "info_hash".to_string(),
            type_hint: "string".to_string(),
            description: "20-byte torrent info hash being announced, hex-encoded".to_string(),
            required: false,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Port the announcing peer is listening on".to_string(),
            required: false,
        },
        Parameter {
            name: "token".to_string(),
            type_hint: "string".to_string(),
            description: "Token this node handed out in an earlier get_peers reply. \
                          Nothing validates it; reject with send_dht_error_response \
                          (code 203) if it is wrong."
                .to_string(),
            required: false,
        },
    ]);

    EventType::new(
        "dht_announce_peer_query",
        "DHT node is announcing that it is downloading a torrent",
        json!({
            "type": "send_announce_peer_response",
            "transaction_id": "6161",
            "node_id": "0123456789abcdef0123456789abcdef01234567"
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_ANNOUNCE_PEER_RESPONSE_ACTION.clone(),
        SEND_DHT_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} DHT announce_peer ({duration_ms}ms)")
            .with_debug("DHT announce_peer from {client_ip}: info_hash={info_hash} port={port}")
            .with_trace("DHT announce_peer: {json_pretty(.)}"),
    )
});

/// `transaction_id` and `node_id`, shared by every KRPC reply action.
fn reply_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded transaction id from the query — echo the event's \
                          `transaction_id` verbatim, because a reply carrying any other \
                          value is discarded by the querying node. A static handler writes \
                          the literal \"{{event.transaction_id}}\", which is substituted \
                          before the action runs; an LLM answer must carry the real hex."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "node_id".to_string(),
            type_hint: "string".to_string(),
            description: "This node's own 20-byte ID, hex-encoded (40 chars). Defaults to \
                          all zeros, which real nodes treat as suspicious; pick a stable \
                          random ID instead."
                .to_string(),
            required: false,
        },
    ]
}

pub static SEND_PING_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_ping_response".to_string(),
        description: "Send DHT ping response".to_string(),
        parameters: reply_parameters(),
        example: json!({"type": "send_ping_response", "transaction_id": "6161", "node_id": "0123456789abcdef0123456789abcdef01234567"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHT ping response")
                .with_debug("DHT ping response: node_id={node_id}"),
        ),
    }
});

pub static SEND_FIND_NODE_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_find_node_response".to_string(),
        description: "Send DHT find_node response carrying the closest nodes we know of"
            .to_string(),
        parameters: {
            let mut p = reply_parameters();
            p.push(Parameter {
                name: "nodes".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {id (40 hex chars), ip (IPv4 dotted quad), port}. \
                              Entries with a non-20-byte id or a non-IPv4 address are \
                              silently dropped; an empty array is a valid answer."
                    .to_string(),
                required: false,
            });
            p
        },
        example: json!({"type": "send_find_node_response", "transaction_id": "6161", "node_id": "0123456789abcdef0123456789abcdef01234567", "nodes": [{"id": "0123456789abcdef0123456789abcdef01234567", "ip": "192.168.1.100", "port": 6881}]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHT find_node: {nodes_len} nodes")
                .with_debug("DHT find_node response: {nodes_len} nodes"),
        ),
    }
});

pub static SEND_GET_PEERS_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_get_peers_response".to_string(),
        description: "Send DHT get_peers response with the peers we know for the info_hash"
            .to_string(),
        parameters: {
            let mut p = reply_parameters();
            p.extend(vec![
                Parameter {
                    name: "token".to_string(),
                    type_hint: "string".to_string(),
                    description: "Opaque token the querier must echo in a later \
                                  announce_peer (default: \"token\"). Sent as plain text, \
                                  not hex."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "peers".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of {ip (IPv4 dotted quad), port}. Omit the key \
                                  entirely to signal 'no peers known'; non-IPv4 entries \
                                  are dropped."
                        .to_string(),
                    required: false,
                },
            ]);
            p
        },
        example: json!({"type": "send_get_peers_response", "transaction_id": "6161", "node_id": "0123456789abcdef0123456789abcdef01234567", "token": "aoeusnth", "peers": [{"ip": "192.168.1.100", "port": 51413}]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHT get_peers: {peers_len} peers")
                .with_debug("DHT get_peers response: {peers_len} peers"),
        ),
    }
});

pub static SEND_ANNOUNCE_PEER_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_announce_peer_response".to_string(),
        description: "Acknowledge an announce_peer query. The reply body is just this \
                      node's ID (BEP 5); nothing about the announcement is stored."
            .to_string(),
        parameters: reply_parameters(),
        example: json!({"type": "send_announce_peer_response", "transaction_id": "6161", "node_id": "0123456789abcdef0123456789abcdef01234567"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHT announce_peer ack")
                .with_debug("DHT announce_peer response: node_id={node_id}"),
        ),
    }
});

pub static SEND_DHT_ERROR_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_dht_error_response".to_string(),
        description: "Reject a query with a KRPC error (`y=e`)".to_string(),
        parameters: vec![
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "string".to_string(),
                description: "Hex-encoded transaction id from the query; use \
                              \"{{event.transaction_id}}\""
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "BEP 5 error code: 201 generic (default), 202 server error, \
                              203 protocol error, 204 method unknown"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error text".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_dht_error_response", "transaction_id": "6161", "code": 204, "message": "Method Unknown"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DHT error {code}: {message}")
                .with_debug("DHT error response: code={code} message={message}"),
        ),
    }
});
