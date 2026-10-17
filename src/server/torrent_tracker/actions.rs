//! BitTorrent Tracker protocol actions implementation

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

pub struct TorrentTrackerProtocol;

impl TorrentTrackerProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorrentTrackerProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            SEND_ANNOUNCE_RESPONSE_ACTION.clone(),
            SEND_SCRAPE_RESPONSE_ACTION.clone(),
            SEND_ERROR_RESPONSE_ACTION.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Torrent-Tracker"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TRACKER_ANNOUNCE_REQUEST_EVENT.clone(),
            TRACKER_SCRAPE_REQUEST_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>BitTorrent-Tracker"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["torrent-tracker", "tracker", "bittorrent-tracker"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(6969)
            .implementation("HTTP server with bencode response encoding (serde_bencode)")
            .llm_control("Peer list generation, announce/scrape responses")
            .e2e_testing(
                "REAL THIRD-PARTY CLIENT: aria2c 1.37.0 (a C++ BitTorrent implementation) in \
                 tests/server/torrent_tracker/real_client_test.rs. NOT #[ignore]d and NOT \
                 skip-gated - both tests FAIL, naming `brew install aria2`, when the binary is \
                 absent. Not circular: the server hand-rolls its HTTP on a raw TcpListener and \
                 encodes with serde_bencode; aria2 links neither. aria2 announces with its own \
                 info_hash and peer_id (the mock rule MATCHES ON BOTH, so a percent-decode or \
                 hex-encode error means the rule never fires and the test fails in both halves), \
                 and then DECODES OUR COMPACT PEER LIST - a bencode byte string, six bytes per \
                 peer, four address octets plus a big-endian port, with nothing self-describing \
                 in it - which the test asserts by requiring aria2 to dial 10.0.0.1:6881 AND \
                 10.0.0.2:6882, so a wrong byte order, stride or length loses a peer and fails. \
                 `compact=1` is HARDCODED in aria2 and is the branch a real swarm always takes; \
                 no earlier test drove it against a real client. The second test asserts aria2 \
                 printing `Tracker returned failure reason: <our text>`, i.e. its own parse of \
                 our bencoded refusal dict inside an HTTP 200. \
                 This field previously claimed 'Real BitTorrent clients (transmission, aria2)' \
                 when nothing in the tree referenced either, and was then corrected to say no \
                 real client existed; aria2 is now genuinely driven. Alongside: e2e_test, \
                 llm_failure_test and peer_inject_test cover announce/scrape round trips, a \
                 send_error_response refusal, connection stats and the LLM-failure reply \
                 (503/500 + bencoded `failure reason`, asserted to leak nothing internal). \
                 NOT PROVEN: the DICTIONARY peer form against a real client (aria2 can parse it \
                 but never requests it, so only hand-written tests reach that branch); IPv6 and \
                 BEP 7 `peers6`, which are NOT IMPLEMENTED; multi-info_hash scrape, and /scrape \
                 against a real client at all, since aria2 does not issue one on its own; a \
                 completed download, there being no real swarm; and the 400/408 paths."
            )
            .notes("Bencode<->JSON conversion, compact peer format. Stores nothing: peers, swarm counts and scrape statistics all come from the model, so successive announces are not correlated unless the model correlates them.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BitTorrent Tracker server for coordinating peers (announce/scrape)"
    }
    fn example_prompt(&self) -> &'static str {
        "start a bittorrent tracker on port 6969"
    }
    fn group_name(&self) -> &'static str {
        "P2P"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every announce with an empty peer list and a
        // 30-minute interval, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "tracker_announce_request":
    actions = [{"type": "send_announce_response", "interval": 1800,
                "complete": 0, "incomplete": 0, "peers": []}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles BitTorrent tracker
            json!({
                "type": "open_server",
                "port": 6969,
                "base_stack": "torrent-tracker",
                "instruction": "Act as BitTorrent tracker. Track peers and respond to announce/scrape requests"
            }),
            // Script mode: Code-based tracker handling
            json!({
                "type": "open_server",
                "port": 6969,
                "base_stack": "torrent-tracker",
                "event_handlers": [{
                    "event_pattern": "tracker_announce_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed tracker responses
            json!({
                "type": "open_server",
                "port": 6969,
                "base_stack": "torrent-tracker",
                "event_handlers": [{
                    "event_pattern": "tracker_announce_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_announce_response",
                            "interval": 1800,
                            "complete": 10,
                            "incomplete": 5,
                            "compact": "{{event.compact}}",
                            "peers": [{"ip": "127.0.0.1", "port": 51413}]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TorrentTrackerProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::torrent_tracker::TorrentTrackerServer;
            TorrentTrackerServer::spawn_with_llm_actions(
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
            "send_announce_response" => self.execute_send_announce_response(action),
            "send_scrape_response" => self.execute_send_scrape_response(action),
            "send_error_response" => self.execute_send_error_response(action),
            // Not advertised to the model — a tracker response already carries
            // `Connection: close` and the session ends on its own, so there is nothing for
            // the model to decide here. It exists because the dashboard's
            // `[ disconnect this peer ]` runs the protocol's **own** `close_connection`
            // through the peer handle, and without an arm the operator's only way to reach a
            // parked announce would fail as an unknown action.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!(
                "Unknown BitTorrent Tracker action: {}",
                action_type
            )),
        }
    }
}

/// Interpret a JSON value as a BitTorrent "compact" flag.
///
/// Clients send `compact=1` in the query string, so the value reaching an action via
/// `{{event.compact}}` is the number 1, not `true`. Accept both spellings (and the
/// string forms a model is liable to produce) rather than silently falling back to the
/// dictionary format that most clients reject.
fn is_compact(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_u64().is_some_and(|n| n != 0),
        Some(serde_json::Value::String(s)) => {
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        _ => false,
    }
}

impl TorrentTrackerProtocol {
    fn execute_send_announce_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let interval = action
            .get("interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(1800) as i64;
        let complete = action.get("complete").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let incomplete = action
            .get("incomplete")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as i64;
        let compact = is_compact(action.get("compact"));

        let peer_entries = action
            .get("peers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // BEP 23: `compact=1` replaces the list of dictionaries with a byte string of
        // 6-byte entries (4-byte IPv4 + 2-byte big-endian port). Nearly every real client
        // (transmission, libtorrent, aria2) asks for compact and several refuse the
        // dictionary form outright, so honouring the flag is what makes this tracker
        // usable by anything other than a hand-written test client.
        let peers_value = if compact {
            let mut bytes = Vec::with_capacity(peer_entries.len() * 6);
            for peer in &peer_entries {
                let Some(ip) = peer.get("ip").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(port) = peer.get("port").and_then(|v| v.as_u64()) else {
                    continue;
                };
                let Ok(std::net::IpAddr::V4(addr)) = ip.parse::<std::net::IpAddr>() else {
                    // IPv6 peers need BEP 7's separate `peers6` key; skip rather than
                    // emit a malformed 6-byte entry.
                    continue;
                };
                bytes.extend_from_slice(&addr.octets());
                bytes.extend_from_slice(&(port as u16).to_be_bytes());
            }
            serde_bencode::value::Value::Bytes(bytes)
        } else {
            let peers = peer_entries
                .iter()
                .filter_map(|peer| {
                    let ip = peer.get("ip").and_then(|v| v.as_str())?.to_string();
                    let port = peer.get("port").and_then(|v| v.as_u64())? as i64;

                    let mut dict = std::collections::HashMap::new();
                    // `peer id` is optional in the dictionary model (BEP 3) and a model
                    // that omits it should still get a well-formed peer entry.
                    //
                    // It is hex-decoded when it is valid 40-character hex, because that is
                    // the form the *event* reports an inbound `peer_id` in, and echoing the
                    // event's value is the obvious thing for a model to do. Writing those
                    // characters through as text put 40 bytes on the wire where BEP 3 wants
                    // 20 — the `send_tcp_data` defect shape. A value that is not 40-char hex
                    // is a literal peer id (`-TR2940-abcdefghijkl`, which real clients send
                    // as raw ASCII) and goes through unchanged; the two are told apart by
                    // decoding rather than by a flag, because only one of them can be both
                    // 40 characters long and valid hex.
                    if let Some(peer_id) = peer.get("peer_id").and_then(|v| v.as_str()) {
                        let bytes = match hex::decode(peer_id) {
                            Ok(decoded) if peer_id.len() == 40 => decoded,
                            _ => peer_id.as_bytes().to_vec(),
                        };
                        dict.insert(
                            b"peer id".to_vec(),
                            serde_bencode::value::Value::Bytes(bytes),
                        );
                    }
                    dict.insert(
                        b"ip".to_vec(),
                        serde_bencode::value::Value::Bytes(ip.into_bytes()),
                    );
                    dict.insert(b"port".to_vec(), serde_bencode::value::Value::Int(port));
                    Some(serde_bencode::value::Value::Dict(dict))
                })
                .collect::<Vec<_>>();
            serde_bencode::value::Value::List(peers)
        };

        let mut response_dict = std::collections::HashMap::new();
        response_dict.insert(
            b"interval".to_vec(),
            serde_bencode::value::Value::Int(interval),
        );
        response_dict.insert(
            b"complete".to_vec(),
            serde_bencode::value::Value::Int(complete),
        );
        response_dict.insert(
            b"incomplete".to_vec(),
            serde_bencode::value::Value::Int(incomplete),
        );
        response_dict.insert(b"peers".to_vec(), peers_value);

        let bencode_data =
            serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response_dict))?;
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bencode_data.len()
        );
        let mut full_response = http_response.into_bytes();
        full_response.extend_from_slice(&bencode_data);

        Ok(ActionResult::Output(full_response))
    }

    fn execute_send_scrape_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // `files` is documented and modelled two ways and both appear in the wild:
        //   {"<info_hash hex>": {complete, downloaded, incomplete}, ...}
        //   [{"info_hash": "<hex>", complete, downloaded, incomplete}, ...]
        // The executor used to accept only the first, so the array form documented in
        // CLAUDE.md (and used by the E2E test) silently produced an empty `files` dict.
        let entries: Vec<(String, &serde_json::Value)> = match action.get("files") {
            Some(serde_json::Value::Object(obj)) => {
                obj.iter().map(|(k, v)| (k.clone(), v)).collect()
            }
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|entry| {
                    let hash = entry.get("info_hash").and_then(|v| v.as_str())?;
                    Some((hash.to_string(), entry))
                })
                .collect(),
            _ => Vec::new(),
        };

        let mut files = std::collections::HashMap::new();
        for (info_hash_hex, stats) in entries {
            let Ok(info_hash) = hex::decode(&info_hash_hex) else {
                continue;
            };
            let complete = stats.get("complete").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
            let downloaded = stats
                .get("downloaded")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as i64;
            let incomplete = stats
                .get("incomplete")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as i64;

            let mut stats_dict = std::collections::HashMap::new();
            stats_dict.insert(
                b"complete".to_vec(),
                serde_bencode::value::Value::Int(complete),
            );
            stats_dict.insert(
                b"downloaded".to_vec(),
                serde_bencode::value::Value::Int(downloaded),
            );
            stats_dict.insert(
                b"incomplete".to_vec(),
                serde_bencode::value::Value::Int(incomplete),
            );
            files.insert(info_hash, serde_bencode::value::Value::Dict(stats_dict));
        }

        let mut response_dict = std::collections::HashMap::new();
        response_dict.insert(b"files".to_vec(), serde_bencode::value::Value::Dict(files));

        let bencode_data =
            serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response_dict))?;
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bencode_data.len()
        );
        let mut full_response = http_response.into_bytes();
        full_response.extend_from_slice(&bencode_data);

        Ok(ActionResult::Output(full_response))
    }

    fn execute_send_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // The action definition, CLAUDE.md and the E2E test all said `failure_reason`
        // (matching the bencode key BEP 3 defines) while the executor read `error`, so
        // every documented use produced the literal string "Unknown error". Accept both.
        // `failure_reason` is declared `required: true`, so it is enforced rather than
        // defaulted. It used to fall back to the literal string "Unknown error", which is
        // then what the client displays before it stops announcing to this tracker — a
        // refusal that says nothing is barely better than no refusal, and the declaration
        // promised the model it would be told when it left the field out.
        let error_message = action
            .get("failure_reason")
            .or_else(|| action.get("error"))
            .and_then(|v| v.as_str())
            .context(
                "send_error_response requires 'failure_reason' (alias 'error'): the text the \
                 client displays before it stops announcing to this tracker",
            )?;

        let mut response_dict = std::collections::HashMap::new();
        response_dict.insert(
            b"failure reason".to_vec(),
            serde_bencode::value::Value::Bytes(error_message.as_bytes().to_vec()),
        );

        let bencode_data =
            serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response_dict))?;
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bencode_data.len()
        );
        let mut full_response = http_response.into_bytes();
        full_response.extend_from_slice(&bencode_data);

        Ok(ActionResult::Output(full_response))
    }
}

/// Fields every tracker request event carries.
///
/// `parse_http_request` guarantees `request_type`, `path` and `compact` are always
/// present so that a static handler can reference `{{event.compact}}` without the
/// interpolator failing on a client that omitted the query parameter.
fn common_request_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "request_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"announce\", \"scrape\" or \"unknown\"".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path including the query string".to_string(),
            required: true,
        },
        Parameter {
            name: "info_hash".to_string(),
            type_hint: "string".to_string(),
            description: "Torrent info hash, hex-encoded (40 chars). Echo it back as the \
                          key of a scrape `files` entry."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "compact".to_string(),
            type_hint: "number".to_string(),
            description: "1 if the client wants BEP 23 compact peers, 0 otherwise. \
                          Always present; pass it straight through to the response action."
                .to_string(),
            required: true,
        },
    ]
}

pub static TRACKER_ANNOUNCE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_request_parameters();
    parameters.extend(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Announcing peer's ID, hex-encoded (40 chars)".to_string(),
            required: false,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Port the announcing peer listens on".to_string(),
            required: false,
        },
        Parameter {
            name: "uploaded".to_string(),
            type_hint: "number".to_string(),
            description: "Bytes uploaded so far".to_string(),
            required: false,
        },
        Parameter {
            name: "downloaded".to_string(),
            type_hint: "number".to_string(),
            description: "Bytes downloaded so far".to_string(),
            required: false,
        },
        Parameter {
            name: "left".to_string(),
            type_hint: "number".to_string(),
            description: "Bytes still needed. 0 means the peer is a seeder.".to_string(),
            required: false,
        },
        Parameter {
            name: "event".to_string(),
            type_hint: "string".to_string(),
            description: "\"started\", \"completed\", \"stopped\" or absent".to_string(),
            required: false,
        },
        Parameter {
            name: "numwant".to_string(),
            type_hint: "number".to_string(),
            description: "How many peers the client would like back".to_string(),
            required: false,
        },
    ]);

    EventType::new(
        "tracker_announce_request",
        "BitTorrent client announced itself and is asking for peers",
        // Concrete, not `"{{event.compact}}"`. A `response_example` is shown to the *model*,
        // and `{{...}}` is interpolated only for static handlers — so the placeholder
        // reached `is_compact` as text, matched nothing, and silently produced the
        // dictionary peer form that real clients refuse. The static-handler example in
        // `get_startup_examples` keeps the placeholder, where it does work.
        json!({
            "type": "send_announce_response",
            "interval": 1800,
            "complete": 1,
            "incomplete": 0,
            "compact": 1,
            "peers": [{"ip": "127.0.0.1", "port": 51413}]
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_ANNOUNCE_RESPONSE_ACTION.clone(),
        SEND_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_error_response",
        "failure_reason": "This tracker does not serve that torrent"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT announce {event} ({duration_ms}ms)")
            .with_debug("BT tracker announce from {client_ip}: event={event}")
            .with_trace("BT announce: {json_pretty(.)}"),
    )
});

pub static TRACKER_SCRAPE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tracker_scrape_request",
        "BitTorrent client asked for torrent statistics",
        // The array form, and a concrete info_hash. A `{{...}}` placeholder used as an
        // object *key* is worse than one used as a value: `hex::decode` rejects it, the
        // entry is dropped, and the client gets an empty `files` dictionary under a 200 OK.
        // Nothing errors, so the model has no way to learn it did not work. Copy the
        // event's own 40-character `info_hash` into the value here.
        json!({
            "type": "send_scrape_response",
            "files": [{
                "info_hash": "1111111111111111111111111111111111111111",
                "complete": 1, "downloaded": 1, "incomplete": 0
            }]
        }),
    )
    .with_parameters(common_request_parameters())
    .with_actions(vec![
        SEND_SCRAPE_RESPONSE_ACTION.clone(),
        SEND_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} BT scrape ({duration_ms}ms)")
            .with_debug("BT tracker scrape from {client_ip}")
            .with_trace("BT scrape: {json_pretty(.)}"),
    )
});

pub static SEND_ANNOUNCE_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_announce_response".to_string(),
        description: "Send announce response with peer list".to_string(),
        parameters: vec![
            Parameter {
                name: "interval".to_string(),
                type_hint: "number".to_string(),
                description: "Announce interval in seconds (default: 1800)".to_string(),
                required: false,
            },
            Parameter {
                name: "complete".to_string(),
                type_hint: "number".to_string(),
                description: "Number of seeders (default: 0)".to_string(),
                required: false,
            },
            Parameter {
                name: "incomplete".to_string(),
                type_hint: "number".to_string(),
                description: "Number of leechers (default: 0)".to_string(),
                required: false,
            },
            Parameter {
                name: "compact".to_string(),
                // Not "boolean". The documented usage is to interpolate `{{event.compact}}`,
                // and the event declares that field a number because clients send
                // `compact=1` in the query string - so declaring boolean here told the model
                // to convert the one value it is being instructed to pass through verbatim.
                // `is_compact` accepts both spellings (and the string forms), so the union is
                // what the executor actually implements.
                type_hint: "boolean|number".to_string(),
                description: "Encode peers in BEP 23 compact form (4-byte IPv4 + 2-byte \
                              port). Send 1 or 0 (`true`/`false` also work). Most real \
                              clients require compact form, which carries no peer_id and \
                              drops IPv6 peers, so 1 is usually right. In a *static* handler \
                              — and only there — \"{{event.compact}}\" passes the request's \
                              own value through; on this path that placeholder is not \
                              interpolated and would be read as text."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "peers".to_string(),
                type_hint: "array".to_string(),
                description: "Array of peer objects with `ip` and `port`, plus an optional \
                              `peer_id` used only in non-compact form. A `peer_id` of 40 hex \
                              characters is decoded to the 20 bytes BEP 3 wants — that is \
                              the form the announce event reports it in — and anything else \
                              is sent as literal text."
                    .to_string(),
                required: false,
            },
        ],
        // `"{{event.compact}}"` is NOT usable here. `{{...}}` is interpolated only for
        // *static* handlers; on the LLM path the model copies the example verbatim and the
        // executor receives that literal string, which `is_compact` does not match — so it
        // answered in the dictionary form this action's own comment says real clients
        // refuse. Accepted, wrong bytes, no error raised, which is why it survived. The
        // example shows a concrete 1; the parameter description explains interpolation for
        // handler authors.
        example: json!({"type": "send_announce_response", "interval": 1800, "complete": 10, "incomplete": 5, "compact": 1, "peers": [{"peer_id": "2d5452303030312d787878787878787878787878", "ip": "192.168.1.100", "port": 51413}]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BT announce: {peers_len} peers, interval={interval}s")
                .with_debug("BT announce response: {peers_len} peers, complete={complete}, incomplete={incomplete}"),
        ),
    }
});

pub static SEND_SCRAPE_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_scrape_response".to_string(),
        description: "Send scrape response with torrent statistics".to_string(),
        parameters: vec![Parameter {
            name: "files".to_string(),
            type_hint: "object".to_string(),
            description: "Either an object keyed by hex info_hash -> \
                          {complete, downloaded, incomplete}, or an array of objects each \
                          carrying an `info_hash` field plus those counts. Keys that are \
                          not valid hex are dropped."
                .to_string(),
            required: false,
        }],
        // Not `{"{{event.info_hash}}": ...}`. On the LLM path that key arrives literally,
        // `hex::decode` rejects it, the entry is `continue`d, and the client gets an empty
        // `files` dictionary under a 200 OK — silently, which is why it survived. The array
        // form is shown instead: it puts the info_hash in a value rather than a key, so a
        // static handler can interpolate it there and the LLM path has an obvious place to
        // copy the event's hex into.
        example: json!({"type": "send_scrape_response", "files": [{"info_hash": "1111111111111111111111111111111111111111", "complete": 10, "downloaded": 100, "incomplete": 5}]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BT scrape: {files_len} torrents")
                .with_debug("BT scrape response: {files_len} torrents"),
        ),
    }
});

pub static SEND_ERROR_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "send_error_response".to_string(),
        description: "Refuse the request with a bencode `failure reason` (BEP 3). Clients \
                      display this and stop announcing to this tracker."
            .to_string(),
        parameters: vec![Parameter {
            name: "failure_reason".to_string(),
            type_hint: "string".to_string(),
            description: "Message shown to the client, which then stops announcing to this \
                          tracker (alias: `error`). Genuinely required — omitting it is an \
                          error, not a generic refusal."
                .to_string(),
            required: true,
        }],
        example: json!({"type": "send_error_response", "failure_reason": "Torrent not found"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BT error: {failure_reason}")
                .with_debug("BT tracker error: {failure_reason}"),
        ),
    });
