//! NetBIOS Name Service protocol vocabulary: what the model sees, and what it can execute.
//!
//! Three events (name query, node status request, name registration) and four actions. The
//! actions are the only way anything reaches the wire — there is no default response anywhere
//! in this file, which is what makes the silence rule in `mod.rs` structural rather than
//! aspirational. See `src/server/netbios_ns/CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

use super::packet::{self, AddressEntry, NodeType};

/// Default TTL for a positive name response when neither the action nor `default_ttl` says
/// otherwise. RFC 1002 §4.2.13 uses 300000 seconds for a well-established name; three hours
/// is the value real NBNS servers commonly hand out and is short enough that a wrong answer
/// does not sit in a cache for days.
pub const DEFAULT_TTL_SECONDS: u32 = 10800;

/// NetBIOS Name Service protocol handler.
///
/// The registry holds a context-free instance from [`NetbiosNsProtocol::new`]. `mod.rs`
/// builds one per received datagram with [`NetbiosNsProtocol::for_request`], carrying the
/// transaction id, the request's opcode and the exact question NAME field. A context-free
/// instance cannot build a response and says so — the model must never supply those three,
/// because a response with the wrong transaction id or the wrong name is precisely what
/// poisons a querier's name cache.
pub struct NetbiosNsProtocol {
    request: Option<RequestContext>,
}

/// Everything a reply must echo, taken from the request rather than from the model.
#[derive(Clone, Debug)]
pub struct RequestContext {
    /// `NAME_TRN_ID` of the request; the reply must repeat it or the client discards it.
    pub trn_id: u16,
    /// The request's OPCODE. A registration response differs from a query response only in
    /// this field.
    pub opcode: u16,
    /// Whether the request set RD, so the reply can echo it.
    pub recursion_desired: bool,
    /// The question's NAME field, verbatim, terminator included. Echoing the bytes preserves
    /// any NetBIOS scope the sender used without this code having to re-encode it.
    pub name_field: Vec<u8>,
    /// The question's decoded name and suffix, so a positive answer can be *checked* against
    /// what was actually asked. See the executor: the wire always carries `name_field`, so
    /// without this the model's `name`/`suffix` would be decoration and a model answering
    /// for the wrong host would still emit a valid answer for the right one.
    pub question_name: String,
    pub question_suffix: u8,
    /// TTL used when the action omits one (the `default_ttl` startup parameter).
    pub default_ttl: u32,
    /// Owner node type used when the action omits one (the `node_type` startup parameter).
    pub default_node_type: NodeType,
}

impl Default for NetbiosNsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl NetbiosNsProtocol {
    pub fn new() -> Self {
        Self { request: None }
    }

    pub fn for_request(ctx: RequestContext) -> Self {
        Self { request: Some(ctx) }
    }

    fn ctx(&self) -> Result<&RequestContext> {
        self.request.as_ref().context(
            "NetBIOS-NS action executed without a request context: the reply's transaction id, \
             opcode and question name all come from the received datagram, and this instance \
             came from the registry rather than from one.",
        )
    }
}

// ===========================================================================================
// Parameter helpers
// ===========================================================================================

/// Read the suffix octet, through the one shared parser
/// ([`packet::parse_suffix_value`]) that the NBNS **client**'s actions also use — so a
/// suffix seen in an event really can be handed straight back, and the two halves cannot
/// drift into reading `"20"` as two different names.
///
/// Required here (unlike on the client, where it defaults to 0): a response names the
/// service, and guessing which one is guessing which name is being answered for.
fn parse_suffix(action: &serde_json::Value) -> Result<u8> {
    let value = action
        .get("suffix")
        .context("action needs a 'suffix' (the NetBIOS service selector, e.g. 0 for a workstation, 32 for a file server)")?;
    packet::parse_suffix_value(Some(value))
}

fn parse_name(action: &serde_json::Value) -> Result<String> {
    action
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .context(
            "action needs a 'name' (the NetBIOS name, at most 15 characters, without the suffix)",
        )
}

fn parse_bool(action: &serde_json::Value, key: &str, default: bool) -> Result<bool> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => v
            .as_bool()
            .with_context(|| format!("'{}' must be true or false", key)),
    }
}

fn parse_node_type(action: &serde_json::Value, default: NodeType) -> Result<NodeType> {
    match action.get("node_type").and_then(|v| v.as_str()) {
        None => Ok(default),
        Some(s) => NodeType::parse(s)
            .with_context(|| format!("'node_type' must be one of b, p, m, h — got '{}'", s)),
    }
}

fn parse_rcode(action: &serde_json::Value) -> Result<u16> {
    let value = action
        .get("rcode")
        .context("send_netbios_negative_response needs an 'rcode'")?;
    if let Some(n) = value.as_u64() {
        let n = u16::try_from(n).context("'rcode' must be 0-15")?;
        if n > 15 {
            anyhow::bail!("'rcode' must be 0-15 (it is a four-bit field)");
        }
        return Ok(n);
    }
    let name = value
        .as_str()
        .context("'rcode' must be a name or a number 1-15")?;
    packet::rcode_by_name(name).with_context(|| {
        format!(
            "unknown rcode '{}'; accepted names are {:?}",
            name,
            packet::RCODE_NAMES
        )
    })
}

// ===========================================================================================
// Protocol
// ===========================================================================================

impl Protocol for NetbiosNsProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "default_ttl".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Seconds a querier may cache a positive name response when the action does \
                     not give its own 'ttl'. Defaults to {}.",
                    DEFAULT_TTL_SECONDS
                ),
                required: false,
                example: json!(3600),
                default: None,
            },
            ParameterDefinition {
                name: "node_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Owner node type reported in name responses when the action does not give \
                     its own: 'b' (broadcast), 'p' (point-to-point), 'm' (mixed) or 'h' \
                     (hybrid). Defaults to 'b'."
                        .to_string(),
                required: false,
                example: json!("b"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // NBNS is purely reactive: the server says nothing until it is asked. There is no
        // user-triggered action that would have anywhere to send its datagram.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            name_response_action(),
            node_status_response_action(),
            negative_response_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "NetBIOS-NS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_netbios_ns_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NetBIOS-NS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["netbios", "netbios-ns", "nbns", "nbt", "wins", "nmb"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // UDP: its "connections" are per-remote-address bookkeeping that nothing ever
            // closes, so the 10-second idle sweep is what reaps them.
            .connectionless()
            // Answers on failure, narrowly: a request addressed to this server as its NBNS (RD set,
            // B clear) gets a NEGATIVE response with RCODE SRV_ERR, the name server's own "I cannot
            // process this", which asserts nothing about the name. Broadcast queries, node-directed
            // queries and node status stay silent - every other reply would assert a name.
            .answers_on_failure()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(137))
            .well_known_udp_port(137)
            .implementation(
                "Hand-written RFC 1001/1002 codec (src/server/netbios_ns/packet.rs); no NBNS \
                 crate exists. 12-octet header, first-level name encoding, NB/NBSTAT queries \
                 and name registration.",
            )
            .llm_control(
                "Which names exist, their addresses, group/unique, node type and TTL; the node \
                 status name list and adapter MAC; and refusal by RCODE. The transaction id, \
                 opcode and question name are echoed by the server, never chosen by the model.",
            )
            .e2e_testing(
                "Raw UDP socket replaying NAME QUERY and NODE STATUS datagrams captured from \
                 Samba 4.24.6 nmblookup byte for byte, plus codec tests against those same \
                 literals. Responses are decoded by the test, not by nmblookup.",
            )
            .notes(
                "Experimental, and the reason is specific: Samba's nmblookup is a genuine \
                 third-party client and its queries are what the tests replay, but nmblookup \
                 is hard-wired to UDP port 137 with no option to change it (verified by packet \
                 capture: --option='nbt port=N' is accepted by the config parser and ignored by \
                 the client), so pointing it at a NetGet server needs a privileged run that no \
                 unattended test can do. Nothing has therefore validated the response direction \
                 against a real client. On LLM failure this server sends NOTHING — a fabricated \
                 NBNS answer is cached by the querier and poisons its name resolution.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NetBIOS Name Service (RFC 1001/1002) name resolution server"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a NetBIOS name server on port 137 that resolves FILESERVER to 192.168.1.10"
    }

    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 137,
                "base_stack": "netbios_ns",
                "instruction": "Resolve the NetBIOS name FILESERVER (suffix 32, the file server \
                                service) to 192.168.1.10. Answer name_not_found for anything else."
            }),
            json!({
                "type": "open_server",
                "port": 137,
                "base_stack": "netbios_ns",
                "event_handlers": [{
                    "event_pattern": "netbios_name_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "name = event.get('name', '')\nif name == 'FILESERVER':\n    respond([{'type': 'send_netbios_name_response', 'name': name, 'suffix': event.get('suffix', 0), 'addresses': ['192.168.1.10'], 'ttl': 3600, 'group': False}])\nelse:\n    respond([{'type': 'send_netbios_negative_response', 'rcode': 'name_not_found'}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 137,
                "base_stack": "netbios_ns",
                "event_handlers": [{
                    "event_pattern": "netbios_name_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_netbios_name_response",
                            "name": "FILESERVER",
                            "suffix": 32,
                            "addresses": ["192.168.1.10"],
                            "ttl": 3600,
                            "group": false
                        }]
                    }
                }]
            }),
        )
    }
}

// ===========================================================================================
// Server
// ===========================================================================================

impl Server for NetbiosNsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::NetbiosNsServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            // Explicit silence. Deliberately available without a request context: saying
            // nothing needs nothing from the request, and it must be trivially reachable —
            // it is the correct answer whenever the model is unsure.
            "no_response" => Ok(ActionResult::NoAction),

            "send_netbios_name_response" => {
                let ctx = self.ctx()?;
                let group = parse_bool(&action, "group", false)?;
                let node_type = parse_node_type(&action, ctx.default_node_type)?;
                let ttl = match action.get("ttl") {
                    None | Some(serde_json::Value::Null) => ctx.default_ttl,
                    Some(v) => {
                        let n = v.as_u64().context("'ttl' must be a number of seconds")?;
                        u32::try_from(n).context("'ttl' exceeds 32 bits")?
                    }
                };

                let raw_addresses = action.get("addresses").and_then(|v| v.as_array()).context(
                    "send_netbios_name_response needs 'addresses': a list of dotted-quad \
                         IPv4 addresses, e.g. [\"192.168.1.10\"]",
                )?;
                if raw_addresses.is_empty() {
                    anyhow::bail!(
                        "'addresses' is empty; a positive name response must carry at least one \
                         address. To say the name does not exist use \
                         send_netbios_negative_response, and to say nothing at all use no_response."
                    );
                }

                let mut flags = node_type.ont_bits();
                if group {
                    flags |= packet::NB_FLAG_GROUP;
                }

                let mut addresses = Vec::with_capacity(raw_addresses.len());
                for value in raw_addresses {
                    let text = value
                        .as_str()
                        .context("each entry of 'addresses' must be a dotted-quad string")?;
                    let address: Ipv4Addr = text
                        .parse()
                        .with_context(|| format!("'{}' is not an IPv4 address", text))?;
                    addresses.push(AddressEntry { flags, address });
                }

                // The NAME field on the wire is the question's, verbatim — RFC 1002 §4.2.13's
                // answer RR names the queried name, and there is no form of positive answer
                // that names a different one. So `name`/`suffix` cannot change what is sent,
                // and a model that supplies the wrong ones is answering for a host it did not
                // mean to. **Refused rather than ignored**: an answer is a cache entry, and
                // silently substituting the queried name for the one the model named is the
                // fail-open shape this protocol exists to avoid. The model's own log line
                // would have read `-> NetBIOS name PRINTER<0x00>` while the wire said
                // `FILESERVER<0x20>`.
                let claimed_name = parse_name(&action)?;
                let claimed_suffix = parse_suffix(&action)?;
                if !claimed_name.eq_ignore_ascii_case(&ctx.question_name)
                    || claimed_suffix != ctx.question_suffix
                {
                    anyhow::bail!(
                        "this query asked about '{}'<{:#04x}> but the response names \
                         '{}'<{:#04x}>. A positive NetBIOS name response always answers for \
                         the name that was queried (RFC 1002 §4.2.13), so it cannot carry a \
                         different one — the querier would cache your addresses against \
                         '{}'<{:#04x}> regardless. To point that name at another host, put \
                         that host's addresses in 'addresses'. To say this name is not held \
                         here, use send_netbios_negative_response or no_response.",
                        ctx.question_name,
                        ctx.question_suffix,
                        claimed_name,
                        claimed_suffix,
                        ctx.question_name,
                        ctx.question_suffix,
                    );
                }

                let bytes = packet::encode_name_query_response(
                    ctx.trn_id,
                    ctx.opcode,
                    ctx.recursion_desired,
                    &ctx.name_field,
                    &addresses,
                    ttl,
                )?;
                Ok(ActionResult::Output(bytes))
            }

            "send_netbios_node_status_response" => {
                let ctx = self.ctx()?;
                let mac_text = action.get("mac_address").and_then(|v| v.as_str()).context(
                    "send_netbios_node_status_response needs 'mac_address' as a string such \
                         as \"00:11:22:33:44:55\"",
                )?;
                let mac = packet::parse_mac(mac_text)?;

                let entries = action.get("names").and_then(|v| v.as_array()).context(
                    "send_netbios_node_status_response needs 'names': a list of \
                         {name, suffix, group, active} objects",
                )?;
                if entries.is_empty() {
                    anyhow::bail!(
                        "'names' is empty; a node status response must list at least one name. \
                         Use no_response to stay silent instead."
                    );
                }

                let mut names = Vec::with_capacity(entries.len());
                for entry in entries {
                    let name = parse_name(entry)?;
                    let suffix = parse_suffix(entry)?;
                    let raw = packet::pad_netbios_name(&name, suffix)?;
                    let mut flags = 0u16;
                    if parse_bool(entry, "group", false)? {
                        flags |= packet::NAME_FLAG_GROUP;
                    }
                    if parse_bool(entry, "active", true)? {
                        flags |= packet::NAME_FLAG_ACTIVE;
                    }
                    names.push(packet::NodeName { raw, flags });
                }

                let bytes =
                    packet::encode_node_status_response(ctx.trn_id, &ctx.name_field, &names, mac)?;
                Ok(ActionResult::Output(bytes))
            }

            "send_netbios_negative_response" => {
                let ctx = self.ctx()?;
                let rcode = parse_rcode(&action)?;
                let bytes = packet::encode_negative_response(
                    ctx.trn_id,
                    ctx.opcode,
                    ctx.recursion_desired,
                    &ctx.name_field,
                    rcode,
                )?;
                Ok(ActionResult::Output(bytes))
            }

            other => Err(anyhow::anyhow!("Unknown NetBIOS-NS action: {}", other)),
        }
    }
}

// ===========================================================================================
// Action definitions
// ===========================================================================================

fn suffix_parameter() -> Parameter {
    Parameter {
        name: "suffix".to_string(),
        type_hint: "number".to_string(),
        description:
            "NetBIOS service suffix — the 16th octet of the name, which selects the service, \
             NOT part of the name text. 0 = workstation, 3 = messenger, 27 (0x1B) = domain \
             master browser, 28 (0x1C) = domain controllers, 30 (0x1E) = browser elections, \
             32 (0x20) = file server. Give it as a number."
                .to_string(),
        required: true,
    }
}

fn name_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_netbios_name_response".to_string(),
        description:
            "Answer a NetBIOS name query positively: this name exists and resolves to these \
             addresses. The response echoes the querier's transaction id and question name \
             automatically — do not try to supply them. Only answer this way when the name \
             really should exist; a querier caches the answer for the TTL."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The NetBIOS name being answered for, at most 15 characters, uppercase by \
                     convention, without the suffix octet."
                        .to_string(),
                required: true,
            },
            suffix_parameter(),
            Parameter {
                name: "addresses".to_string(),
                type_hint: "array".to_string(),
                description:
                    "IPv4 addresses as dotted quads, e.g. [\"192.168.1.10\"]. At least one."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the querier may cache this answer. Defaults to the \
                              server's default_ttl."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "group".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "true for a group name (several hosts may hold it, e.g. a workgroup), false \
                     for a unique name owned by one host. Defaults to false."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "node_type".to_string(),
                type_hint: "string".to_string(),
                description: "Owner node type: 'b', 'p', 'm' or 'h'. Defaults to the server's \
                              node_type."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_netbios_name_response",
            "name": "FILESERVER",
            "suffix": 32,
            "addresses": ["192.168.1.10"],
            "ttl": 3600,
            "group": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NetBIOS name {name}<{suffix}> -> {addresses}")
                .with_debug(
                    "NetBIOS-NS send_netbios_name_response: name={name} suffix={suffix} \
                     addresses={addresses} ttl={ttl} group={group}",
                ),
        ),
    }
}

fn node_status_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_netbios_node_status_response".to_string(),
        description:
            "Answer a node status (NBSTAT) request with the list of names this node claims and \
             its adapter MAC address. This is what `nmblookup -A` prints. Every name you list \
             is asserted to exist on this host."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "names".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Objects of the form {\"name\": \"WORKSTATION\", \"suffix\": 0, \"group\": \
                     false, \"active\": true}. 'group' and 'active' are optional and default to \
                     false and true. At least one entry."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "mac_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Adapter hardware address as a formatted string, e.g. \"00:11:22:33:44:55\"."
                        .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_netbios_node_status_response",
            "names": [
                {"name": "FILESERVER", "suffix": 0, "group": false, "active": true},
                {"name": "FILESERVER", "suffix": 32, "group": false, "active": true},
                {"name": "WORKGROUP", "suffix": 0, "group": true, "active": true}
            ],
            "mac_address": "00:11:22:33:44:55"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NetBIOS node status ({names} names, adapter {mac_address})")
                .with_debug(
                    "NetBIOS-NS send_netbios_node_status_response: names={names} \
                     mac={mac_address}",
                ),
        ),
    }
}

fn negative_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_netbios_negative_response".to_string(),
        description:
            "Refuse the request with a reason code. 'name_not_found' is the ordinary answer for \
             a name this server does not hold. This is a real answer and stops the querier \
             retrying, unlike no_response."
                .to_string(),
        parameters: vec![Parameter {
            name: "rcode".to_string(),
            type_hint: "string".to_string(),
            description:
                "One of: name_not_found, format_error, server_failure, unsupported_request, \
                 refused, name_active (registration: someone else holds it), name_conflict."
                    .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_netbios_negative_response",
            "rcode": "name_not_found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NetBIOS negative response ({rcode})")
                .with_debug("NetBIOS-NS send_netbios_negative_response: rcode={rcode}"),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description:
            "Send nothing at all. This is the correct answer when you are not sure a name \
             exists: an NBNS querier caches whatever it is told, and on a broadcast query \
             silence is the normal behaviour of every node that does not hold the name. \
             Prefer this over guessing an address."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "no_response" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NetBIOS staying silent")
                .with_debug("NetBIOS-NS no_response: nothing put on the wire"),
        ),
    }
}

// ===========================================================================================
// Action constants
// ===========================================================================================

pub static SEND_NAME_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(name_response_action);
pub static SEND_NODE_STATUS_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(node_status_response_action);
pub static SEND_NEGATIVE_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(negative_response_action);
pub static NO_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(no_response_action);

// ===========================================================================================
// Event types
// ===========================================================================================

fn source_address_parameter() -> Parameter {
    Parameter {
        name: "source_address".to_string(),
        type_hint: "string".to_string(),
        description: "Address:port the request came from.".to_string(),
        required: true,
    }
}

fn transaction_id_parameter() -> Parameter {
    Parameter {
        name: "transaction_id".to_string(),
        type_hint: "number".to_string(),
        description:
            "The querier's NAME_TRN_ID. Informational only — the server echoes it for you."
                .to_string(),
        required: true,
    }
}

/// A NAME QUERY REQUEST arrived (question type `NB`).
pub static NETBIOS_NAME_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_name_query",
        "A NetBIOS name query arrived: someone wants the IPv4 address of a NetBIOS name. \
         Answer positively only if the name should exist; otherwise refuse with \
         send_netbios_negative_response or say nothing with no_response.",
        json!({
            "type": "send_netbios_name_response",
            "name": "FILESERVER",
            "suffix": 32,
            "addresses": ["192.168.1.10"],
            "ttl": 3600,
            "group": false
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The NetBIOS name asked about, trailing padding removed.".to_string(),
            required: true,
        },
        suffix_parameter(),
        Parameter {
            name: "question_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"NB\" for a name query.".to_string(),
            required: true,
        },
        source_address_parameter(),
        transaction_id_parameter(),
    ])
    .with_actions(vec![
        SEND_NAME_RESPONSE_ACTION.clone(),
        SEND_NEGATIVE_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_netbios_negative_response",
        "rcode": "name_not_found"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("NetBIOS name query {name}<{suffix}> from {source_address}")
            .with_debug(
                "NetBIOS-NS query: name={name} suffix={suffix} type={question_type} \
                 from={source_address} trn_id={transaction_id}",
            )
            .with_trace("NetBIOS-NS query: {json_pretty(.)}"),
    )
});

/// A NODE STATUS REQUEST arrived (question type `NBSTAT`).
pub static NETBIOS_NODE_STATUS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_node_status_request",
        "A NetBIOS node status (NBSTAT) request arrived: someone is asking which names this \
         node holds, as `nmblookup -A` does. The name asked about is usually the wildcard '*'.",
        json!({
            "type": "send_netbios_node_status_response",
            "names": [
                {"name": "FILESERVER", "suffix": 0, "group": false, "active": true},
                {"name": "WORKGROUP", "suffix": 0, "group": true, "active": true}
            ],
            "mac_address": "00:11:22:33:44:55"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The name asked about; '*' means \"whatever you hold\".".to_string(),
            required: true,
        },
        suffix_parameter(),
        source_address_parameter(),
        transaction_id_parameter(),
    ])
    .with_actions(vec![
        SEND_NODE_STATUS_RESPONSE_ACTION.clone(),
        SEND_NEGATIVE_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NetBIOS node status request for {name}<{suffix}> from {source_address}")
            .with_debug(
                "NetBIOS-NS node status: name={name} suffix={suffix} from={source_address} \
                 trn_id={transaction_id}",
            )
            .with_trace("NetBIOS-NS node status: {json_pretty(.)}"),
    )
});

/// A NAME REGISTRATION REQUEST arrived.
pub static NETBIOS_NAME_REGISTRATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_name_registration",
        "A node is claiming a NetBIOS name for itself. Accept with \
         send_netbios_name_response (which confirms the claim), refuse with \
         send_netbios_negative_response (rcode name_active if someone else holds it, \
         name_conflict if it is disputed), or stay silent with no_response.",
        json!({
            "type": "send_netbios_name_response",
            "name": "WORKSTATION",
            "suffix": 0,
            "addresses": ["192.168.1.55"],
            "ttl": 3600,
            "group": false
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The NetBIOS name being claimed.".to_string(),
            required: true,
        },
        suffix_parameter(),
        Parameter {
            name: "address".to_string(),
            type_hint: "string".to_string(),
            description:
                "IPv4 address the claimant gave in the request's additional record, as a dotted \
                 quad. Absent if the request carried none."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "group".to_string(),
            type_hint: "boolean".to_string(),
            description: "true if the claimant is registering a group name.".to_string(),
            required: false,
        },
        source_address_parameter(),
        transaction_id_parameter(),
    ])
    .with_actions(vec![
        SEND_NAME_RESPONSE_ACTION.clone(),
        SEND_NEGATIVE_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_netbios_negative_response",
        "rcode": "name_active"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("NetBIOS name registration {name}<{suffix}> for {address}")
            .with_debug(
                "NetBIOS-NS registration: name={name} suffix={suffix} address={address} \
                 group={group} from={source_address} trn_id={transaction_id}",
            )
            .with_trace("NetBIOS-NS registration: {json_pretty(.)}"),
    )
});

pub fn get_netbios_ns_event_types() -> Vec<EventType> {
    vec![
        NETBIOS_NAME_QUERY_EVENT.clone(),
        NETBIOS_NODE_STATUS_REQUEST_EVENT.clone(),
        NETBIOS_NAME_REGISTRATION_EVENT.clone(),
    ]
}
