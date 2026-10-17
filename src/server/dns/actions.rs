//! DNS protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use hickory_proto::op::{Header, Message as DnsMessage, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

/// Longest DNS `<character-string>`, in octets (RFC 1035 §3.3).
///
/// A character-string is one length octet followed by that many characters, so 255 is what
/// the format can describe — not a policy this server chose. `send_dns_txt_response` emits
/// the TXT record as a single character-string, so this is its ceiling.
///
/// It is enforced in `execute_send_dns_txt_response` rather than left to hickory, and the
/// difference is not cosmetic: hickory's encoder does refuse, but it refuses inside
/// `message.to_vec()`, which fails the whole action with "Failed to serialize DNS message".
/// `src/server/dns/mod.rs` then takes its `Ok` branch with no `ActionResult::Output` in hand
/// and writes **nothing at all** — the peer waits out its own timeout, and the model is told
/// a serialisation error rather than the one number it needed. Stating the bound here turns a
/// fail-silent into an error the model can act on, which is the same reason
/// `coap::codec::MAX_PAYLOAD_LEN` is checked in `decode_payload` instead of at `send_to`.
pub const MAX_CHARACTER_STRING_LEN: usize = 255;

/// Most records one `send_dns_records` answer may carry, across all three sections.
pub const MAX_ANSWER_RECORDS: usize = 100;

/// Names carried by the [`ActionResult::Custom`] results the zone-transfer actions produce.
/// The action comes back validated and `mod.rs` builds the transfer from it, because a zone
/// does not fit the one message an `ActionResult::Output` would carry.
pub const RESULT_ZONE: &str = "dns_zone";
pub const RESULT_IXFR: &str = "dns_ixfr";

/// DNS protocol action handler
pub struct DnsProtocol;

impl Default for DnsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsProtocol {
    pub fn new() -> Self {
        Self
    }

    /// The actions that answer a query — what DoH, DoT and DoQ forward onto their own query
    /// events. The zone-transfer actions are left out: those servers have no transfer event.
    pub fn query_actions() -> Vec<ActionDefinition> {
        vec![
            send_dns_a_response_action(),
            send_dns_aaaa_response_action(),
            send_dns_cname_response_action(),
            send_dns_mx_response_action(),
            send_dns_txt_response_action(),
            send_dns_nxdomain_action(),
            send_dns_records_action(),
            send_dns_refused_action(),
            send_dns_response_action(),
            ignore_query_action(),
        ]
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DnsProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new() // DNS has no async actions
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = Self::query_actions();
        actions.push(send_dns_zone_action());
        actions.push(send_dns_ixfr_action());
        actions
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "dnssec_zone".to_string(),
                type_hint: "string".to_string(),
                description: "Sign this zone with DNSSEC, e.g. \"example.com.\". The server \
                    generates an ECDSA P-256 key at startup, answers the zone's DNSKEY query \
                    itself, signs every answer under the zone for a client that sets the DO \
                    bit, proves non-existence with NSEC, and signs zone transfers with a full \
                    NSEC chain. Omitted, nothing is signed."
                    .to_string(),
                required: false,
                example: json!("example.com."),
                default: None,
            },
            ParameterDefinition {
                name: "tcp_idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a DNS-over-TCP connection may sit idle between queries \
                    before the server closes it (RFC 7766 §6.2.3). 1-300."
                    .to_string(),
                required: false,
                example: json!(10),
                default: Some(json!(super::DEFAULT_TCP_IDLE_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "tcp_connections_per_ip".to_string(),
                type_hint: "number".to_string(),
                description: "DNS-over-TCP connections one client address may hold open at \
                    once (IPv6 counted per /64); past it a new connection from that address is \
                    closed unread. 1-64, the server's cap on all TCP connections."
                    .to_string(),
                required: false,
                example: json!(8),
                default: Some(json!(super::MAX_TCP_CONNECTIONS_PER_IP)),
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DNS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_dns_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dns"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: SERVFAIL echoing the query id, never silence.
            .answers_on_failure()
            // STABLE, set 16 September 2026 against the six conditions in the root CLAUDE.md,
            // each verified in that pass rather than inherited. Read `.e2e_testing` and
            // `.notes` before quoting it: the rating covers the surface this server
            // implements, which is plain UDP DNS with one record per answer.
            .state(DevelopmentState::Stable)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(53))
            .well_known_udp_port(53)
            .implementation(
                "hickory-proto for parsing and construction; UDP and TCP (RFC 7766) on the same \
                 port; EDNS0 with the TC bit; AXFR (RFC 5936) and IXFR (RFC 1995) zone \
                 transfers; DNSSEC signing of one zone (RFC 4033-4035) with a key generated at \
                 startup, compact NSEC denial in answers and a full NSEC chain in transfers",
            )
            .llm_control(
                "Response records (A, AAAA, MX, TXT, CNAME, NS, PTR, SRV, SOA, NXDOMAIN, \
                 REFUSED), and whole zones or their changes for a transfer. Keys, signatures, \
                 NSEC, EDNS and truncation are server-side",
            )
            .e2e_testing(
                "STABLE rests on all six conditions, each checked against source and by \
                 running it on 16 September 2026. (1) TWO independent resolvers from different \
                 projects, neither #[ignore]d and neither able to skip -- each FAILS naming its \
                 package when absent: dig_test.rs drives ISC BIND's dig and kdig_test.rs drives \
                 Knot DNS's kdig (CZ.NIC). Between them they decode EVERY record type this \
                 server can produce -- A, AAAA, CNAME, MX (preference 4660 = 0x1234, so a \
                 byte-swap reads 13330 rather than something plausible), the TXT \
                 character-string, and RCODE 3 for NXDOMAIN -- each through that resolver's own \
                 presentation writer, and each asserts no transaction-id mismatch. Verified by \
                 answering with a fixed id instead of the client's, at which point kdig \
                 discards the reply. dig_test.rs additionally runs ONE query as a person would \
                 actually invoke it, with EDNS offered and no flags, and it resolves: RFC 6891 \
                 §6.1.1 says a server that does not understand EDNS answers without an OPT \
                 record and the requestor treats it as non-EDNS. Without that query the whole \
                 rating would rest on a +noedns configuration nobody uses -- the \
                 mysql_native_password situation. (2) The pcap oracle reads both SERVFAIL paths \
                 in llm_failure_test.rs and a NOERROR answer with A rdata in bounds_test.rs, \
                 and hard-fails when tshark is missing. (3) fuzz/fuzz_targets/dns_message.rs: \
                 2,777,883 runs in 91s, clean; the corpus includes compression_pointer_loop, \
                 which is the depth bomb for a format whose recursion is the compression \
                 pointer. It fuzzes hickory-proto rather than NetGet code because NetGet has no \
                 DNS parser -- three registered protocols reach that decoder from an \
                 unauthenticated first datagram. (4) Every declared bound has a test in \
                 bounds_test.rs -- the 4096-byte receive buffer, query_id and MX preference as \
                 u16, the 12-octet floor on a raw message, the 255-octet character-string -- \
                 each verified by REMOVING the bound and recording what failed. (5) Both \
                 CLAUDE.md files were re-read against source in that pass; several claims were \
                 false and the corrections are in them. (6) No #[ignore] and no skip gate \
                 anywhere in tests/server/dns/. \
                 \
                 tests/server/dns/test.rs covers the same ground with hickory-client -- useful, \
                 but circular on its own, since hickory-client decodes with the same codec \
                 hickory-proto encoded with. It is not part of the evidence above. \
                 \
                 TCP, EDNS0, ZONE TRANSFERS AND DNSSEC, added October 2026, carry the six \
                 conditions on their own surface. (1) dig and kdig each transfer a 611-record \
                 zone in two TCP messages (transfer_test.rs), apply an IXFR difference and read \
                 the single-SOA current answer, see the TC bit and retry over TCP, read the \
                 OPT record, and decode NS, SOA, SRV and PTR from send_dns_records; delv and \
                 drill each validate a signed positive answer, and delv a compact-denial \
                 negative one and a NODATA (dnssec_test.rs), against a trust anchor built from \
                 the DNSKEY the server serves; ldns-verify-zone and BIND's dnssec-verify each \
                 verify the whole signed zone received by AXFR, signatures and NSEC chain. \
                 Every one of those tools fails rather than skips when absent. (2) The pcap \
                 oracle reads the UDP and TCP exchanges of transport_bounds_test.rs, truncated \
                 answers, transfers and refusals included. (3) dns_message.rs also reads the OPT \
                 record and the authority SOA every query now feeds the server, with two new \
                 seeds. (4) The TCP connection cap, the TCP idle timeout, the 512/EDNS/4096 UDP \
                 limits, 100 answer records, 10,000 zone records and the transfer message size \
                 each have a test; the TCP cap, the UDP cap, the answer signatures and the NSEC \
                 chain were each removed and a test failed. \
                 \
                 UNPROVEN, because not implemented: NSEC3, more than one signed zone, a \
                 separate ZSK and KSK (one key acts as both; dnssec-verify is run with -z), \
                 delegations in a signed zone (refused), DNS COOKIEs, and TSIG on transfers.",
            )
            .notes(
                "Stable means the evidence for the implemented surface is complete, NOT that \
                 RFC 1035 is. Every action the model is offered is decoded by two \
                 independent resolvers; DNSSEC is validated by two validators and two zone \
                 verifiers. What is missing is listed in e2e_testing and in \
                 src/server/dns/AGENTS.md. \
                 A query that produces no answer fails closed with SERVFAIL through one exit, \
                 `send_servfail`, tagged decision=fail_closed_llm_error / _llm_overload / \
                 _no_action; `ignore_query` is decision=model_silent and is the only path that \
                 writes nothing. The third of those did not exist before September 2026 and its \
                 absence was a fail-silent: a model answering with only common actions, or with \
                 a DNS action execute_action refused, produced no packet at all. \
                 Excellent scripting candidate; static handlers cannot echo the client's \
                 transaction ID, so use script mode for deterministic answers. \
                 Re-check rather than inherit: no CI job builds fuzz/ (it is its own \
                 workspace), and dig and kdig must be on PATH wherever the suite runs, since \
                 both tests hard-fail by design.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Domain name resolution server"
    }
    fn example_prompt(&self) -> &'static str {
        "DNS server on port 53 and resolve everything to 93.184.216.34"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // A fixed-resolve DNS server: everything under example.com answers with a
        // fixed A record, everything else NXDOMAIN. Reads the event from stdin
        // and echoes the client's random transaction id (query_id) — the one
        // thing a static handler cannot do, which is why DNS needs script mode.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "dns_query":
    domain = event.get("domain", "").rstrip(".")
    if domain.endswith("example.com"):
        actions = [{"type": "send_dns_a_response", "query_id": event["query_id"],
                    "domain": event["domain"], "ip": "93.184.216.34", "ttl": 300}]
    else:
        actions = [{"type": "send_dns_nxdomain", "query_id": event["query_id"],
                    "domain": event["domain"],
                    "query_type": event.get("query_type", "A")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: a different answer per subdomain — genuine reasoning.
            json!({
                "type": "open_server",
                "port": 53,
                "base_stack": "dns",
                "instruction": "Act as a DNS resolver that returns a different IP per query: map each queried hostname to a stable address in 10.0.0.0/8 derived from the name, but return the real public IP for well-known names such as www.example.com. Always echo the query's transaction id."
            }),
            // Script mode: deterministic fixed-resolve, no LLM call. The script
            // sees the event and can echo the client's random transaction id.
            json!({
                "type": "open_server",
                "port": 53,
                "base_stack": "dns",
                "event_handlers": [{
                    "event_pattern": "dns_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: static handlers emit fixed action JSON with no access
            // to the event, so they cannot echo the client's random transaction
            // ID or the queried name - a static answer record would be silently
            // discarded by every real resolver. Dropping queries (a DNS
            // blackhole) is what static mode can do correctly here; use script
            // mode for deterministic answers.
            json!({
                "type": "open_server",
                "port": 53,
                "base_stack": "dns",
                "event_handlers": [{
                    "event_pattern": "dns_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "ignore_query"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DnsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dns::{DnsServer, DnsSettings};
            let params = ctx.startup_params.as_ref();
            let dnssec_zone = params
                .map(|p| p.get_optional_string("dnssec_zone"))
                .transpose()?
                .flatten();
            let idle = params
                .map(|p| p.get_optional_u64("tcp_idle_timeout_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(super::DEFAULT_TCP_IDLE_TIMEOUT.as_secs());
            if !(1..=300).contains(&idle) {
                anyhow::bail!("tcp_idle_timeout_secs must be between 1 and 300, got {idle}");
            }
            let per_ip = params
                .map(|p| p.get_optional_u64("tcp_connections_per_ip"))
                .transpose()?
                .flatten()
                .unwrap_or(super::MAX_TCP_CONNECTIONS_PER_IP as u64);
            if !(1..=super::MAX_TCP_CONNECTIONS as u64).contains(&per_ip) {
                anyhow::bail!(
                    "tcp_connections_per_ip must be between 1 and {}, got {per_ip}",
                    super::MAX_TCP_CONNECTIONS
                );
            }
            DnsServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                DnsSettings {
                    dnssec_zone,
                    tcp_idle_timeout: std::time::Duration::from_secs(idle),
                    tcp_connections_per_ip: per_ip as usize,
                },
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
            "send_dns_a_response" => self.execute_send_dns_a_response(action),
            "send_dns_aaaa_response" => self.execute_send_dns_aaaa_response(action),
            "send_dns_cname_response" => self.execute_send_dns_cname_response(action),
            "send_dns_mx_response" => self.execute_send_dns_mx_response(action),
            "send_dns_txt_response" => self.execute_send_dns_txt_response(action),
            "send_dns_nxdomain" => self.execute_send_dns_nxdomain(action),
            "send_dns_response" => self.execute_send_dns_response(action),
            "send_dns_records" => execute_send_dns_records(&action),
            "send_dns_refused" => execute_send_dns_refused(&action),
            "send_dns_zone" => {
                super::transfer::zone_from_action(&action)?;
                Ok(ActionResult::Custom {
                    name: RESULT_ZONE.to_string(),
                    data: action,
                })
            }
            "send_dns_ixfr" => {
                // The serial the client holds is read from its query, not from the model, and
                // nothing checked here depends on it, so 0 validates every field.
                super::transfer::ixfr_from_action(&action, 0)?;
                Ok(ActionResult::Custom {
                    name: RESULT_IXFR.to_string(),
                    data: action,
                })
            }
            "ignore_query" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown DNS action: {}", action_type)),
        }
    }
}

/// Read the DNS transaction ID out of an action.
///
/// The transaction ID is how a client correlates a response with the query it
/// sent, and clients pick it at random. Silently truncating an out-of-range
/// value with `as u16` would produce a response the client discards without any
/// diagnostic, so an out-of-range value is a hard error instead.
fn parse_query_id(action: &serde_json::Value) -> Result<u16> {
    let raw = action
        .get("query_id")
        .and_then(|v| v.as_u64())
        .context("Missing 'query_id' parameter (echo the query_id from the dns_query event)")?;

    u16::try_from(raw).map_err(|_| {
        anyhow::anyhow!(
            "'query_id' must be a 16-bit DNS transaction ID (0-65535), got {}. \
             Echo the query_id from the dns_query event verbatim.",
            raw
        )
    })
}

/// Parse a DNS record type name (`"A"`, `"AAAA"`, `"MX"`, ...).
fn parse_record_type(name: &str) -> Result<RecordType> {
    RecordType::from_str(&name.to_ascii_uppercase())
        .with_context(|| format!("Unknown DNS record type: {name}"))
}

/// Build the shell of a DNS response: header plus the echoed question section.
///
/// RFC 1035 §4.1.2 requires a response to repeat the question it answers, and
/// real stub resolvers (glibc's, systemd-resolved, `dig`) discard responses
/// whose question section does not match the query they sent. The question is
/// reconstructed from the action's `domain` plus the record type implied by the
/// action, so answering a query with the matching action produces a response
/// those clients accept.
fn new_response(
    query_id: u16,
    domain: &str,
    query_type: RecordType,
    response_code: ResponseCode,
) -> Result<(DnsMessage, Name)> {
    let name =
        Name::from_str(domain).with_context(|| format!("Invalid domain name: '{domain}'"))?;

    let mut message = DnsMessage::new();
    let mut header = Header::new();
    header.set_id(query_id);
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_response_code(response_code);
    message.set_header(header);

    // Echo the question section (counts are recomputed by hickory at encode time).
    message.add_query(Query::query(name.clone(), query_type));

    Ok((message, name))
}

/// Build a SERVFAIL (RCODE 2) answer to `query`, for when the server cannot
/// produce a real answer at all — the LLM backend is down, overloaded, or
/// returned nothing usable.
///
/// RFC 1035 §4.1.1 gives exactly one code for "this server failed while
/// processing your query", and a resolver that receives it stops waiting and
/// moves to the next nameserver immediately. Writing nothing instead leaves the
/// resolver blocked for its own full timeout (5s in glibc, per server).
///
/// The transaction ID and the question section are copied from the query, for
/// the same reason `new_response` echoes them: a stub resolver discards any
/// response whose ID or question does not match what it sent, which would turn
/// this into silence again.
///
/// `AA` is deliberately *not* set: we are not answering authoritatively, we are
/// failing.
pub fn build_servfail(query: &DnsMessage) -> Result<Vec<u8>> {
    let mut message = DnsMessage::new();
    let mut header = Header::new();
    header.set_id(query.id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(query.op_code());
    header.set_recursion_desired(query.recursion_desired());
    header.set_response_code(ResponseCode::ServFail);
    message.set_header(header);

    for question in query.queries() {
        message.add_query(question.clone());
    }

    message
        .to_vec()
        .context("Failed to serialize DNS SERVFAIL response")
}

/// Serialize a response message to DNS wire format.
fn finish_response(message: DnsMessage) -> Result<ActionResult> {
    let bytes = message
        .to_vec()
        .context("Failed to serialize DNS message")?;
    Ok(ActionResult::Output(bytes))
}

fn ttl_of(action: &serde_json::Value) -> u32 {
    action
        .get("ttl")
        .and_then(|v| v.as_u64())
        .unwrap_or(300)
        .min(u32::MAX as u64) as u32
}

fn required_str<'a>(action: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    action
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("Missing '{key}' parameter"))
}

impl DnsProtocol {
    fn execute_send_dns_a_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;
        let ip = required_str(&action, "ip")?;
        let ttl = ttl_of(&action);

        let ipv4 =
            Ipv4Addr::from_str(ip).with_context(|| format!("Invalid IPv4 address: '{ip}'"))?;

        let (mut message, name) =
            new_response(query_id, domain, RecordType::A, ResponseCode::NoError)?;

        let mut record = Record::with(name, RecordType::A, ttl);
        record.set_data(Some(RData::A(rdata::A(ipv4))));
        message.add_answer(record);

        finish_response(message)
    }

    fn execute_send_dns_aaaa_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;
        let ip = required_str(&action, "ip")?;
        let ttl = ttl_of(&action);

        let ipv6 =
            Ipv6Addr::from_str(ip).with_context(|| format!("Invalid IPv6 address: '{ip}'"))?;

        let (mut message, name) =
            new_response(query_id, domain, RecordType::AAAA, ResponseCode::NoError)?;

        let mut record = Record::with(name, RecordType::AAAA, ttl);
        record.set_data(Some(RData::AAAA(rdata::AAAA(ipv6))));
        message.add_answer(record);

        finish_response(message)
    }

    fn execute_send_dns_cname_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;
        let target = required_str(&action, "target")?;
        let ttl = ttl_of(&action);

        let target_name = Name::from_str(target)
            .with_context(|| format!("Invalid target domain name: '{target}'"))?;

        // A CNAME may be returned for any query type; the question echoes CNAME
        // unless the caller says which type was actually asked for.
        let query_type = match action.get("query_type").and_then(|v| v.as_str()) {
            Some(qt) => parse_record_type(qt)?,
            None => RecordType::CNAME,
        };

        let (mut message, name) =
            new_response(query_id, domain, query_type, ResponseCode::NoError)?;

        let mut record = Record::with(name, RecordType::CNAME, ttl);
        record.set_data(Some(RData::CNAME(rdata::CNAME(target_name))));
        message.add_answer(record);

        finish_response(message)
    }

    fn execute_send_dns_mx_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;
        let exchange = required_str(&action, "exchange")?;
        let ttl = ttl_of(&action);

        let preference_raw = action
            .get("preference")
            .and_then(|v| v.as_u64())
            .unwrap_or(10);
        let preference = u16::try_from(preference_raw).map_err(|_| {
            anyhow::anyhow!("'preference' must be in the range 0-65535, got {preference_raw}")
        })?;

        let exchange_name = Name::from_str(exchange)
            .with_context(|| format!("Invalid exchange domain name: '{exchange}'"))?;

        let (mut message, name) =
            new_response(query_id, domain, RecordType::MX, ResponseCode::NoError)?;

        let mut record = Record::with(name, RecordType::MX, ttl);
        record.set_data(Some(RData::MX(rdata::MX::new(preference, exchange_name))));
        message.add_answer(record);

        finish_response(message)
    }

    fn execute_send_dns_txt_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;
        let text = required_str(&action, "text")?;
        let ttl = ttl_of(&action);

        if text.len() > MAX_CHARACTER_STRING_LEN {
            anyhow::bail!(
                "'text' is {} octets, over the {}-octet limit. RFC 1035 §3.3 defines a DNS \
                 <character-string> as one length octet followed by that many characters, so \
                 {} is what a single length octet can describe and this server emits the TXT \
                 record as one string. Shorten it.",
                text.len(),
                MAX_CHARACTER_STRING_LEN,
                MAX_CHARACTER_STRING_LEN
            );
        }

        let (mut message, name) =
            new_response(query_id, domain, RecordType::TXT, ResponseCode::NoError)?;

        let mut record = Record::with(name, RecordType::TXT, ttl);
        record.set_data(Some(RData::TXT(rdata::TXT::new(vec![text.to_string()]))));
        message.add_answer(record);

        finish_response(message)
    }

    fn execute_send_dns_nxdomain(&self, action: serde_json::Value) -> Result<ActionResult> {
        let query_id = parse_query_id(&action)?;
        let domain = required_str(&action, "domain")?;

        // NXDOMAIN carries no answer, so the question section is the only way a
        // client can tell which of its outstanding queries the response is for.
        let query_type = match action.get("query_type").and_then(|v| v.as_str()) {
            Some(qt) => parse_record_type(qt)?,
            None => RecordType::A,
        };

        let (message, _name) = new_response(query_id, domain, query_type, ResponseCode::NXDomain)?;

        finish_response(message)
    }

    fn execute_send_dns_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = required_str(&action, "data")?;

        // Hex only. The previous behaviour fell back to sending the raw string
        // bytes when hex decoding failed, which silently put non-DNS bytes on
        // the wire and left the client timing out with no diagnostic.
        let bytes = hex::decode(data.trim()).map_err(|e| {
            anyhow::anyhow!(
                "'data' must be a hex-encoded DNS message ({e}). \
                 Prefer the structured actions (send_dns_a_response, send_dns_nxdomain, ...) \
                 which build the wire format for you."
            )
        })?;

        if bytes.len() < 12 {
            anyhow::bail!(
                "'data' decoded to {} bytes; a DNS message needs at least a 12-byte header",
                bytes.len()
            );
        }

        Ok(ActionResult::Output(bytes))
    }
}

/// The RCODE names an answer may carry.
fn parse_rcode(name: &str) -> Result<ResponseCode> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "NOERROR" => ResponseCode::NoError,
        "NXDOMAIN" => ResponseCode::NXDomain,
        "REFUSED" => ResponseCode::Refused,
        "SERVFAIL" => ResponseCode::ServFail,
        "NOTIMP" => ResponseCode::NotImp,
        "FORMERR" => ResponseCode::FormErr,
        other => anyhow::bail!(
            "'rcode' {other:?} is not one of NOERROR, NXDOMAIN, REFUSED, SERVFAIL, NOTIMP, FORMERR"
        ),
    })
}

/// `send_dns_records`: any number of records in any of the three sections, any RCODE.
fn execute_send_dns_records(action: &serde_json::Value) -> Result<ActionResult> {
    let query_id = parse_query_id(action)?;
    let domain = required_str(action, "domain")?;
    let query_type = parse_record_type(required_str(action, "query_type")?)?;
    let rcode = match action.get("rcode").and_then(|v| v.as_str()) {
        Some(r) => parse_rcode(r)?,
        None => ResponseCode::NoError,
    };
    let (mut message, name) = new_response(query_id, domain, query_type, rcode)?;
    let mut total = 0;
    for (section, key) in [(0, "answers"), (1, "authority"), (2, "additional")] {
        let default_name = (section == 0).then_some(&name);
        let records = super::records::records_from_json(
            action.get(key),
            None,
            default_name,
            key,
            MAX_ANSWER_RECORDS,
        )?;
        total += records.len();
        if total > MAX_ANSWER_RECORDS {
            anyhow::bail!("the answer holds more than {MAX_ANSWER_RECORDS} records");
        }
        for r in records {
            match section {
                0 => message.add_answer(r),
                1 => message.add_name_server(r),
                _ => message.add_additional(r),
            };
        }
    }
    finish_response(message)
}

/// `send_dns_refused`: REFUSED (RCODE 5), the answer for a query or transfer this server will
/// not serve to this client.
fn execute_send_dns_refused(action: &serde_json::Value) -> Result<ActionResult> {
    let query_id = parse_query_id(action)?;
    let domain = required_str(action, "domain")?;
    let query_type = match action.get("query_type").and_then(|v| v.as_str()) {
        Some(qt) => parse_record_type(qt)?,
        None => RecordType::A,
    };
    let (message, _) = new_response(query_id, domain, query_type, ResponseCode::Refused)?;
    finish_response(message)
}

fn send_dns_a_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_a_response".to_string(),
        description: "Answer a query whose query_type is A with an IPv4 address. Only for query_type A: a TXT query is answered with send_dns_txt_response, AAAA with send_dns_aaaa_response, MX with send_dns_mx_response. This is the correct DNS-specific action - do NOT use generic 'send_data' or 'show_message' actions for DNS responses. Always include the query_id from the request, the domain name, and the IPv4 address to return.".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request (MUST match the request)".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (e.g., 'example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "ip".to_string(),
                type_hint: "string".to_string(),
                description: "IPv4 address to return (e.g., '192.0.2.1' or '93.184.216.34')".to_string(),
                required: true,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Time-to-live in seconds (how long clients should cache this response). Default: 300".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_a_response",
            "query_id": 12345,
            "domain": "example.com",
            "ip": "192.0.2.1",
            "ttl": 300
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS A {domain} -> {ip}")
                .with_debug("DNS A response: {domain} -> {ip} (TTL={ttl})")
                .with_trace("DNS A response: {json_pretty(.)}"),
        ),
    }
}

fn send_dns_aaaa_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_aaaa_response".to_string(),
        description: "Send DNS AAAA record response (IPv6 address)".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (e.g., 'example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "ip".to_string(),
                type_hint: "string".to_string(),
                description: "IPv6 address to return (e.g., '2001:db8::1')".to_string(),
                required: true,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Time-to-live in seconds. Default: 300".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_aaaa_response",
            "query_id": 12345,
            "domain": "example.com",
            "ip": "2001:db8::1",
            "ttl": 300
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS AAAA {domain} -> {ip}")
                .with_debug("DNS AAAA response: {domain} -> {ip} (TTL={ttl})"),
        ),
    }
}

fn send_dns_cname_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_cname_response".to_string(),
        description: "Send DNS CNAME record response (canonical name/alias)".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (e.g., 'www.example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Target domain name (e.g., 'example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "Record type the client actually asked for (A, AAAA, ...). Echoed back in the question section. Default: CNAME".to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Time-to-live in seconds. Default: 300".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_cname_response",
            "query_id": 12345,
            "domain": "www.example.com",
            "target": "example.com",
            "ttl": 300
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS CNAME {domain} -> {target}")
                .with_debug("DNS CNAME response: {domain} -> {target} (TTL={ttl})"),
        ),
    }
}

fn send_dns_mx_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_mx_response".to_string(),
        description: "Send DNS MX record response (mail exchange)".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (e.g., 'example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "exchange".to_string(),
                type_hint: "string".to_string(),
                description: "Mail server domain (e.g., 'mail.example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "preference".to_string(),
                type_hint: "number".to_string(),
                description: "MX preference (priority, lower = higher priority). Default: 10"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Time-to-live in seconds. Default: 300".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_mx_response",
            "query_id": 12345,
            "domain": "example.com",
            "exchange": "mail.example.com",
            "preference": 10,
            "ttl": 300
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS MX {domain} -> {exchange} (pref={preference})")
                .with_debug(
                    "DNS MX response: {domain} -> {exchange} (pref={preference}, TTL={ttl})",
                ),
        ),
    }
}

fn send_dns_txt_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_txt_response".to_string(),
        description: "Answer a query whose query_type is TXT with a text record - the only action for TXT queries. A TXT question asks for text, never for an address: when the instruction says to answer text queries with some text, this carries that text.".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (e.g., 'example.com')".to_string(),
                required: true,
            },
            Parameter {
                name: "text".to_string(),
                type_hint: "string".to_string(),
                description: "Text data to return. At most 255 octets: it is emitted as a \
                     single DNS <character-string>, whose length is one octet (RFC 1035 \
                     §3.3). Longer text is refused rather than split."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Time-to-live in seconds. Default: 300".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_txt_response",
            "query_id": 12345,
            "domain": "example.com",
            "text": "v=spf1 include:_spf.example.com ~all",
            "ttl": 300
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS TXT {domain}")
                .with_debug("DNS TXT response: {domain} -> \"{text}\" (TTL={ttl})"),
        ),
    }
}

fn send_dns_nxdomain_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_nxdomain".to_string(),
        description: "IMPORTANT: Use this action to respond when a DNS domain does not exist. This is the correct DNS-specific action for NXDOMAIN responses - do NOT use generic error actions. This tells the client that the requested domain name does not exist in the DNS system.".to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "DNS query ID from the request (MUST match the request)".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "Domain name being queried (the nonexistent domain)".to_string(),
                required: true,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "Record type from the request (A, AAAA, MX, TXT, ...). Echoed back in the question section so the client can match the response to its query. Default: A".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_nxdomain",
            "query_id": 12345,
            "domain": "nonexistent.example.com",
            "query_type": "A"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS NXDOMAIN {domain}")
                .with_debug("DNS NXDOMAIN response: {domain}"),
        ),
    }
}

fn send_dns_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_response".to_string(),
        description: "ESCAPE HATCH - only for record types that have no dedicated action (NS, SOA, PTR, SRV, CAA, ...). Prefer send_dns_a_response / send_dns_aaaa_response / send_dns_cname_response / send_dns_mx_response / send_dns_txt_response / send_dns_nxdomain, which build the wire format for you. This action requires you to hand-assemble the full DNS message, including echoing the query ID and the question section.".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Complete DNS response message in RFC 1035 wire format, hex-encoded (at least 12 bytes / 24 hex characters). Not base64, not plain text - invalid hex is rejected.".to_string(),
            required: true,
        }],
        // A complete RFC 1035 response: id=0x1234, flags 0x8180 (QR|RD|RA), one
        // question (example.com A IN) and one answer (compressed name pointer
        // 0xc00c, A IN, TTL 300, rdlength 4, 93.184.216.34). The previous example
        // was abbreviated with an ellipsis and omitted the 2-byte id, so it was
        // neither valid hex nor a DNS message.
        example: json!({
            "type": "send_dns_response",
            "data": "123481800001000100000000076578616d706c6503636f6d0000010001\
                     c00c000100010000012c00045db8d822"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS raw response {output_bytes}B")
                .with_debug("DNS send_dns_response: {output_bytes}B"),
        ),
    }
}

fn ignore_query_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_query".to_string(),
        description: "Ignore this DNS query and don't send a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_query"
        }),
        log_template: Some(LogTemplate::new().with_debug("DNS ignore_query")),
    }
}

fn record_shape() -> &'static str {
    "Each record is an object: {\"name\": \"www.example.com.\", \"type\": \"A\", \"ttl\": 300, \
     \"ip\": \"192.0.2.1\"}. Fields by type: A/AAAA ip; CNAME/NS/PTR target; MX preference, \
     exchange; TXT text (a string, or an array of strings of at most 255 octets each); SRV \
     priority, weight, port, target; SOA mname, rname, serial, refresh, retry, expire, minimum. \
     ttl defaults to 300. In a zone, a name may be relative to the zone (\"www\") or \"@\" for \
     the apex."
}

fn send_dns_records_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_records".to_string(),
        description: format!(
            "Answer a query with any records: several at once (a round-robin of A records, \
             all of a name's MX records), types with no dedicated action (NS, SOA, PTR, SRV), \
             or an authority section (the SOA of a negative answer). An answer record with no \
             'name' takes the queried domain. 'rcode' defaults to NOERROR; NOERROR with no \
             answers is the right reply when the name exists but has no record of that type. \
             At most {MAX_ANSWER_RECORDS} records. {}",
            record_shape()
        ),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "Echo query_id from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "The queried domain, from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "The queried type, from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "answers".to_string(),
                type_hint: "array".to_string(),
                description: "The records that answer the question, each an object with \
                    'type' and its fields; a record without 'name' takes the queried domain. \
                    Leave empty (with NOERROR) when the name exists but has no record of this \
                    type"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "authority".to_string(),
                type_hint: "array".to_string(),
                description: "Authority records, e.g. the zone's SOA for a negative answer"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "additional".to_string(),
                type_hint: "array".to_string(),
                description: "Additional records, e.g. the A records of an MX target".to_string(),
                required: false,
            },
            Parameter {
                name: "rcode".to_string(),
                type_hint: "string".to_string(),
                description: "NOERROR (default), NXDOMAIN, REFUSED, SERVFAIL, NOTIMP or FORMERR"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_records",
            "query_id": 12345,
            "domain": "example.com",
            "query_type": "NS",
            "answers": [
                {"type": "NS", "target": "ns1.example.com."},
                {"type": "NS", "target": "ns2.example.com."}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS {query_type} {domain} -> records")
                .with_debug("DNS send_dns_records {domain} ({output_bytes}B)"),
        ),
    }
}

fn send_dns_refused_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_refused".to_string(),
        description: "Refuse the query (RCODE REFUSED): this server will not answer it for \
             this client. The answer to a zone transfer your instructions do not allow."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "Echo query_id from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "domain".to_string(),
                type_hint: "string".to_string(),
                description: "The queried domain or zone, from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "The queried type, from the event (AXFR or IXFR for a transfer)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_refused",
            "query_id": 12345,
            "domain": "example.com",
            "query_type": "AXFR"
        }),
        log_template: Some(LogTemplate::new().with_info("DNS {domain} -> REFUSED")),
    }
}

fn send_dns_zone_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_zone".to_string(),
        description: format!(
            "Transfer the whole zone (AXFR). Give the zone's SOA and every other record in it; \
             the server sends SOA, the records, SOA again, split over as many messages as it \
             takes, and for a signed zone adds the DNSKEY, every signature and the NSEC chain. \
             Also a valid answer to IXFR (RFC 1995 allows a full zone in reply); over UDP the \
             server sends the SOA alone instead, and the client asks again over TCP. Every record \
             must be inside the zone; the SOA goes in 'soa', not among the records. {}",
            record_shape()
        ),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "Echo query_id from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "zone".to_string(),
                type_hint: "string".to_string(),
                description: "The zone's name, from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "soa".to_string(),
                type_hint: "object".to_string(),
                description: "The zone's SOA: mname, rname, serial, refresh, retry, expire, \
                    minimum"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "records".to_string(),
                type_hint: "array".to_string(),
                description: "Every other record in the zone".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dns_zone",
            "query_id": 12345,
            "zone": "example.com.",
            "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                    "serial": 2026101101, "refresh": 3600, "retry": 600,
                    "expire": 604800, "minimum": 300},
            "records": [
                {"name": "@", "type": "NS", "target": "ns1.example.com."},
                {"name": "ns1", "type": "A", "ip": "192.0.2.53"},
                {"name": "www", "type": "A", "ip": "192.0.2.80"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS AXFR {zone}")
                .with_debug("DNS send_dns_zone {zone}"),
        ),
    }
}

fn send_dns_ixfr_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_ixfr".to_string(),
        description: "Answer an IXFR with the changes since the client's serial \
             (client_serial in the event). Each change names the serial it ends at, the \
             records it deleted and the records it added, oldest first; the last change's \
             serial must equal the new SOA's. With no changes, the client is told it is \
             current. If you cannot list the changes, answer with send_dns_zone instead. Not \
             for a signed zone: answer its IXFR with send_dns_zone."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "query_id".to_string(),
                type_hint: "number".to_string(),
                description: "Echo query_id from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "zone".to_string(),
                type_hint: "string".to_string(),
                description: "The zone's name, from the event".to_string(),
                required: true,
            },
            Parameter {
                name: "soa".to_string(),
                type_hint: "object".to_string(),
                description: "The zone's current SOA".to_string(),
                required: true,
            },
            Parameter {
                name: "changes".to_string(),
                type_hint: "array".to_string(),
                description: "[{\"serial\": N, \"deleted\": [records], \"added\": [records]}], \
                    oldest first"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dns_ixfr",
            "query_id": 12345,
            "zone": "example.com.",
            "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                    "serial": 2026101102},
            "changes": [{
                "serial": 2026101102,
                "deleted": [{"name": "www", "type": "A", "ip": "192.0.2.80"}],
                "added": [{"name": "www", "type": "A", "ip": "192.0.2.81"}]
            }]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("DNS IXFR {zone}")
                .with_debug("DNS send_dns_ixfr {zone}"),
        ),
    }
}

// ============================================================================
// DNS Event Type Constants
// ============================================================================

/// DNS query event - triggered when DNS client sends a query
pub static DNS_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dns_query",
        "DNS client sent a query for domain resolution",
        serde_json::json!({
            "type": "send_dns_a_response",
            "query_id": 12345,
            "domain": "example.com",
            "ip": "93.184.216.34",
            "ttl": 300
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query ID from the request packet".to_string(),
            required: true,
        },
        Parameter {
            name: "domain".to_string(),
            type_hint: "string".to_string(),
            description: "Domain name being queried".to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "DNS query type (A, AAAA, MX, TXT, CNAME, etc.). Decides the action: A -> send_dns_a_response, AAAA -> send_dns_aaaa_response, MX -> send_dns_mx_response, TXT -> send_dns_txt_response, CNAME -> send_dns_cname_response; NS, SOA, PTR, SRV, or several records at once -> send_dns_records.".to_string(),
            required: true,
        },
        Parameter {
            name: "transport".to_string(),
            type_hint: "string".to_string(),
            description: "\"udp\" or \"tcp\". Informational: an answer too large for the \
                client's UDP buffer is truncated for you and the client retries over TCP."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "dnssec_ok".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client set the DO bit. Informational: signatures are added for \
                you when the server signs this zone."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "The address the query came from. Over UDP it is unauthenticated: \
                anyone can put another host's address on a datagram."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "number".to_string(),
            description: "The source port the query came from".to_string(),
            required: true,
        },
    ])
    .with_actions(DnsProtocol::query_actions())
    .with_alternative_example(serde_json::json!({
        "type": "send_dns_nxdomain",
        "query_id": 12345,
        "domain": "unknown.example.com"
    }))
    .with_alternative_example(serde_json::json!({
        "type": "send_dns_aaaa_response",
        "query_id": 12345,
        "domain": "example.com",
        "ip": "2606:2800:220:1:248:1893:25c8:1946",
        "ttl": 300
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("DNS {query_type} {domain} from {client_ip}")
            .with_debug("DNS query ID={query_id}, type={query_type}, domain={domain}")
            .with_trace("DNS query: {json_pretty(.)}"),
    )
});

/// A zone transfer request: AXFR or IXFR, over TCP (or IXFR over UDP).
pub static DNS_ZONE_TRANSFER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dns_zone_transfer",
        "A client asked to transfer a zone: the whole zone (AXFR) or the changes since its \
         serial (IXFR). Transfer only a zone your instructions give this server, and only to a \
         client_ip they allow; otherwise refuse with send_dns_refused. Over UDP the client's \
         address can be forged, so send_dns_zone there is answered with the SOA alone and the \
         client must ask again over TCP.",
        serde_json::json!({
            "type": "send_dns_zone",
            "query_id": 12345,
            "zone": "example.com.",
            "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                    "serial": 2026101101},
            "records": [{"name": "www", "type": "A", "ip": "192.0.2.80"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query ID, to echo".to_string(),
            required: true,
        },
        Parameter {
            name: "zone".to_string(),
            type_hint: "string".to_string(),
            description: "The zone asked for".to_string(),
            required: true,
        },
        Parameter {
            name: "transfer_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"AXFR\" (whole zone) or \"IXFR\" (changes since client_serial)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_serial".to_string(),
            type_hint: "number".to_string(),
            description: "IXFR only: the SOA serial the client holds".to_string(),
            required: false,
        },
        Parameter {
            name: "transport".to_string(),
            type_hint: "string".to_string(),
            description: "\"tcp\", or \"udp\" for an IXFR. Over UDP send_dns_zone is always \
                answered with the SOA alone, and a send_dns_ixfr difference too large for UDP \
                is too; either sends the client to TCP"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "signed".to_string(),
            type_hint: "boolean".to_string(),
            description: "The server signs this zone; answer an IXFR with send_dns_zone"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "The address asking for the transfer; decide by it whether this \
                client may have the zone. Over UDP it is unauthenticated."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "number".to_string(),
            description: "The source port the transfer request came from".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_dns_zone_action(),
        send_dns_ixfr_action(),
        send_dns_refused_action(),
        ignore_query_action(),
    ])
    .with_alternative_example(serde_json::json!({
        "type": "send_dns_refused",
        "query_id": 12345,
        "domain": "example.com.",
        "query_type": "AXFR"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("DNS {transfer_type} {zone} from {client_ip}")
            .with_debug("DNS {transfer_type} {zone} id={query_id} via {transport}"),
    )
});

/// Get DNS event types
pub fn get_dns_event_types() -> Vec<EventType> {
    vec![DNS_QUERY_EVENT.clone(), DNS_ZONE_TRANSFER_EVENT.clone()]
}
