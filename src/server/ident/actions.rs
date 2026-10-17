//! Ident (RFC 1413) protocol actions.
//!
//! The wire protocol is two lines. The client sends a port pair; the server answers with
//! either a USERID line or an ERROR line. Everything interesting is in what may go into
//! those lines, and this module is deliberately strict about it:
//!
//! * **The port pair is echoed, never invented.** RFC 1413 §3 has the client match a reply
//!   to its query by the port pair, so a reply carrying a different pair is unmatchable —
//!   indistinguishable, to the client, from no reply at all. Both wire actions take the pair
//!   as required parameters, and `mod.rs` additionally rewrites it to the pair actually
//!   received (see `enforce_port_pair` there).
//! * **Every field the model supplies is sanitised.** A `userid` containing CRLF would let a
//!   model append a second reply line to the stream; `sanitize_token` removes control
//!   characters and the `:` separator from the fields where the grammar forbids them.
//! * **The four error tokens are a closed set.** RFC 1413 §6 defines exactly `INVALID-PORT`,
//!   `NO-USER`, `HIDDEN-USER` and `UNKNOWN-ERROR`. Anything else is rejected with an error
//!   naming the accepted set rather than being passed through — a client parses this field,
//!   it is not free text.
//!
//! **NetGet never looks up a real user.** Ident's entire purpose is disclosing which local
//! account owns a TCP connection, so a NetGet ident server that consulted the host would be
//! disclosing the operator's own accounts to whoever asked. Nothing here reads `/etc/passwd`,
//! socket ownership, `getpwuid`, or any other OS state: the model invents the answer, and
//! that is the only source of a userid.

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

/// The four error tokens RFC 1413 §6 defines. Not extensible: a client parses this field.
pub const IDENT_ERROR_TOKENS: [&str; 4] =
    ["INVALID-PORT", "NO-USER", "HIDDEN-USER", "UNKNOWN-ERROR"];

/// RFC 1413 §6 caps a userid at 512 octets. Longer values are truncated rather than
/// rejected, because a reply is better than a timeout and the model has already decided.
const MAX_USERID_LEN: usize = 512;

/// `opsys` and `charset` are short tokens from the Assigned Numbers "SYSTEM NAMES" and
/// character-set registries; nothing legitimate is anywhere near this long.
const MAX_TOKEN_LEN: usize = 64;

pub struct IdentProtocol;

impl IdentProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IdentProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip everything the reply grammar cannot carry.
///
/// The reply is a single CRLF-terminated line whose fields are separated by `:`, so a value
/// containing CR, LF or `:` would either forge a second reply or shift every field after it.
/// Control characters go too — this text is printed by whatever the client is (historically,
/// an IRC daemon's log).
fn sanitize_token(raw: &str, max_len: usize) -> String {
    let without_separator: String = raw.chars().filter(|c| *c != ':').collect();
    crate::utils::sanitize::token(&without_separator, max_len)
}

/// A port the RFC will accept: `1..=65535`. Zero and out-of-range are `INVALID-PORT`
/// territory, which is a parse verdict rather than something to put on the wire as a port.
fn port_param(action: &serde_json::Value, key: &str) -> Result<u16> {
    let raw = action
        .get(key)
        .with_context(|| format!("Missing '{}' parameter", key))?;

    // Accept a JSON number or a numeric string: small models produce both, and rejecting
    // "113" while accepting 113 would be a gratuitous failure on a value we can read.
    let n = match raw.as_i64() {
        Some(n) => n,
        None => raw
            .as_str()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .with_context(|| format!("'{}' must be an integer TCP port, got {}", key, raw))?,
    };

    if !(1..=65535).contains(&n) {
        return Err(anyhow::anyhow!(
            "'{}' must be a TCP port in 1..=65535, got {}",
            key,
            n
        ));
    }
    Ok(n as u16)
}

/// Build the RFC 1413 §3 success reply.
///
/// `<port-on-server> , <port-on-client> : USERID : <opsys>[,<charset>] : <userid>`
pub fn format_userid_reply(
    server_port: u16,
    client_port: u16,
    opsys: &str,
    charset: Option<&str>,
    userid: &str,
) -> Vec<u8> {
    let opsys = {
        let s = sanitize_token(opsys, MAX_TOKEN_LEN);
        if s.is_empty() {
            "UNIX".to_string()
        } else {
            s
        }
    };
    // The charset, when present, is appended to opsys after a comma — it is not its own
    // field, so a comma inside it would create a third one.
    let opsys_field = match charset {
        Some(cs) => {
            let cs = sanitize_token(cs, MAX_TOKEN_LEN).replace(',', "");
            if cs.is_empty() {
                opsys
            } else {
                format!("{},{}", opsys, cs)
            }
        }
        None => opsys,
    };

    let userid = sanitize_token(userid, MAX_USERID_LEN);

    format!(
        "{} , {} : USERID : {} : {}\r\n",
        server_port, client_port, opsys_field, userid
    )
    .into_bytes()
}

/// Build the RFC 1413 §6 error reply. `token` must already be one of [`IDENT_ERROR_TOKENS`].
pub fn format_error_reply(server_port: u16, client_port: u16, token: &str) -> Vec<u8> {
    format!("{} , {} : ERROR : {}\r\n", server_port, client_port, token).into_bytes()
}

/// Error reply for a query whose port pair could not be parsed at all.
///
/// The pair is echoed as the client wrote it (sanitised), because there are no numbers to
/// echo and the RFC's reply grammar still wants that position filled.
pub fn format_error_reply_raw_pair(echo: &str, token: &str) -> Vec<u8> {
    format!("{} : ERROR : {}\r\n", echo, token).into_bytes()
}

impl Protocol for IdentProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Ident is purely reactive: the server says nothing until a query arrives, and the
        // connection is over one reply later. There is nothing an operator could usefully
        // push into it out of band.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_ident_userid_action(),
            send_ident_error_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Ident"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_ident_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Ident"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ident", "identd", "rfc1413", "auth"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(113))
            .well_known_port(113)
            .implementation(
                "Hand-rolled tokio TCP line reader; no library. One query, one reply, close, \
                 per RFC 1413. INVALID-PORT is decided in Rust without an LLM call.",
            )
            .llm_control(
                "The userid, the opsys/charset tokens, and whether the answer is a USERID or \
                 one of the four RFC 1413 error tokens. The port pair is echoed by NetGet, \
                 not chosen by the model.",
            )
            .e2e_testing(
                "tests/server/ident/e2e_test.rs, 3 tests, 9 LLM calls, raw TCP sockets only. \
                 Covers the USERID line, the error tokens, whitespace tolerance, INVALID-PORT \
                 refused with no LLM call (asserted by call count), and a wrong port pair \
                 from the handler being rewritten to the queried one. No third-party ident \
                 client validated this server - see notes.",
            )
            .notes(
                "Experimental, and it is unlikely to move: no runnable third-party ident \
                 CLIENT exists to validate it against. crates.io has no RFC 1413 client (the \
                 'ident' namespace is entirely identity/identifier crates); there is no \
                 ident/identd client binary on macOS and no Homebrew formula for one; PyPI \
                 has no working ident package. The realistic real-world client is an IRC \
                 daemon (ngircd links libident), but every ident client hardcodes \
                 destination port 113 because RFC 1413 has no notion of a configurable \
                 server port - so none can be pointed at an ephemeral loopback port, and 113 \
                 needs root. Homebrew's libident is a C library with no CLI and the same port \
                 limitation. This is the dhcp situation: the strongest evidence the protocol \
                 admits is an in-test client written from the wire format, which per this \
                 repo's bar is an independent reading of the spec, not an independent \
                 implementation. NetGet never consults the host: no /etc/passwd, no socket \
                 ownership, no getpwuid. The model invents every userid, which is the only \
                 safe way to run a protocol whose purpose is disclosing account identity.",
            )
            .max_inbound_bytes(crate::server::ident::MAX_QUERY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Ident (RFC 1413) identification server - answers 'who owns this TCP connection'"
    }

    fn example_prompt(&self) -> &'static str {
        "Ident server on port 113 - answer every query with the userid 'nobody' on UNIX"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven
            json!({
                "type": "open_server",
                "port": 113,
                "base_stack": "ident",
                "instruction": "Ident server. Answer queries for port 6667 with the userid 'ircuser' on UNIX; answer everything else with ERROR NO-USER."
            }),
            // Script handler - echo the pair the event carries, which is the whole trick.
            json!({
                "type": "open_server",
                "port": 113,
                "base_stack": "ident",
                "event_handlers": [{
                    "event_pattern": "ident_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Echo the port pair back verbatim - the client matches on it.\nrespond([{'type': 'send_ident_userid', 'server_port': event['server_port'], 'client_port': event['client_port'], 'opsys': 'UNIX', 'userid': 'nobody'}])"
                    }
                }]
            }),
            // Static handler. A static reply cannot echo the pair, so it is only correct for
            // a client whose port pair you already know; the script form above is the
            // general answer.
            json!({
                "type": "open_server",
                "port": 113,
                "base_stack": "ident",
                "event_handlers": [{
                    "event_pattern": "ident_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_ident_error",
                            "server_port": 113,
                            "client_port": 1234,
                            "error": "HIDDEN-USER"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for IdentProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ident::IdentServer;
            IdentServer::spawn_with_llm_actions(
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
            "send_ident_userid" => self.execute_send_ident_userid(action),
            "send_ident_error" => self.execute_send_ident_error(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Ident action: {}", action_type)),
        }
    }
}

impl IdentProtocol {
    fn execute_send_ident_userid(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_port = port_param(&action, "server_port")?;
        let client_port = port_param(&action, "client_port")?;

        let userid = action
            .get("userid")
            .and_then(|v| v.as_str())
            .context("Missing 'userid' parameter")?;

        if sanitize_token(userid, MAX_USERID_LEN).is_empty() {
            return Err(anyhow::anyhow!(
                "'userid' is empty after removing characters the RFC 1413 reply line cannot \
                 carry (control characters and ':'); supply a plain account name"
            ));
        }

        // RFC 1413 §6: opsys should come from the Assigned Numbers SYSTEM NAMES list.
        // "UNIX" is what essentially every real identd answers, so it is the default.
        let opsys = action
            .get("opsys")
            .and_then(|v| v.as_str())
            .unwrap_or("UNIX");

        let charset = action.get("charset").and_then(|v| v.as_str());

        Ok(ActionResult::Output(format_userid_reply(
            server_port,
            client_port,
            opsys,
            charset,
            userid,
        )))
    }

    fn execute_send_ident_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_port = port_param(&action, "server_port")?;
        let client_port = port_param(&action, "client_port")?;

        let raw = action
            .get("error")
            .and_then(|v| v.as_str())
            .context("Missing 'error' parameter")?;

        // Closed set. A client parses this field, so an unrecognised token is worse than a
        // rejected action: the reply would look well-formed and mean nothing.
        let upper = raw.trim().to_ascii_uppercase();
        let token = IDENT_ERROR_TOKENS
            .iter()
            .find(|t| **t == upper)
            .with_context(|| {
                format!(
                    "'{}' is not an RFC 1413 error token. Use one of: {}",
                    raw,
                    IDENT_ERROR_TOKENS.join(", ")
                )
            })?;

        Ok(ActionResult::Output(format_error_reply(
            server_port,
            client_port,
            token,
        )))
    }
}

fn port_pair_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "The port on THIS server from the query, echoed back unchanged. Copy \
                          it from the event's server_port - the client matches the reply to \
                          its query by the port pair, so a different value is unmatchable"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "The port on the querying client from the query, echoed back \
                          unchanged. Copy it from the event's client_port"
                .to_string(),
            required: true,
        },
    ]
}

fn send_ident_userid_action() -> ActionDefinition {
    let mut parameters = port_pair_parameters();
    parameters.extend([
        Parameter {
            name: "userid".to_string(),
            type_hint: "string".to_string(),
            description: "The account name to claim owns the connection. Invent it - NetGet \
                          never looks up a real local user, and must not be asked to"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "opsys".to_string(),
            type_hint: "string".to_string(),
            description: "Operating system token from the Assigned Numbers SYSTEM NAMES list, \
                          e.g. UNIX, WIN32, OTHER. Defaults to UNIX"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "charset".to_string(),
            type_hint: "string".to_string(),
            description: "Optional character set appended to opsys after a comma, e.g. \
                          US-ASCII, giving 'UNIX,US-ASCII'"
                .to_string(),
            required: false,
        },
    ]);

    ActionDefinition {
        name: "send_ident_userid".to_string(),
        description: "Answer an ident query with a userid: '<server_port> , <client_port> : \
                      USERID : <opsys> : <userid>'. The server closes the connection after \
                      the reply, as RFC 1413 requires"
            .to_string(),
        parameters,
        example: json!({
            "type": "send_ident_userid",
            "server_port": 6193,
            "client_port": 23,
            "opsys": "UNIX",
            "userid": "stjohns"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IDENT {server_port},{client_port} USERID {userid}")
                .with_debug(
                    "IDENT send_ident_userid: {server_port},{client_port} opsys={opsys} \
                     userid={userid}",
                ),
        ),
    }
}

fn send_ident_error_action() -> ActionDefinition {
    let mut parameters = port_pair_parameters();
    parameters.push(Parameter {
        name: "error".to_string(),
        type_hint: "string".to_string(),
        description: "One of exactly four RFC 1413 tokens: INVALID-PORT (a port was out of \
                      range or unparseable), NO-USER (no connection matches the pair), \
                      HIDDEN-USER (it matches but the owner declined to be named), \
                      UNKNOWN-ERROR (anything else). No other value is accepted"
            .to_string(),
        required: true,
    });

    ActionDefinition {
        name: "send_ident_error".to_string(),
        description: "Refuse an ident query: '<server_port> , <client_port> : ERROR : <token>'. \
                      HIDDEN-USER is the right answer when you do not want to name anyone; \
                      NO-USER says the connection does not exist. The server closes after \
                      the reply"
            .to_string(),
        parameters,
        example: json!({
            "type": "send_ident_error",
            "server_port": 6193,
            "client_port": 23,
            "error": "NO-USER"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IDENT {server_port},{client_port} ERROR {error}")
                .with_debug("IDENT send_ident_error: {server_port},{client_port} {error}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the connection. RFC 1413 has the server close after every reply \
                      and NetGet does so automatically, so this is only needed to hang up \
                      from the dashboard - and answering with it ALONE produces no reply, \
                      which NetGet then fills in as ERROR : UNKNOWN-ERROR rather than \
                      leaving the client to time out"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("IDENT connection closed")
                .with_debug("IDENT close_connection"),
        ),
    }
}

/// Raised once per well-formed query. A query whose ports do not parse never reaches the
/// model — that is a parse verdict (`INVALID-PORT`), not a decision, and `mod.rs` answers it
/// in Rust without an LLM call.
pub static IDENT_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ident_query",
        "A client asked which local account owns the TCP connection identified by this port \
         pair. Answer with an invented userid or one of the four RFC 1413 error tokens; echo \
         server_port and client_port back unchanged.",
        json!({
            "type": "send_ident_userid",
            "server_port": 113,
            "client_port": 49152,
            "opsys": "UNIX",
            "userid": "nobody"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Port on this server named in the query. Echo it back unchanged"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Port on the querying host named in the query. Echo it back unchanged"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "source_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address:port the query itself arrived from".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("IDENT query {server_port},{client_port}")
            .with_debug("IDENT query: {server_port},{client_port} from {source_addr}")
            .with_trace("IDENT: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_ident_userid_action(),
        send_ident_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_ident_error",
        "server_port": 113,
        "client_port": 49152,
        "error": "HIDDEN-USER"
    }))
});

pub fn get_ident_event_types() -> Vec<EventType> {
    vec![IDENT_QUERY_EVENT.clone()]
}
