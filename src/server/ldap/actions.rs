//! LDAP protocol actions implementation.
//!
//! The directory is entirely LLM-supplied: nothing here stores an entry, an attribute or a
//! password. A bind is granted or refused by the model; a search returns whatever entries the
//! model names; an add, modify or delete is acknowledged by the model and changes nothing on
//! this side, because there is nothing on this side to change.
//!
//! Actions carry structured entries (`{"dn": ..., "attributes": {...}}`), never bytes: the
//! BER encoding of every response is built here from those fields.

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
use tracing::debug;

/// LDAP protocol action handler
pub struct LdapProtocol;

/// Read the model's `result_code`, refusing anything the one-byte ENUMERATED cannot carry.
///
/// This was `as_u64()… as u8`, which wraps in silence, and for LDAP the wrap lands exactly on
/// the worst value: **`result_code: 256` encodes `0`, and `0` is `success`**. Every refusal
/// the model can express is a multiple of 256 away from telling the client the operation
/// succeeded — a directory asserting a bind, a write or a search completed when it did not.
///
/// Refusing beats clamping: 255 is not what the model asked for either, and the message is
/// what the repair loop reads. RFC 4511 §4.1.9 makes resultCode extensible, so the honest
/// bound is what this encoder can put on the wire rather than a list of named codes.
fn parse_result_code(action: &serde_json::Value, default: u8) -> Result<u8> {
    let value = match action.get("result_code") {
        None => return Ok(default),
        Some(v) if v.is_null() => return Ok(default),
        Some(v) => v,
    };
    let raw = value
        .as_u64()
        .with_context(|| format!("'result_code' must be a number, got {value}"))?;
    if raw > u8::MAX as u64 {
        return Err(anyhow::anyhow!(
            "'result_code' {raw} does not fit the LDAP resultCode this server encodes \
             (0-255). 0 is success, 32 noSuchObject, 49 invalidCredentials, 50 \
             insufficientAccessRights, 68 entryAlreadyExists."
        ));
    }
    Ok(raw as u8)
}

/// Read the model's `message_id`, refusing anything outside LDAP's `INTEGER (0 .. maxInt)`.
///
/// `as i64 … as i32` wraps, so `4294967297` becomes `1` and the response is correlated with
/// whichever request happened to carry that id. A client matches replies by messageID alone,
/// so a wrapped one is answered to the wrong question or to none at all.
fn parse_message_id(action: &serde_json::Value) -> Result<i32> {
    let value = match action.get("message_id") {
        None => return Ok(1),
        Some(v) if v.is_null() => return Ok(1),
        Some(v) => v,
    };
    let raw = value
        .as_i64()
        .with_context(|| format!("'message_id' must be a number, got {value}"))?;
    if !(0..=i32::MAX as i64).contains(&raw) {
        return Err(anyhow::anyhow!(
            "'message_id' {raw} is outside LDAP's INTEGER (0 .. maxInt) range of \
             0-2147483647. Echo the message_id from the triggering event so the client can \
             match the reply to its request."
        ));
    }
    Ok(raw as i32)
}

impl LdapProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_ldap_bind_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_id = parse_message_id(&action)?;

        let success = action
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        let result_code = if success { 0 } else { 49 }; // 0 = success, 49 = invalidCredentials

        debug!(
            "LDAP sending bind response: success={}, message={}",
            success, message
        );

        let response = encode_bind_response(message_id, result_code, message);
        Ok(ActionResult::Output(response))
    }

    fn execute_ldap_search_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_id = parse_message_id(&action)?;

        let entries = action
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let result_code = parse_result_code(&action, 0)?;

        debug!(
            "LDAP sending search response: {} entries, result_code={}",
            entries.len(),
            result_code
        );

        // Build response with search entries + search done
        let mut response = Vec::new();

        // Send SearchResultEntry for each entry
        for entry in entries {
            let dn = entry.get("dn").and_then(|v| v.as_str()).unwrap_or("");

            let attributes = entry
                .get("attributes")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();

            response.extend_from_slice(&encode_search_entry(message_id, dn, attributes));
        }

        // Send SearchResultDone
        response.extend_from_slice(&encode_search_done(message_id, result_code, ""));

        Ok(ActionResult::Output(response))
    }

    fn execute_ldap_add_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_id = parse_message_id(&action)?;

        // Not defaulted to `true`. `success` is only consulted to pick a resultCode when the
        // model names none, so a forgotten field used to encode resultCode 0 - the directory
        // telling the client the entry was added. An omission is not an outcome. An explicit
        // `result_code` still wins on its own, so naming either field works as before.
        let success = action
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 68 = entryAlreadyExists
        let result_code = parse_result_code(&action, if success { 0 } else { 68 })?;

        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        debug!(
            "LDAP sending add response: success={}, result_code={}",
            success, result_code
        );

        let response = encode_ldap_result(message_id, 0x69, result_code, message); // 0x69 = AddResponse
        Ok(ActionResult::Output(response))
    }

    fn execute_ldap_modify_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_id = parse_message_id(&action)?;

        // See `execute_ldap_add_response`: an omitted `success` must not encode resultCode 0.
        let success = action
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 32 = noSuchObject
        let result_code = parse_result_code(&action, if success { 0 } else { 32 })?;

        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        debug!(
            "LDAP sending modify response: success={}, result_code={}",
            success, result_code
        );

        let response = encode_ldap_result(message_id, 0x67, result_code, message); // 0x67 = ModifyResponse
        Ok(ActionResult::Output(response))
    }

    fn execute_ldap_delete_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_id = parse_message_id(&action)?;

        // See `execute_ldap_add_response`: an omitted `success` must not encode resultCode 0.
        let success = action
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 32 = noSuchObject
        let result_code = parse_result_code(&action, if success { 0 } else { 32 })?;

        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        debug!(
            "LDAP sending delete response: success={}, result_code={}",
            success, result_code
        );

        let response = encode_ldap_result(message_id, 0x6B, result_code, message); // 0x6B = DelResponse
        Ok(ActionResult::Output(response))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for LdapProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "send_first".to_string(),
                type_hint: "boolean".to_string(),
                description: "Unsupported by this server and refused if set to true. LDAP: \
                                  the client sends a BindRequest or SearchRequest first and \
                                  every server message is a response framed against one."
                    .to_string(),
                required: false,
                example: serde_json::json!(false),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no LDAP message before the \
                              server closes it. Default 300, matching the window a `manual` \
                              rule gives a human to answer one event - a peer is often \
                              NetGet's own LDAP client, which sends nothing at all until \
                              someone uses [ send message ]. Lower it for a listener exposed \
                              to strangers."
                    .to_string(),
                required: false,
                example: serde_json::json!(300),
                default: Some(serde_json::json!(
                    super::FIRST_MESSAGE_READ_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established session may send nothing further between \
                              LDAP messages before the server closes it. Default 900."
                    .to_string(),
                required: false,
                example: serde_json::json!(900),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_MESSAGES_TIMEOUT.as_secs()
                )),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // LDAP doesn't need async actions for now
        Vec::new()
    }
    /// Every event advertises its own subset of these; this list is the union.
    ///
    /// `wait_for_more` used to be declared here and is gone: LDAP messages are framed by their
    /// BER length, the session reassembles them itself, and the session only ever looks for an
    /// `ActionResult::Output`. `ActionResult::WaitForMore` was discarded, so the client was
    /// left waiting for a response that would never come.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ldap_bind_response_action(),
            ldap_search_response_action(),
            ldap_add_response_action(),
            ldap_modify_response_action(),
            ldap_delete_response_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "LDAP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_ldap_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>LDAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ldap", "directory server"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        use crate::protocol::metadata::PrivilegeRequirement;

        ProtocolMetadataV2::builder()
            // Beta: exercised against TWO real, independent clients — ldap3 (Rust) and
            // OpenLDAP's own `ldapsearch` (C) — covering bind and search, with the write
            // operations covered by ldap3 alone. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            // 389 is below 1024 and is the port every LDAP client defaults to, so the
            // preflight check in server_startup.rs should fire rather than letting the bind
            // fail later with a bare EPERM.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(389))
            .well_known_port(389)
            .implementation("Manual ASN.1 BER encoding/decoding, no LDAP crate")
            .llm_control("Bind decisions, search results, add/modify/delete outcomes")
            .e2e_testing(
                "TWO independent clients, neither of them the crate this server frames with. \
                 (1) ldap3 0.11, a Rust LDAP client, in tests/server/ldap/e2e_test.rs: it \
                 binds, searches, adds, modifies and deletes, and parses entries through its \
                 own SearchEntry::construct, so a reply it rejected would fail rather than be \
                 counted as bytes on a socket. It is independent of `ldap3_proto` despite the \
                 similar name: different project, different authors. \
                 (2) OpenLDAP's `ldapsearch` -- C, written by the project that wrote the RFC -- \
                 in tests/server/ldap/real_client_test.rs: it completes a simple bind and a \
                 search, and the test parses the LDIF it rendered and asserts every value of \
                 each multi-valued SET OF, an entry long enough to force the long-form BER \
                 length, the bind diagnosticMessage, and noSuchObject (32) read off \
                 ldapsearch's own exit status. \
                 NEITHER is #[ignore]d and NEITHER is skip-gated: ldap3 is a plain optional \
                 dependency the `ldap` feature turns on, and the ldapsearch test FAILS, naming \
                 the install command, when no ldapsearch is found. \
                 The ldapsearch test was verified non-vacuous by breaking the server twice and \
                 watching the client's rendering change: truncating the attribute SET OF to its \
                 first value made ldapsearch print one objectClass instead of three, and \
                 forcing encode_ber_length to the short form made it print no LDIF at all and \
                 exit 254 with `ldap_result: Local error (-2)`. \
                 THIS FIELD ONCE CLAIMED `the ldapsearch/ldapadd command-line tools` WHILE \
                 NOTHING ASSERTING DROVE THEM -- ldapsearch appeared only in tests/eval, the \
                 real-model harness, which skips unless NETGET_USE_OLLAMA=1 and reports rather \
                 than asserts. That claim is now true for ldapsearch; `ldapadd` is still driven \
                 by nothing. \
                 UNPROVEN: LDAPS and StartTLS, SASL, referrals, and the write operations, which \
                 are acknowledged without anything changing.",
            )
            .notes(
                "LDAPv3 simple bind only - no SASL, no StartTLS, no LDAPS. Search filters, \
                 scope and requested-attribute lists are parsed off the wire but not \
                 evaluated: the model is given the base DN and scope and decides what to \
                 return. No directory is stored; add/modify/delete are acknowledged, not \
                 applied. No referrals, no schema validation, no access control beyond what \
                 the model chooses.",
            )
            .max_inbound_bytes(crate::server::ldap::MAX_LDAP_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "LDAP directory server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an LDAP directory server on port 389"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every search with an empty result set (echoing
        // the request's message_id), no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ldap_search":
    actions = [{"type": "ldap_search_response",
                "message_id": event.get("message_id", 1),
                "entries": []}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all LDAP responses intelligently
            json!({
                "type": "open_server",
                "port": 389,
                "base_stack": "ldap",
                "instruction": "LDAP directory server handling bind and search operations"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 389,
                "base_stack": "ldap",
                "event_handlers": [{
                    "event_pattern": "ldap_search",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 389,
                "base_stack": "ldap",
                "event_handlers": [{
                    "event_pattern": "ldap_bind",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "ldap_bind_response",
                            "message_id": 1,
                            "success": true
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for LdapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ldap::LdapServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // LDAP: the client sends a BindRequest or a SearchRequest first and every server
            // message is a response framed against one, so there is nothing for this to turn
            // on.
            //
            // This was `let _send_first = …`: read, then dropped on the floor. The September
            // sweep that fixed the same defect in seven other servers matched on a discarded
            // `_send_first` *parameter* and missed this one, because ldap discards it a layer
            // later, in a local binding.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the LDAP server: the client sends a \
                     BindRequest or SearchRequest first and every server message is a \
                     response framed against one."
                ));
            }

            // Both read bounds are tunable because their right value is a property of who is on
            // the other end, which only the operator knows. The defaults serve NetGet's own
            // client waiting on a human at `[ send message ]`; a listener exposed to strangers
            // wants the first one much lower.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            LdapServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
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
            "ldap_bind_response" => self.execute_ldap_bind_response(action),
            "ldap_search_response" => self.execute_ldap_search_response(action),
            "ldap_add_response" => self.execute_ldap_add_response(action),
            "ldap_modify_response" => self.execute_ldap_modify_response(action),
            "ldap_delete_response" => self.execute_ldap_delete_response(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown LDAP action: {}", action_type)),
        }
    }
}

// ============================================================================
// Action Definitions
// ============================================================================

fn ldap_bind_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ldap_bind_response".to_string(),
        description: "Respond to LDAP bind (authentication) request".to_string(),
        parameters: vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether bind was successful".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional diagnostic message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ldap_bind_response",
            "message_id": 1,
            "success": true,
            "message": "Bind successful"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LDAP bind: {success}")
                .with_debug("LDAP ldap_bind_response: success={success}"),
        ),
    }
}

fn ldap_search_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ldap_search_response".to_string(),
        description: "Answer an LDAP search with the entries the instruction says exist \
                      under the request's base_dn - and only those. Every entry's dn ends \
                      with the base_dn the client searched. When nothing exists there, send \
                      \"entries\": [] with result_code 0: a search that finds no one is a \
                      success, not an error. The example's entry is a stand-in for the shape; \
                      never send it as data."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "entries".to_string(),
                type_hint: "array".to_string(),
                description: "The matching entries, each {\"dn\": \"cn=...,<base_dn>\", \
                              \"attributes\": {\"name\": [\"value\", ...]}}. Every attribute \
                              value is a list of strings. [] when nothing matches."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "result_code".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP result code (0 = success, default: 0)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ldap_search_response",
            "message_id": 2,
            "entries": [
                {
                    "dn": "cn=Example Person,ou=example,dc=example,dc=org",
                    "attributes": {
                        "cn": ["Example Person"],
                        "mail": ["person@example.org"],
                        "objectClass": ["person", "inetOrgPerson"]
                    }
                }
            ],
            "result_code": 0
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LDAP search: {entries_len} entries")
                .with_debug("LDAP ldap_search_response: {entries_len} entries"),
        ),
    }
}

fn ldap_add_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ldap_add_response".to_string(),
        description: "Respond to LDAP add (create entry) request".to_string(),
        parameters: vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether add was successful".to_string(),
                required: true,
            },
            Parameter {
                name: "result_code".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP result code (0 = success, 68 = entryAlreadyExists)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional diagnostic message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ldap_add_response",
            "message_id": 3,
            "success": true,
            "result_code": 0,
            "message": "Entry added successfully"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LDAP add: {success}")
                .with_debug("LDAP ldap_add_response: success={success}"),
        ),
    }
}

fn ldap_modify_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ldap_modify_response".to_string(),
        description: "Respond to LDAP modify (update entry) request".to_string(),
        parameters: vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether modify was successful".to_string(),
                required: true,
            },
            Parameter {
                name: "result_code".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP result code (0 = success, 32 = noSuchObject)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional diagnostic message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ldap_modify_response",
            "message_id": 4,
            "success": true,
            "result_code": 0,
            "message": "Entry modified successfully"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LDAP modify: {success}")
                .with_debug("LDAP ldap_modify_response: success={success}"),
        ),
    }
}

fn ldap_delete_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ldap_delete_response".to_string(),
        description: "Respond to LDAP delete (remove entry) request".to_string(),
        parameters: vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID from the request".to_string(),
                required: true,
            },
            Parameter {
                name: "success".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether delete was successful".to_string(),
                required: true,
            },
            Parameter {
                name: "result_code".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP result code (0 = success, 32 = noSuchObject)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Optional diagnostic message".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ldap_delete_response",
            "message_id": 5,
            "success": true,
            "result_code": 0,
            "message": "Entry deleted successfully"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LDAP delete: {success}")
                .with_debug("LDAP ldap_delete_response: success={success}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the LDAP connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("LDAP connection closed")
                .with_debug("LDAP close_connection"),
        ),
    }
}

// ============================================================================
// Action Constants
// ============================================================================

pub static LDAP_BIND_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ldap_bind_response_action());
pub static LDAP_SEARCH_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ldap_search_response_action());
pub static LDAP_ADD_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ldap_add_response_action());
pub static LDAP_MODIFY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ldap_modify_response_action());
pub static LDAP_DELETE_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ldap_delete_response_action());
pub static CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| close_connection_action());

// ============================================================================
// Event Type Constants
// ============================================================================

/// LDAP bind event - triggered when client attempts to authenticate
pub static LDAP_BIND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_bind",
        "LDAP bind (authentication) request received",
        json!({
            "type": "ldap_bind_response",
            "message_id": 1,
            "success": true,
            "message": "Bind successful"
        }),
    )
    .with_alternative_example(json!({
        "type": "ldap_bind_response",
        "message_id": 1,
        "success": false,
        "message": "Invalid credentials"
    }))
    .with_parameters(vec![
        Parameter {
            name: "message_id".to_string(),
            type_hint: "number".to_string(),
            description: "LDAP message ID".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description: "LDAP protocol version (typically 3)".to_string(),
            required: true,
        },
        Parameter {
            name: "dn".to_string(),
            type_hint: "string".to_string(),
            description: "Distinguished Name for authentication".to_string(),
            required: true,
        },
        Parameter {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "Password for simple authentication (empty for an anonymous bind)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "auth_type".to_string(),
            type_hint: "string".to_string(),
            description: "'simple' or 'sasl'. SASL is not supported: the mechanism is reported \
                          but no credentials are available, so a SASL bind can only be refused."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        LDAP_BIND_RESPONSE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LDAP BIND {client_ip} dn={dn}")
            .with_debug("LDAP bind v{version} from {client_ip}:{client_port}, dn={dn}")
            .with_trace("LDAP bind: {json_pretty(.)}"),
    )
});

/// LDAP search event - triggered when client performs a directory search
pub static LDAP_SEARCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_search",
        "LDAP search request received",
        json!({
            "type": "ldap_search_response",
            "message_id": 2,
            "entries": [{
                "dn": "cn=Example Person,ou=example,dc=example,dc=org",
                "attributes": {
                    "cn": ["Example Person"],
                    "mail": ["person@example.org"],
                    "objectClass": ["person", "inetOrgPerson"]
                }
            }],
            "result_code": 0
        }),
    )
        .with_alternative_example(json!({
            "type": "ldap_search_response",
            "message_id": 2,
            "entries": [],
            "result_code": 0
        }))
        .with_parameters(vec![
            Parameter {
                name: "message_id".to_string(),
                type_hint: "number".to_string(),
                description: "LDAP message ID".to_string(),
                required: true,
            },
            Parameter {
                name: "base_dn".to_string(),
                type_hint: "string".to_string(),
                description: "Base DN the client searched. Answer only with entries at or \
                              under it; if the instruction puts nothing there, answer with \
                              no entries."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "authenticated".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether client is authenticated".to_string(),
                required: true,
            },
            Parameter {
                name: "bind_dn".to_string(),
                type_hint: "string".to_string(),
                description: "DN of authenticated user (empty if not authenticated)".to_string(),
                required: true,
            },
            Parameter {
                name: "scope".to_string(),
                type_hint: "string".to_string(),
                description: "'base', 'one' or 'sub'. Reported, not enforced - the entries you return are returned as-is.".to_string(),
                required: true,
            },
            Parameter {
                name: "filter".to_string(),
                type_hint: "string".to_string(),
                description: "Search filter in RFC 4515 text form, e.g. '(objectClass=person)'. Reported, not evaluated: decide for yourself which entries match.".to_string(),
                required: true,
            },
            Parameter {
                name: "attributes".to_string(),
                type_hint: "array".to_string(),
                description: "Attribute names the client asked for; empty means all. Reported, not enforced.".to_string(),
                required: true,
            },
        ])
        .with_actions(vec![
            LDAP_SEARCH_RESPONSE_ACTION.clone(),
            CLOSE_CONNECTION_ACTION.clone(),
        ])
        .with_log_template(
            LogTemplate::new()
                .with_info("LDAP SEARCH {client_ip} base={base_dn}")
                .with_debug("LDAP search from {client_ip}:{client_port}, base_dn={base_dn}, scope={scope}, filter={filter}")
                .with_trace("LDAP search: {json_pretty(.)}"),
        )
});

/// LDAP add event - triggered when a client asks to create an entry
///
/// Nothing is stored: the response tells the client whether the add "succeeded". A server
/// instruction that accepts adds is claiming the entry exists from then on, and it is the
/// model's memory that has to make the following search agree.
pub static LDAP_ADD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_add",
        "LDAP add (create entry) request received",
        json!({
            "type": "ldap_add_response",
            "message_id": 3,
            "success": true,
            "message": "Entry added"
        }),
    )
    .with_alternative_example(json!({
        "type": "ldap_add_response",
        "message_id": 3,
        "success": false,
        "result_code": 50,
        "message": "Insufficient access rights"
    }))
    .with_parameters(vec![
        Parameter {
            name: "message_id".to_string(),
            type_hint: "number".to_string(),
            description: "LDAP message ID".to_string(),
            required: true,
        },
        Parameter {
            name: "dn".to_string(),
            type_hint: "string".to_string(),
            description: "Distinguished Name of the entry to create".to_string(),
            required: true,
        },
        Parameter {
            name: "attributes".to_string(),
            type_hint: "object".to_string(),
            description: "Attributes of the new entry, name -> array of values".to_string(),
            required: true,
        },
        Parameter {
            name: "authenticated".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether this connection completed a successful bind".to_string(),
            required: true,
        },
        Parameter {
            name: "bind_dn".to_string(),
            type_hint: "string".to_string(),
            description: "DN of authenticated user (empty if not authenticated)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        LDAP_ADD_RESPONSE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LDAP ADD {client_ip} dn={dn}")
            .with_debug("LDAP add from {client_ip}:{client_port}, dn={dn}")
            .with_trace("LDAP add: {json_pretty(.)}"),
    )
});

/// LDAP modify event - triggered when a client asks to change an entry
pub static LDAP_MODIFY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_modify",
        "LDAP modify (update entry) request received",
        json!({
            "type": "ldap_modify_response",
            "message_id": 4,
            "success": true,
            "message": "Entry modified"
        }),
    )
    .with_alternative_example(json!({
        "type": "ldap_modify_response",
        "message_id": 4,
        "success": false,
        "result_code": 32,
        "message": "No such object"
    }))
    .with_parameters(vec![
        Parameter {
            name: "message_id".to_string(),
            type_hint: "number".to_string(),
            description: "LDAP message ID".to_string(),
            required: true,
        },
        Parameter {
            name: "dn".to_string(),
            type_hint: "string".to_string(),
            description: "Distinguished Name of the entry being modified".to_string(),
            required: true,
        },
        Parameter {
            name: "changes".to_string(),
            type_hint: "array".to_string(),
            description: "Requested changes: [{\"operation\": \"add\"|\"delete\"|\"replace\", \
                          \"attribute\": \"mail\", \"values\": [\"a@example.com\"]}]"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "authenticated".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether this connection completed a successful bind".to_string(),
            required: true,
        },
        Parameter {
            name: "bind_dn".to_string(),
            type_hint: "string".to_string(),
            description: "DN of authenticated user (empty if not authenticated)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        LDAP_MODIFY_RESPONSE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LDAP MODIFY {client_ip} dn={dn}")
            .with_debug("LDAP modify from {client_ip}:{client_port}, dn={dn}")
            .with_trace("LDAP modify: {json_pretty(.)}"),
    )
});

/// LDAP delete event - triggered when a client asks to remove an entry
pub static LDAP_DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_delete",
        "LDAP delete (remove entry) request received",
        json!({
            "type": "ldap_delete_response",
            "message_id": 5,
            "success": true,
            "message": "Entry deleted"
        }),
    )
    .with_alternative_example(json!({
        "type": "ldap_delete_response",
        "message_id": 5,
        "success": false,
        "result_code": 32,
        "message": "No such object"
    }))
    .with_parameters(vec![
        Parameter {
            name: "message_id".to_string(),
            type_hint: "number".to_string(),
            description: "LDAP message ID".to_string(),
            required: true,
        },
        Parameter {
            name: "dn".to_string(),
            type_hint: "string".to_string(),
            description: "Distinguished Name of the entry to delete".to_string(),
            required: true,
        },
        Parameter {
            name: "authenticated".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether this connection completed a successful bind".to_string(),
            required: true,
        },
        Parameter {
            name: "bind_dn".to_string(),
            type_hint: "string".to_string(),
            description: "DN of authenticated user (empty if not authenticated)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        LDAP_DELETE_RESPONSE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LDAP DELETE {client_ip} dn={dn}")
            .with_debug("LDAP delete from {client_ip}:{client_port}, dn={dn}")
            .with_trace("LDAP delete: {json_pretty(.)}"),
    )
});

/// LDAP unbind event - triggered when client closes connection
///
/// Purely informational: RFC 4511 forbids a response to an unbind, so there is no protocol
/// action to offer. `.with_no_actions()` says so explicitly - an empty `.with_actions(vec![])`
/// is indistinguishable from a forgotten action list, and `call_llm` treats that as a bug,
/// firing a `debug_assert!` that panics the connection task in dev builds.
pub static LDAP_UNBIND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ldap_unbind",
        "LDAP unbind (disconnect) request received",
        json!({"type": "show_message", "message": "LDAP client disconnected"}),
    )
    .with_parameters(vec![Parameter {
        name: "bind_dn".to_string(),
        type_hint: "string".to_string(),
        description: "DN of authenticated user (empty if not authenticated)".to_string(),
        required: true,
    }])
    .with_no_actions()
    .with_log_template(
        LogTemplate::new()
            .with_info("LDAP UNBIND {client_ip}")
            .with_debug("LDAP unbind from {client_ip}:{client_port}, bind_dn={bind_dn}")
            .with_trace("LDAP unbind: {json_pretty(.)}"),
    )
});

/// Get LDAP event types
pub fn get_ldap_event_types() -> Vec<EventType> {
    vec![
        LDAP_BIND_EVENT.clone(),
        LDAP_SEARCH_EVENT.clone(),
        LDAP_ADD_EVENT.clone(),
        LDAP_MODIFY_EVENT.clone(),
        LDAP_DELETE_EVENT.clone(),
        LDAP_UNBIND_EVENT.clone(),
    ]
}

// ============================================================================
// BER Encoding Helpers
// ============================================================================

fn encode_ber_length(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![length as u8]
    } else if length < 256 {
        vec![0x81, length as u8]
    } else if length < 65536 {
        vec![0x82, (length >> 8) as u8, length as u8]
    } else {
        vec![
            0x83,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]
    }
}

fn encode_ber_integer(value: i32) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag

    if value >= 0 && value < 128 {
        result.push(0x01); // length
        result.push(value as u8);
    } else {
        result.push(0x04); // length (4 bytes)
        result.extend_from_slice(&value.to_be_bytes());
    }

    result
}

fn encode_ber_string(s: &str) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    let bytes = s.as_bytes();
    result.extend_from_slice(&encode_ber_length(bytes.len()));
    result.extend_from_slice(bytes);
    result
}

fn encode_ldap_message(msg_id: i32, protocol_op: Vec<u8>) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&encode_ber_integer(msg_id));
    content.extend_from_slice(&protocol_op);

    let mut message = vec![0x30]; // SEQUENCE tag
    message.extend_from_slice(&encode_ber_length(content.len()));
    message.extend_from_slice(&content);

    message
}

fn encode_bind_response(msg_id: i32, result_code: u8, diagnostic_message: &str) -> Vec<u8> {
    let mut bind_resp = Vec::new();

    // resultCode (ENUMERATED)
    bind_resp.push(0x0A);
    bind_resp.push(0x01);
    bind_resp.push(result_code);

    // matchedDN (empty)
    bind_resp.push(0x04);
    bind_resp.push(0x00);

    // diagnosticMessage
    bind_resp.extend_from_slice(&encode_ber_string(diagnostic_message));

    // Wrap in BindResponse APPLICATION tag [1]
    let mut bind_msg = vec![0x61];
    bind_msg.extend_from_slice(&encode_ber_length(bind_resp.len()));
    bind_msg.extend_from_slice(&bind_resp);

    encode_ldap_message(msg_id, bind_msg)
}

fn encode_search_entry(
    msg_id: i32,
    dn: &str,
    attributes: serde_json::Map<String, serde_json::Value>,
) -> Vec<u8> {
    // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    //     objectName LDAPDN,
    //     attributes PartialAttributeList }

    let mut entry_content = Vec::new();

    // objectName (DN)
    entry_content.extend_from_slice(&encode_ber_string(dn));

    // attributes (SEQUENCE OF)
    let mut attrs_content = Vec::new();
    for (attr_name, attr_values) in attributes {
        // PartialAttribute ::= SEQUENCE {
        //     type AttributeDescription,
        //     vals SET OF value AttributeValue }

        let mut attr_content = Vec::new();

        // type (attribute name)
        attr_content.extend_from_slice(&encode_ber_string(&attr_name));

        // vals (SET OF)
        let mut vals_content = Vec::new();
        if let Some(arr) = attr_values.as_array() {
            for val in arr {
                if let Some(s) = val.as_str() {
                    vals_content.extend_from_slice(&encode_ber_string(s));
                }
            }
        }

        let mut vals = vec![0x31]; // SET tag
        vals.extend_from_slice(&encode_ber_length(vals_content.len()));
        vals.extend_from_slice(&vals_content);
        attr_content.extend_from_slice(&vals);

        // Wrap in SEQUENCE
        let mut attr = vec![0x30];
        attr.extend_from_slice(&encode_ber_length(attr_content.len()));
        attr.extend_from_slice(&attr_content);
        attrs_content.extend_from_slice(&attr);
    }

    let mut attrs = vec![0x30]; // SEQUENCE tag
    attrs.extend_from_slice(&encode_ber_length(attrs_content.len()));
    attrs.extend_from_slice(&attrs_content);
    entry_content.extend_from_slice(&attrs);

    // Wrap in SearchResultEntry APPLICATION tag [4]
    let mut entry_msg = vec![0x64];
    entry_msg.extend_from_slice(&encode_ber_length(entry_content.len()));
    entry_msg.extend_from_slice(&entry_content);

    encode_ldap_message(msg_id, entry_msg)
}

fn encode_search_done(msg_id: i32, result_code: u8, diagnostic_message: &str) -> Vec<u8> {
    let mut result = Vec::new();

    // resultCode (ENUMERATED)
    result.push(0x0A);
    result.push(0x01);
    result.push(result_code);

    // matchedDN (empty)
    result.push(0x04);
    result.push(0x00);

    // diagnosticMessage
    result.extend_from_slice(&encode_ber_string(diagnostic_message));

    // Wrap in SearchResultDone APPLICATION tag [5]
    let mut search_msg = vec![0x65];
    search_msg.extend_from_slice(&encode_ber_length(result.len()));
    search_msg.extend_from_slice(&result);

    encode_ldap_message(msg_id, search_msg)
}

fn encode_ldap_result(
    msg_id: i32,
    app_tag: u8,
    result_code: u8,
    diagnostic_message: &str,
) -> Vec<u8> {
    let mut result = Vec::new();

    // resultCode (ENUMERATED)
    result.push(0x0A);
    result.push(0x01);
    result.push(result_code);

    // matchedDN (empty)
    result.push(0x04);
    result.push(0x00);

    // diagnosticMessage
    result.extend_from_slice(&encode_ber_string(diagnostic_message));

    // Wrap in APPLICATION tag
    let mut msg = vec![app_tag];
    msg.extend_from_slice(&encode_ber_length(result.len()));
    msg.extend_from_slice(&result);

    encode_ldap_message(msg_id, msg)
}
