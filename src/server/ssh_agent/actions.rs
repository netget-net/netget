//! SSH Agent server protocol actions

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

// ============================================================================
// Action constants
//
// These are defined here rather than inline in `get_sync_actions` so that each event type can
// attach the actions that actually answer it. An event that lists none leaves the model with
// only the common actions (`set_memory`, `show_message`, ...), so every agent action it returns
// is rejected as unknown and the request fails after two retries - which is what happened to
// all eight of these events. See `tests/event_action_declarations_test.rs`.
// ============================================================================

pub static SEND_IDENTITIES_LIST_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_identities_list".to_string(),
        description: "Answer ssh_agent_request_identities with the keys this agent \
            holds. This is the ONLY valid answer to that event - send_success does not \
            satisfy it. An empty 'identities' array is valid and means the agent holds \
            no keys, which is what `ssh-add -l` reports as \"no identities\"."
            .to_string(),
        parameters: vec![Parameter {
            name: "identities".to_string(),
            type_hint: "array".to_string(),
            description: "Array of objects, one per key. Give each key as 'public_key': an \
                OpenSSH public key exactly as it appears in authorized_keys or a .pub file, \
                \"<algorithm> <base64 blob> [comment]\". 'comment' is the label \
                `ssh-add -l` prints and overrides any comment in the line. \
                'public_key_blob_hex' is the escape hatch for a blob with no OpenSSH text \
                form - give that or 'public_key', never both. A key whose blob will not \
                decode, or whose length prefixes do not span it exactly, fails the whole \
                request rather than sending a broken identity"
                .to_string(),
            required: true,
        }],
        // An OpenSSH text key, not a hex blob. The hex spelling here used to declare a
        // 32-byte ed25519 key and then supply three bytes of it - a truncation nobody could
        // see, because nobody proofreads hex, and one `ssh-add -l` would have rejected. The
        // text form is the one a model has actually seen, and its framing is now checked.
        example: json!({"type": "send_identities_list", "identities": [{"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH98ewNgR4yzG9S6UrA3P6sN2mFMedO/XrRqPcibUAfr", "comment": "deploy-key"}]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SSH Agent {identities_len} identities")
                .with_debug("SSH Agent send_identities_list: count={identities_len}"),
        ),
    }
});

pub static SEND_SIGN_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "send_sign_response".to_string(),
        description: "Answer ssh_agent_sign_request with a signature over the data the \
            client sent. NOTE: no private key exists here - you are fabricating the \
            signature bytes, so a real client will fail to verify them against the \
            public key it holds. Useful for honeypots and for exercising the protocol; \
            reply with send_failure to refuse the signature instead."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "algorithm".to_string(),
                type_hint: "string".to_string(),
                description: "Signature algorithm name - \"ssh-ed25519\", \"ssh-rsa\", \
                    \"rsa-sha2-256\" or \"rsa-sha2-512\" - matching the key in the event's \
                    'key_type' and its 'flags'. The server builds the framing (algorithm \
                    name and signature, each length-prefixed) and, unless you give \
                    'signature_bytes_hex', fabricates a signature of the size that \
                    algorithm requires. This is the field to use"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "signature_bytes_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Optional: the raw signature bytes to put inside the framing \
                    'algorithm' builds - 64 for ssh-ed25519. NOT the framed blob; that is \
                    'signature_hex'"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "signature_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Escape hatch: the whole framed signature blob as hex - the \
                    algorithm name and the signature, each length-prefixed, as in the \
                    event's 'public_key_blob_hex' encoding. Give this or 'algorithm', never \
                    both. Invalid hex, or hex decoding to zero bytes, fails the request \
                    instead of sending an empty signature"
                    .to_string(),
                required: false,
            },
        ],
        // Name the algorithm; the server frames it. The hex spelling here used to declare a
        // 64-byte ed25519 signature and supply four bytes of it, which is the drift a hex
        // literal in an example invites - and the framing is the only part of a fabricated
        // signature that has a right answer at all.
        example: json!({"type": "send_sign_response", "algorithm": "ssh-ed25519"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SSH Agent signature")
                .with_debug("SSH Agent send_sign_response"),
        ),
    }
});

pub static SEND_SUCCESS_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_success".to_string(),
    description: "Send SSH_AGENT_SUCCESS: the operation was accepted. This is the \
        expected answer to ssh_agent_add_identity, ssh_agent_remove_identity, \
        ssh_agent_remove_all_identities, ssh_agent_lock and ssh_agent_unlock. It is \
        NOT a valid answer to a request for identities or a signature."
        .to_string(),
    parameters: vec![],
    example: json!({"type": "send_success"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> SSH Agent SUCCESS")
            .with_debug("SSH Agent send_success"),
    ),
});

pub static SEND_FAILURE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "send_failure".to_string(),
    description: "Send SSH_AGENT_FAILURE: refuse the operation. Use it to deny a \
        signature, reject a key, or refuse an unlock whose passphrase does not \
        match. Every event accepts this. If you return no action at all the server \
        sends nothing and the client blocks, so refuse explicitly."
        .to_string(),
    parameters: vec![],
    example: json!({"type": "send_failure"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> SSH Agent FAILURE")
            .with_debug("SSH Agent send_failure"),
    ),
});

pub static CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the agent connection that raised this event, without \
        replying to the request. The client sees the socket drop. Use send_failure \
        instead when you want to refuse an operation but keep the session."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SSH Agent close connection")
                .with_debug("SSH Agent close_connection"),
        ),
    });

pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| ActionDefinition {
    name: "wait_for_more".to_string(),
    description: "Send no reply and wait for the next message. Rarely correct: the \
        agent protocol is strict request/response and a client blocks until it gets \
        an answer, so prefer send_success or send_failure."
        .to_string(),
    parameters: vec![],
    example: json!({"type": "wait_for_more"}),
    log_template: Some(
        LogTemplate::new()
            .with_info("-> SSH Agent wait")
            .with_debug("SSH Agent wait_for_more"),
    ),
});

// Event type constants
pub static SSH_AGENT_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_connection_opened",
        "A client connected to the agent socket and has not sent a request yet. Nothing is \
         expected of you here - it exists so you can set up state before the first request. \
         Returning no action is normal; do NOT send send_success, which would put an \
         unrequested reply on the wire and desynchronise the client. Close the connection if \
         you want to refuse the client outright.",
        json!({
            "type": "close_connection"
        }),
    )
    .with_parameter(Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Unique connection identifier".to_string(),
        required: true,
    })
    // Only close_connection: replying to a request the client has not made desynchronises it,
    // which the description above spells out. Refusing the connection outright is legitimate.
    .with_actions(vec![CLOSE_CONNECTION_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent connection opened")
            .with_debug("SSH Agent conn={connection_id}")
            .with_trace("SSH Agent connection: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_REQUEST_IDENTITIES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_request_identities",
        "The client asked which keys this agent holds (`ssh-add -l`, or ssh choosing a key for a \
         login). Answer with send_identities_list - an empty list is valid.",
        json!({
            "type": "send_identities_list",
            "identities": []
        }),
    )
    .with_actions(vec![
        SEND_IDENTITIES_LIST_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent REQUEST_IDENTITIES")
            .with_debug("SSH Agent REQUEST_IDENTITIES")
            .with_trace("SSH Agent identities request: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_SIGN_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_sign_request",
        "The client asked the agent to sign a challenge with one of its keys, which is how an \
         SSH login using agent authentication proves key possession. Answer with \
         send_sign_response to sign, or send_failure to refuse. No private key exists here, so \
         any signature you return is fabricated and will not verify.",
        json!({
            "type": "send_sign_response",
            "algorithm": "ssh-ed25519"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "key_type".to_string(),
            type_hint: "string".to_string(),
            description: "Algorithm name decoded from the key blob, e.g. \"ssh-ed25519\" or \
                \"ssh-rsa\". Use this to identify which key is being asked for rather than \
                comparing hex blobs. Empty if the blob could not be decoded"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "public_key_blob_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The public key the client wants to sign with, as the hex-encoded SSH \
                wire blob. Compare it against the blobs you returned from send_identities_list \
                to tell which of your keys is meant"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The challenge to be signed, hex-encoded. It is an SSH session \
                identifier and login request, not human-readable text"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "flags".to_string(),
            type_hint: "integer".to_string(),
            description: "Signature flags from the client: 0 for the key's default algorithm, \
                2 requests rsa-sha2-256 and 4 rsa-sha2-512 for RSA keys"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_SIGN_RESPONSE_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent SIGN_REQUEST flags={flags}")
            .with_debug("SSH Agent SIGN_REQUEST flags={flags}")
            .with_trace("SSH Agent sign request: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_ADD_IDENTITY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_add_identity",
        "The client is loading a private key into the agent (`ssh-add`). The private key material \
         is parsed off the wire and discarded - it is never given to you and never stored. \
         Answer send_success to accept the key or send_failure to refuse it; remember accepted \
         keys in memory if you want them to appear in later identity listings.",
        json!({
            "type": "send_success"
        })
    )
    .with_parameters(vec![
        Parameter {
            name: "key_type".to_string(),
            type_hint: "string".to_string(),
            description: "Algorithm name the client sent, e.g. \"ssh-ed25519\" or \"ssh-rsa\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "public_key_blob_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded public part of the key. NOTE: this is parsed assuming the \
                Ed25519 layout, so for RSA and other multi-field key types this value and \
                'comment' may be wrong or the message may fail to parse entirely"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "comment".to_string(),
            type_hint: "string".to_string(),
            description: "The label the client attached to the key, usually the path or an \
                email address. Subject to the same Ed25519-layout caveat as \
                'public_key_blob_hex'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "constrained".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if the client sent the key with constraints such as a lifetime \
                (`ssh-add -t`) or confirmation requirement (`ssh-add -c`). The constraints \
                themselves are not parsed and nothing enforces them - honour them yourself if \
                you care"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_SUCCESS_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent ADD_IDENTITY {key_type} ({comment})")
            .with_debug("SSH Agent ADD_IDENTITY key_type={key_type} comment={comment} constrained={constrained}")
            .with_trace("SSH Agent add identity: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_REMOVE_IDENTITY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_remove_identity",
        "The client asked the agent to forget one key (`ssh-add -d`). Answer send_success if you \
         drop it from memory, or send_failure if you do not hold it.",
        json!({
            "type": "send_success"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "public_key_blob_hex".to_string(),
        type_hint: "string".to_string(),
        description: "Hex-encoded SSH wire blob of the key to forget. Match it against the \
                blobs you return from send_identities_list"
            .to_string(),
        required: true,
    }])
    .with_actions(vec![
        SEND_SUCCESS_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent REMOVE_IDENTITY")
            .with_debug("SSH Agent REMOVE_IDENTITY")
            .with_trace("SSH Agent remove identity: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_REMOVE_ALL_IDENTITIES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_remove_all_identities",
        "The client asked the agent to forget every key (`ssh-add -D`). Answer send_success after \
         clearing them from memory.",
        json!({
            "type": "send_success"
        }),
    )
    .with_actions(vec![
        SEND_SUCCESS_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent REMOVE_ALL_IDENTITIES")
            .with_debug("SSH Agent REMOVE_ALL_IDENTITIES")
            .with_trace("SSH Agent remove all: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_LOCK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_lock",
        "The client asked to lock the agent with a passphrase (`ssh-add -x`). While locked, a \
         real agent hides its identities and refuses to sign until unlocked. Nothing here \
         enforces that: record the passphrase and the locked state in memory and honour it \
         yourself on later events. Answer send_success to accept.",
        json!({
            "type": "send_success"
        }),
    )
    .with_parameter(Parameter {
        name: "passphrase".to_string(),
        type_hint: "string".to_string(),
        description: "The passphrase the client sent, in the clear".to_string(),
        required: true,
    })
    .with_actions(vec![
        SEND_SUCCESS_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent LOCK")
            .with_debug("SSH Agent LOCK")
            .with_trace("SSH Agent lock: {json_pretty(.)}"),
    )
});

pub static SSH_AGENT_UNLOCK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_unlock",
        "The client asked to unlock the agent (`ssh-add -X`). Compare 'passphrase' with the one \
         from the lock request you remembered: answer send_success if it matches and \
         send_failure if it does not.",
        json!({
            "type": "send_success"
        }),
    )
    .with_parameter(Parameter {
        name: "passphrase".to_string(),
        type_hint: "string".to_string(),
        description: "The passphrase the client sent, in the clear".to_string(),
        required: true,
    })
    .with_actions(vec![
        SEND_SUCCESS_ACTION.clone(),
        SEND_FAILURE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SSH Agent UNLOCK")
            .with_debug("SSH Agent UNLOCK")
            .with_trace("SSH Agent unlock: {json_pretty(.)}"),
    )
});

// ============================================================================
// Turning what the model can write into what the wire needs
//
// Both of these exist for the same reason. An SSH key blob and an SSH signature blob are
// sequences of length-prefixed strings, and the two examples this protocol advertised were
// hex transcriptions of them that were *wrong*: one declared a 32-byte ed25519 key and
// supplied three bytes, the other declared a 64-byte signature and supplied four. Nothing
// caught it, because nothing proofreads hex - which is the whole argument of
// `tests/example_hex_drift_test.rs`. Naming the algorithm and letting the server frame the
// blob removes the only part of this a model could get wrong.
// ============================================================================

/// Do the SSH `string` length prefixes in `blob` span it exactly?
///
/// Every standard public key blob is a run of length-prefixed fields - `string(algorithm)`
/// then the key's own fields, `mpint` for RSA, `string` for ed25519 and ECDSA - so a walk
/// that consumes the blob exactly is the cheapest check that it is not truncated, which is
/// how the old example was broken.
fn ssh_fields_span_exactly(blob: &[u8]) -> bool {
    let mut at = 0usize;
    while at < blob.len() {
        let Some(header) = blob.get(at..at + 4) else {
            return false;
        };
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        at += 4;
        let Some(end) = at.checked_add(len) else {
            return false;
        };
        if end > blob.len() {
            return false;
        }
        at = end;
    }
    at == blob.len() && !blob.is_empty()
}

/// Encode an SSH `string`: a 32-bit big-endian length followed by the bytes.
fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Normalise one entry of `send_identities_list` into the `public_key_blob_hex` the server
/// writes, from whichever spelling the model used.
fn normalise_identity(identity: &serde_json::Value) -> Result<serde_json::Value> {
    use base64::Engine as _;

    let text = identity
        .get("public_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty());
    let blob_hex = identity
        .get("public_key_blob_hex")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let stated_comment = identity.get("comment").and_then(|v| v.as_str());

    match (text, blob_hex) {
        (Some(line), None) => {
            let mut fields = line.split_whitespace();
            let algorithm = fields
                .next()
                .context("'public_key' is empty; it is an authorized_keys line")?;
            let encoded = fields.next().with_context(|| {
                format!(
                    "'public_key' must be \"<algorithm> <base64 blob> [comment]\", e.g. \
                     \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...\"; got {line:?}"
                )
            })?;
            let line_comment = fields.next();

            let blob = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .with_context(|| {
                    format!("the base64 blob in 'public_key' does not decode ({encoded:?})")
                })?;
            if !ssh_fields_span_exactly(&blob) {
                anyhow::bail!(
                    "the key blob in 'public_key' is truncated: its length prefixes do not \
                     span its {} bytes. Copy a whole line from a .pub file rather than \
                     shortening it",
                    blob.len()
                );
            }
            // The blob names its own algorithm; disagreeing with the word in front of it
            // means one of the two is wrong and there is no way to tell which.
            let named: &[u8] = {
                let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
                &blob[4..4 + len]
            };
            if named != algorithm.as_bytes() {
                anyhow::bail!(
                    "'public_key' says {algorithm:?} but its blob names {:?}",
                    String::from_utf8_lossy(named)
                );
            }

            Ok(json!({
                "public_key_blob_hex": hex::encode(&blob),
                "comment": stated_comment.or(line_comment).unwrap_or(""),
            }))
        }
        (None, Some(blob_hex)) => Ok(json!({
            "public_key_blob_hex": blob_hex,
            "comment": stated_comment.unwrap_or(""),
        })),
        (Some(_), Some(_)) => anyhow::bail!(
            "an identity has both 'public_key' and 'public_key_blob_hex'; they are two \
             spellings of the same key and nothing can tell which one you meant"
        ),
        (None, None) => anyhow::bail!(
            "an identity has neither 'public_key' (an authorized_keys line, e.g. \
             \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... deploy-key\") nor \
             'public_key_blob_hex'"
        ),
    }
}

/// How many bytes of signature a named algorithm carries inside its frame.
///
/// RSA's is the modulus size, so 2048-bit is the assumption; a caller wanting anything else
/// supplies `signature_bytes_hex`.
fn fabricated_signature_len(algorithm: &str) -> Option<usize> {
    match algorithm {
        "ssh-ed25519" => Some(64),
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => Some(256),
        _ => None,
    }
}

/// Build the framed signature blob `send_sign_response` puts on the wire.
fn sign_response_blob(action: &serde_json::Value) -> Result<Vec<u8>> {
    let algorithm = action
        .get("algorithm")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let framed_hex = action
        .get("signature_hex")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match (algorithm, framed_hex) {
        (Some(algorithm), None) => {
            let signature = match action.get("signature_bytes_hex").and_then(|v| v.as_str()) {
                Some(raw) if !raw.is_empty() => hex::decode(raw)
                    .context("Invalid hex in 'signature_bytes_hex'")
                    .and_then(|bytes| {
                        if bytes.is_empty() {
                            anyhow::bail!("'signature_bytes_hex' decoded to zero bytes");
                        }
                        Ok(bytes)
                    })?,
                _ => {
                    let len = fabricated_signature_len(algorithm).with_context(|| {
                        format!(
                            "no signature size is known for {algorithm:?}, so there is \
                             nothing to fabricate - give 'signature_bytes_hex' as well, or \
                             the whole framed blob as 'signature_hex'"
                        )
                    })?;
                    // Recognisable in a capture as what it is. Nothing here holds a private
                    // key, so these bytes cannot verify and should not pretend to.
                    const MARKER: &[u8] = b"netget-fabricated-signature-";
                    MARKER.iter().copied().cycle().take(len).collect()
                }
            };

            let mut blob = Vec::with_capacity(8 + algorithm.len() + signature.len());
            ssh_string(&mut blob, algorithm.as_bytes());
            ssh_string(&mut blob, &signature);
            Ok(blob)
        }
        (None, Some(framed_hex)) => {
            let blob = hex::decode(framed_hex).context("Invalid hex in 'signature_hex'")?;
            if blob.is_empty() {
                anyhow::bail!("'signature_hex' decoded to zero bytes");
            }
            Ok(blob)
        }
        (Some(_), Some(_)) => anyhow::bail!(
            "give 'algorithm' or 'signature_hex', not both - the first builds the framing and \
             the second already contains it"
        ),
        (None, None) => anyhow::bail!(
            "Missing 'algorithm'. Name the signature algorithm (e.g. \"ssh-ed25519\") and the \
             server frames the blob for you, or pass a whole framed blob as 'signature_hex'"
        ),
    }
}

/// SSH Agent server protocol implementation
pub struct SshAgentProtocol;

impl SshAgentProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SshAgentProtocol {
    /// A Unix socket has no host and no port.
    ///
    /// Without this, `server_startup.rs` treats the protocol as "unmigrated" and *requires* a
    /// `port`, so starting it from the dashboard or over MCP with only a `socket_path` failed
    /// with "requires 'port' parameter" — the same defect `socket_file` had. Declaring empty
    /// binding defaults opts into the path where port is optional; the listen address that
    /// path computes is ignored, since the server binds `socket_path`.
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: None,
            host: None,
            port: None,
        })
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "socket_path".to_string(),
                type_hint: "string".to_string(),
                description: "Path to Unix domain socket (default: ./netget-ssh-agent.sock)"
                    .to_string(),
                required: false,
                example: json!("./netget-ssh-agent.sock"),
                default: None,
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no request at all before the \
                              server closes it. Default 300: ssh-add and ssh ask at once, but \
                              NetGet's own ssh_agent client connects and waits for a person."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established connection may be silent between requests \
                              before the server closes it. Default 900. A request still being \
                              answered never counts as silence."
                    .to_string(),
                required: false,
                example: json!(900),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // None.
        //
        // `modify_instruction` produced an ActionResult::Custom that execute_action_result
        // ignored, so it never changed anything; the common `update_instruction` action does
        // the job properly. `close_connection` declared a `connection_id` parameter that the
        // executor discarded - it always closed the connection that raised the event, never
        // the one named - so it has moved to the sync actions below, without that parameter.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            SEND_IDENTITIES_LIST_ACTION.clone(),
            SEND_SIGN_RESPONSE_ACTION.clone(),
            SEND_SUCCESS_ACTION.clone(),
            SEND_FAILURE_ACTION.clone(),
            CLOSE_CONNECTION_ACTION.clone(),
            WAIT_FOR_MORE_ACTION.clone(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "SSH Agent"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*SSH_AGENT_CONNECTION_OPENED_EVENT).clone(),
            (*SSH_AGENT_REQUEST_IDENTITIES_EVENT).clone(),
            (*SSH_AGENT_SIGN_REQUEST_EVENT).clone(),
            (*SSH_AGENT_ADD_IDENTITY_EVENT).clone(),
            (*SSH_AGENT_REMOVE_IDENTITY_EVENT).clone(),
            (*SSH_AGENT_REMOVE_ALL_IDENTITIES_EVENT).clone(),
            (*SSH_AGENT_LOCK_EVENT).clone(),
            (*SSH_AGENT_UNLOCK_EVENT).clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "UNIX Socket > SSH Agent"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ssh-agent", "agent", "key-agent", "ssh keys"]
    }

    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Unix domain socket, so no privileged port is involved.
            .implementation("Custom SSH Agent wire parser over a Unix domain socket")
            .llm_control("Identity listings, signing decisions, key lifecycle, lock/unlock")
            .e2e_testing(
                "tests/server/ssh_agent drives the real binary over its Unix socket with a \
                 hand-written agent client and a mocked model, covering REQUEST_IDENTITIES, \
                 SIGN_REQUEST, ADD_IDENTITY and a pipelined multi-operation session. That \
                 client is written from the wire format inside the test, so it is an \
                 independent reading of the protocol, not an independent implementation - \
                 the same class of evidence as dhcp's in-test RFC 2131 decoder. No \
                 third-party agent client drives it, and none usefully could: see notes.",
            )
            .notes(
                "FAILS CLOSED: an LLM error, an answer with no usable action, and an action \
                 whose fields will not decode all send SSH_AGENT_FAILURE, logged as \
                 decision=fail_closed_*. Saying nothing is not an option - the client blocks \
                 on the read - and it is never SSH_AGENT_SUCCESS. Virtual agent: no private \
                 keys exist, so signatures are fabricated and will not verify, which is why \
                 a real `ssh` cannot complete a login through this agent and why its rating \
                 cannot rest on one. ADD_IDENTITY parsing assumes the Ed25519 key layout. \
                 Lock/unlock and key constraints are reported but never enforced.",
            )
            .max_inbound_bytes(crate::server::ssh_agent::MAX_AGENT_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "SSH Agent protocol server for managing SSH keys and signing operations"
    }

    fn example_prompt(&self) -> &'static str {
        "Start SSH Agent on ./netget-ssh-agent.sock; provide 2 Ed25519 keys (admin-key, deploy-key); sign any requests automatically"
    }

    fn group_name(&self) -> &'static str {
        "Security"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: report an empty key list for every identities request,
        // no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ssh_agent_request_identities":
    actions = [{"type": "send_identities_list", "identities": []}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all SSH Agent responses intelligently
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "ssh-agent",
                "instruction": "SSH Agent managing keys and signing operations"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "ssh-agent",
                "event_handlers": [{
                    "event_pattern": "ssh_agent_request_identities",
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
                "port": 0,
                "base_stack": "ssh-agent",
                "event_handlers": [{
                    "event_pattern": "ssh_agent_request_identities",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_identities_list",
                            "identities": []
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SshAgentProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            // For Unix sockets, we need a path not a SocketAddr
            // Extract socket_path from startup_params or use default
            let socket_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("socket_path"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| "./netget-ssh-agent.sock".to_string());

            let socket_path_buf = std::path::PathBuf::from(socket_path);

            // Both read bounds are the operator's to tune; the defaults are argued beside
            // FIRST_BYTE_READ_TIMEOUT and IDLE_BETWEEN_REQUESTS_TIMEOUT in mod.rs.
            let secs = |name: &str| -> Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            use crate::server::ssh_agent::SshAgentServer;
            let _actual_path = SshAgentServer::spawn_with_llm_actions(
                socket_path_buf,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await?;

            // Return a dummy SocketAddr since Unix sockets don't have IP addresses
            Ok("127.0.0.1:0".parse().unwrap())
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action["type"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'type' field in action"))?;

        match action_type {
            "send_identities_list" => {
                let identities = action["identities"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'identities' field"))?;

                // Normalise here rather than in the server loop, so the one form that
                // reaches the wire is the hex blob and `executable_examples_test` exercises
                // the conversion the advertised example depends on.
                let normalised = identities
                    .iter()
                    .map(normalise_identity)
                    .collect::<Result<Vec<_>>>()?;

                Ok(ActionResult::Custom {
                    name: "send_identities_list".to_string(),
                    data: json!({ "identities": normalised }),
                })
            }
            "send_sign_response" => Ok(ActionResult::Custom {
                name: "send_sign_response".to_string(),
                data: json!({ "signature_hex": hex::encode(sign_response_blob(&action)?) }),
            }),
            "send_success" => Ok(ActionResult::Custom {
                name: "send_success".to_string(),
                data: json!({}),
            }),
            "send_failure" => Ok(ActionResult::Custom {
                name: "send_failure".to_string(),
                data: json!({}),
            }),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // No `modify_instruction` arm. It is advertised by nothing (see
            // get_async_actions), and the Custom result it used to build had no branch in
            // execute_action_result, so it was accepted and did nothing - the shape a
            // round-trip check passes and a user never gets any use from. Rejecting the name
            // now routes it through the fail-closed rule as decision=fail_closed_action_error.
            "close_connection" => {
                // CloseConnection is a unit variant
                Ok(ActionResult::CloseConnection)
            }
            _ => anyhow::bail!("Unknown action type: {}", action_type),
        }
    }
}
