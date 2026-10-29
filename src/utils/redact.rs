//! Redact credentials from JSON before it is displayed or logged.
//!
//! Startup parameters and actions are echoed in two places an operator reads: the
//! `open_client` / `open_server` summary pushed to the dashboard and MCP status stream, and the
//! executor's per-action DEBUG line in `netget.log`. Both printed the RADIUS client's shared
//! `secret`, the MQTT client's `password` and anything else of that kind verbatim. The protocol
//! still receives the real value; only what is shown is replaced.
//!
//! Matching is by key name, case-insensitively, on a substring, so `secret`, `shared_secret`,
//! `password`, `bind_password` and `api_key` are all caught. A false positive costs a line of
//! display; a false negative prints a credential.

use serde_json::Value;

/// Substrings of a key name that mark its value as a credential.
pub const SENSITIVE_KEY_PARTS: &[&str] = &[
    "secret",
    // NVMe/TCP's configured TLS PSK, named after nvme-cli's --tls_key.
    "tls_key",
    "password",
    "passphrase",
    "passwd",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "credential",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "idtoken",
    "auth_token",
    "authtoken",
    "authorization",
    "cookie",
    // A credential that is not called one: the HTTP proxy client's `proxy_auth`
    // (`user:password`).
    "proxy_auth",
    // LoRaWAN root and session keys (the `devices` of the network server and the gateway):
    // the AppKey admits a device, the session keys read and forge its traffic.
    "app_key",
    "appkey",
    "nwk_key",
    "nwkkey",
    "nwk_s_key",
    "nwkskey",
    "app_s_key",
    "appskey",
    // Zigbee: the network key every device of the network encrypts with, and trust-center or
    // application link keys (the zigbee co-processor's `network_key`).
    "network_key",
    "networkkey",
    "link_key",
    "linkkey",
    // NGAP: a 5G subscriber's permanent key K and its operator key (OPc, or OP), from which every
    // 5G-AKA vector and NAS key derives (the AMF's `subscribers` and the gNB's UE). The SUCI
    // home network key matches `private_key` above.
    "subscriber_key",
    "subscriber_op",
];

/// Substrings of a key name whose value is masked wherever it is displayed, without making
/// the request that carries it private.
///
/// STOMP's `passcode` and the SNMP `community` string are credentials, but every SNMP event
/// and every STOMP CONNECT carries one, so treating them as [`SENSITIVE_KEY_PARTS`] would turn
/// off tracing and the access-log detail for the whole of both protocols. They are hidden
/// from the `open_client` summary, the executor's DEBUG line and startup-parameter errors
/// ([`redact_sensitive`], [`is_shown_redacted`]) and nothing else.
pub const DISPLAY_ONLY_KEY_PARTS: &[&str] = &["passcode", "community"];

/// What a redacted value is shown as.
pub const REDACTED: &str = "<redacted>";

/// Whether a key names a credential.
///
/// Bare `key` is not matched: `routing_key`, `access_key_id` and `key_type` are not secrets,
/// and the ones that are (`api_key`, `private_key`, `secret_access_key`) match on their own
/// part. Bare `auth` is a value-shaped case, see [`is_sensitive_entry`].
pub fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    key == "token"
        || key.ends_with("_token")
        || SENSITIVE_KEY_PARTS.iter().any(|part| key.contains(part))
}

/// Whether a key/value pair holds a credential.
///
/// [`is_sensitive_key`] on the name, plus one case the name alone cannot decide: a key that
/// is exactly `auth` holding a **string** is a credential (the WebDAV client's `auth` is
/// `username:password`), while an `auth` **object** is a block to walk — Vault's answer
/// carries `auth.client_token` beside `auth.token_type`, and only the first is hidden.
/// `auth_type`, `auth_url`, `authenticated` and `auth_method` describe a mechanism and are
/// shown, which a substring match would have hidden for nothing.
pub fn is_sensitive_entry(key: &str, value: &Value) -> bool {
    if value.is_null() {
        return false;
    }
    if is_sensitive_key(key) {
        return true;
    }
    let key = key.to_ascii_lowercase();
    key == "auth" && value.is_string()
}

/// Whether a key/value pair is shown as [`REDACTED`]: every [`is_sensitive_entry`], plus the
/// [`DISPLAY_ONLY_KEY_PARTS`].
pub fn is_shown_redacted(key: &str, value: &Value) -> bool {
    if value.is_null() {
        return false;
    }
    if is_sensitive_entry(key, value) {
        return true;
    }
    let key = key.to_ascii_lowercase();
    DISPLAY_ONLY_KEY_PARTS.iter().any(|part| key.contains(part))
}

/// Whether this request offers an action that can carry credentials. Such model
/// replies can be malformed or plain text, so hiding whole payloads is safer
/// than trying to recover credential fields from an unparseable response.
pub fn actions_have_credentials(actions: &[crate::llm::actions::ActionDefinition]) -> bool {
    actions
        .iter()
        .any(|action| action.parameters.iter().any(|p| is_sensitive_key(&p.name)))
}

/// Detect credential-bearing structured input without cloning or recursive traversal.
/// A budget-exceeding input is private because its remaining keys cannot be proven safe.
/// Null credential fields do not contain a value. Bounds apply to node count, depth and
/// retained string/key content; no request-wide or global privacy state is retained.
pub fn contains_credentials(value: &Value) -> bool {
    const MAX_NODES: usize = 4096;
    const MAX_DEPTH: usize = 64;
    const MAX_BYTES: usize = 256 * 1024;
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        bytes = bytes.saturating_add(std::mem::size_of::<Value>());
        if nodes > MAX_NODES || depth > MAX_DEPTH || bytes > MAX_BYTES {
            return true;
        }
        match value {
            Value::String(s) => bytes = bytes.saturating_add(s.len()),
            Value::Array(values) => {
                if values.len() > MAX_NODES.saturating_sub(nodes + pending.len()) {
                    return true;
                }
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_NODES.saturating_sub(nodes + pending.len()) {
                    return true;
                }
                for (key, value) in values {
                    bytes = bytes.saturating_add(key.len());
                    if bytes > MAX_BYTES {
                        return true;
                    }
                    if is_sensitive_entry(key, value) {
                        return true;
                    }
                    pending.push((value, depth + 1));
                }
            }
            _ => {}
        }
        if bytes > MAX_BYTES {
            return true;
        }
    }
    false
}

/// Remove untyped context from a private request's error while preserving the
/// numeric overload category that protocols use to choose a retryable wire reply.
pub fn hide_error_details(error: anyhow::Error) -> anyhow::Error {
    if let Some(category) = error.downcast_ref::<crate::llm::rate_limiter::RateLimitError>() {
        anyhow::Error::new(*category)
    } else {
        anyhow::anyhow!("credential-bearing request failed; diagnostics hidden")
    }
}

/// Deepest nesting walked. `serde_json` refuses to parse past 128 levels, so a parsed value
/// never reaches this; a value built in code might, and past it the subtree is shown as
/// [`REDACTED`] whole rather than walked on a shrinking stack.
pub const MAX_REDACT_DEPTH: usize = 64;

/// A copy of `value` with every credential-named key's value replaced by [`REDACTED`], at any
/// depth up to [`MAX_REDACT_DEPTH`].
pub fn redact_sensitive(value: &Value) -> Value {
    redact_at(value, 0)
}

fn redact_at(value: &Value, depth: usize) -> Value {
    if depth > MAX_REDACT_DEPTH {
        return Value::String(REDACTED.to_string());
    }
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let shown = if is_shown_redacted(k, v) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_at(v, depth + 1)
                    };
                    (k.clone(), shown)
                })
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| redact_at(v, depth + 1)).collect())
        }
        other => other.clone(),
    }
}
