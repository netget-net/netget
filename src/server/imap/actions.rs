//! IMAP protocol actions implementation
//!
//! This module implements the action system for IMAP (Internet Message Access Protocol).
//! The LLM controls all IMAP responses through these actions, including:
//! - Greeting and capability advertisement
//! - Authentication (LOGIN)
//! - Mailbox operations (SELECT, LIST, CREATE, DELETE, RENAME, STATUS, EXAMINE)
//! - Message operations (FETCH, STORE, SEARCH, COPY, EXPUNGE)
//! - UID-based operations (UID FETCH, UID STORE, UID SEARCH, UID COPY)
//! - APPEND for adding messages

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

/// Octets that may legally follow a literal inside an IMAP **server** response.
///
/// RFC 3501's response grammar puts a literal either as the last element of a line (so a CR
/// follows, opening the CRLF), or as one element of a space-separated, parenthesised list (so a
/// space or a closing paren follows). `msg-att-static`'s `"BODY" section SP nstring` is the case
/// that matters here — a `BODY[]` literal is followed by ` ` when another attribute comes after
/// it and by `)` when it is last — and this server's own `send_imap_fetch`, which computes its
/// counts from `body.len()`, produces exactly those two.
const LITERAL_FOLLOWERS: &[u8] = b") \r";

/// Refuse a response whose `{N}` literal count disagrees with the octets that follow it.
///
/// # Why this is a guard and not a lint
///
/// `send_imap_response`'s `response` field relays a **pre-framed, model-authored** response
/// straight to the socket. RFC 3501 §4.3 makes a client read *exactly* the declared number of
/// octets, so a count that is wrong by even one desynchronises the connection **permanently**:
/// the client swallows part of the next line as message body, then reads the remainder as a
/// response it cannot parse, and every subsequent tag is off by that much. There is no
/// recovery and no error the server can send afterwards that the client will understand.
///
/// It is also invisible to the kind of assertion a test naturally writes. A fixture in this
/// tree declared `{50}` for a 46-octet body and passed for as long as it existed, because every
/// assertion was `line.contains("FETCH")` on a **trimmed** string — trimming discards precisely
/// the framing the RFC cares about. The pcap oracle found it by handing the bytes to
/// Wireshark's dissector. This function is the same check on our side of the socket, so a
/// model that miscounts is refused rather than relayed.
///
/// # What it checks
///
/// Walking the bytes once, and skipping *over* each literal's payload so a `{5}` that happens
/// to appear inside a message body is not mistaken for a second marker:
///
/// * `{N}` immediately followed by CRLF is a literal marker. `{N}` anywhere else is ordinary
///   text — `A001 OK fetched {46} bytes` is a perfectly good response — and is left alone.
/// * At least `N` octets must follow. Fewer is a truncated response.
/// * The octet at `N` must be one of [`LITERAL_FOLLOWERS`]. This is what catches an *over*-count
///   that is still long enough: `{50}` over a 46-octet body lands mid-`A004`, which is neither a
///   space, a paren, nor the CR of a CRLF.
///
/// A count that is short by a whole element could still land on a legal follower and pass; this
/// is a guard against the counting mistake models actually make, not a parser.
pub fn validate_imap_literals(response: &[u8]) -> Result<()> {
    let mut i = 0usize;
    while i < response.len() {
        if response[i] != b'{' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < response.len() && response[j].is_ascii_digit() {
            j += 1;
        }
        // `{}` with no digits, or `{` with no closing brace, is not a literal marker.
        if j == i + 1 || j >= response.len() || response[j] != b'}' {
            i += 1;
            continue;
        }
        // A literal marker is `{N}CRLF`. Anything else is text that happens to contain braces.
        if j + 3 > response.len() || &response[j + 1..j + 3] != b"\r\n" {
            i += 1;
            continue;
        }
        let digits = std::str::from_utf8(&response[i + 1..j]).unwrap_or("");
        let Ok(declared) = digits.parse::<usize>() else {
            // Too many digits to be a real count; nothing on this wire is that big.
            anyhow::bail!(
                "IMAP response declares a literal of {{{digits}}}, which is not a usable octet \
                 count; the client would block reading it"
            );
        };
        let start = j + 3;
        let available = response.len() - start;
        if declared > available {
            anyhow::bail!(
                "IMAP response declares a literal of {{{declared}}} octets but only {available} \
                 follow it. RFC 3501 §4.3 makes the client read exactly the declared count, so \
                 it would block on octets that are never sent. Count the bytes of the literal \
                 itself — CRLFs included — and declare that number."
            );
        }
        match response.get(start + declared) {
            None => anyhow::bail!(
                "IMAP response declares a literal of {{{declared}}} octets that runs to the very \
                 end, so the line carrying it is never terminated. A literal is an element of a \
                 line, not the line: follow it with the rest of the line and a CRLF."
            ),
            Some(b) if LITERAL_FOLLOWERS.contains(b) => {}
            Some(b) => anyhow::bail!(
                "IMAP response declares a literal of {{{declared}}} octets, but octet {declared} \
                 is followed by {:?} rather than a space, a ')' or the CR of a CRLF — so the \
                 count does not line up with the response around it. RFC 3501 §4.3 makes the \
                 client read exactly {declared} octets as data, swallowing the start of what \
                 comes next and desynchronising the connection for good. Count the literal's \
                 own bytes, CRLFs included.",
                *b as char
            ),
        }
        // Skip the payload: a `{5}` inside a message body is data, not a second marker.
        i = start + declared;
    }
    Ok(())
}

/// IMAP protocol action handler
pub struct ImapProtocol;

impl ImapProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_imap_greeting(&self, action: serde_json::Value) -> Result<ActionResult> {
        let hostname = action
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");

        // IMAP4rev1 is always first: RFC 3501 6.1.1 requires it, and this list is also what
        // NetGet answers the CAPABILITY command with (`super::greeting_capabilities`).
        let capabilities = super::with_imap4rev1(
            &action
                .get("capabilities")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default(),
        );

        debug!(
            "IMAP sending greeting: hostname={}, capabilities={}",
            hostname, capabilities
        );

        let greeting = format!(
            "* OK [CAPABILITY {}] {} IMAP4rev1 Service Ready\r\n",
            capabilities, hostname
        );
        Ok(ActionResult::Output(greeting.into_bytes()))
    }

    fn execute_send_imap_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Support two formats:
        // 1. Full response string in 'response' field (simple format for mocks/LLM)
        // 2. Structured fields: tag, status, message, code (detailed format)

        if let Some(response_str) = action.get("response").and_then(|v| v.as_str()) {
            // Simple format: just send the response as-is
            debug!("IMAP sending response (simple format): {}", response_str);
            let mut response = response_str.to_string();
            if !response.ends_with("\r\n") {
                response.push_str("\r\n");
            }
            return Ok(ActionResult::Output(response.into_bytes()));
        }

        // Structured format: build response from tag/status/message/code
        let tag = action
            .get("tag")
            .and_then(|v| v.as_str())
            .context("Missing 'tag' field in send_imap_response (use 'response' field for untagged responses)")?;

        // Required, never defaulted. RFC 3501 §7.1 gives a tagged response no default
        // condition, and the one this used to assume was `OK` - so a model that emitted a
        // `tag` and omitted `status` produced `A001 OK`, which `handle_auth` reads as a
        // successful LOGIN. A forgotten field is not an authentication decision.
        let status = action
            .get("status")
            .and_then(|v| v.as_str())
            .context("Missing 'status' field in send_imap_response: a tagged response must say OK, NO or BAD explicitly")?;

        // RFC 3501 9 (`resp-text`): the text after the status is at least one character, so
        // `a1 OK` alone is not a response - imaplib rejects it ("unexpected response") and
        // aborts the session. A model that leaves `message` out gets a neutral text instead.
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .filter(|m| !m.trim().is_empty())
            .unwrap_or("completed");

        let code = action.get("code").and_then(|v| v.as_str());

        debug!(
            "IMAP sending response (structured format): tag={}, status={}, message={}",
            tag, status, message
        );

        let response = if let Some(code) = code {
            format!("{} {} [{}] {}\r\n", tag, status, code, message)
        } else {
            format!("{} {} {}\r\n", tag, status, message)
        };

        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_untagged(&self, action: serde_json::Value) -> Result<ActionResult> {
        let response_type = action
            .get("response_type")
            .and_then(|v| v.as_str())
            .context("Missing 'response_type' field in send_imap_untagged")?;

        let data = action.get("data").and_then(|v| v.as_str()).unwrap_or("");

        debug!(
            "IMAP sending untagged response: type={}, data={}",
            response_type, data
        );

        let response = if data.is_empty() {
            format!("* {}\r\n", response_type)
        } else {
            format!("* {} {}\r\n", response_type, data)
        };

        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let mailboxes = action
            .get("mailboxes")
            .and_then(|v| v.as_array())
            .context("Missing 'mailboxes' array in send_imap_list")?;

        debug!("IMAP sending LIST response: {} mailboxes", mailboxes.len());

        let mut response = Vec::new();

        for mailbox in mailboxes {
            let name = mailbox
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("INBOX");

            let delimiter = mailbox
                .get("delimiter")
                .and_then(|v| v.as_str())
                .unwrap_or("/");

            let flags = mailbox
                .get("flags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();

            let line = if flags.is_empty() {
                format!("* LIST () \"{}\" \"{}\"\r\n", delimiter, name)
            } else {
                format!("* LIST ({}) \"{}\" \"{}\"\r\n", flags, delimiter, name)
            };
            response.extend_from_slice(line.as_bytes());
        }

        Ok(ActionResult::Output(response))
    }

    fn execute_send_imap_status(&self, action: serde_json::Value) -> Result<ActionResult> {
        let mailbox = action
            .get("mailbox")
            .and_then(|v| v.as_str())
            .context("Missing 'mailbox' field in send_imap_status")?;

        let status_items = action
            .get("items")
            .and_then(|v| v.as_object())
            .context("Missing 'items' object in send_imap_status")?;

        debug!("IMAP sending STATUS response for mailbox: {}", mailbox);

        let mut items_str = Vec::new();
        for (key, value) in status_items {
            items_str.push(format!("{} {}", key.to_uppercase(), value));
        }

        let response = format!("* STATUS \"{}\" ({})\r\n", mailbox, items_str.join(" "));
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_fetch(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Support two formats:
        // 1. Structured: {"sequence": N, "data": {"FLAGS": [...], "BODY[]": "..."}}
        // 2. Simple: {"message_id": N, "body": "...", "flags": [...], ...}

        let sequence = action
            .get("sequence")
            .or_else(|| action.get("message_id"))
            .and_then(|v| v.as_u64())
            .context("Missing 'sequence' or 'message_id' field in send_imap_fetch")?;

        debug!("IMAP sending FETCH response for message: {}", sequence);

        let mut items = Vec::new();

        // Check if using structured format with "data" object
        if let Some(data) = action.get("data").and_then(|v| v.as_object()) {
            // Structured format - use "data" object
            for (key, value) in data {
                match key.to_uppercase().as_str() {
                    "FLAGS" => {
                        if let Some(flags_arr) = value.as_array() {
                            let flags: Vec<&str> =
                                flags_arr.iter().filter_map(|v| v.as_str()).collect();
                            items.push(format!("FLAGS ({})", flags.join(" ")));
                        }
                    }
                    "UID" => {
                        if let Some(uid) = value.as_u64() {
                            items.push(format!("UID {}", uid));
                        }
                    }
                    "RFC822.SIZE" => {
                        if let Some(size) = value.as_u64() {
                            items.push(format!("RFC822.SIZE {}", size));
                        }
                    }
                    "BODY[]" | "RFC822" => {
                        if let Some(body) = value.as_str() {
                            items.push(format!(
                                "{} {{{}}}\r\n{}",
                                key.to_uppercase(),
                                body.len(),
                                body
                            ));
                        }
                    }
                    "ENVELOPE" => {
                        if let Some(env_str) = value.as_str() {
                            items.push(format!("ENVELOPE {}", env_str));
                        }
                    }
                    "BODYSTRUCTURE" => {
                        if let Some(bs_str) = value.as_str() {
                            items.push(format!("BODYSTRUCTURE {}", bs_str));
                        }
                    }
                    "INTERNALDATE" => {
                        if let Some(date) = value.as_str() {
                            items.push(format!("INTERNALDATE \"{}\"", date));
                        }
                    }
                    _ => {
                        // Handle any other custom items
                        if let Some(val_str) = value.as_str() {
                            items.push(format!("{} {}", key.to_uppercase(), val_str));
                        }
                    }
                }
            }
        } else {
            // Simple format - check for direct fields
            if let Some(body) = action.get("body").and_then(|v| v.as_str()) {
                items.push(format!("RFC822 {{{}}}\r\n{}", body.len(), body));
            }

            if let Some(flags_arr) = action.get("flags").and_then(|v| v.as_array()) {
                let flags: Vec<&str> = flags_arr.iter().filter_map(|v| v.as_str()).collect();
                items.push(format!("FLAGS ({})", flags.join(" ")));
            }

            if let Some(uid) = action.get("uid").and_then(|v| v.as_u64()) {
                items.push(format!("UID {}", uid));
            }

            if let Some(size) = action.get("size").and_then(|v| v.as_u64()) {
                items.push(format!("RFC822.SIZE {}", size));
            }
        }

        let response = format!("* {} FETCH ({})\r\n", sequence, items.join(" "));
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_search(&self, action: serde_json::Value) -> Result<ActionResult> {
        let empty_vec = vec![];
        let results = action
            .get("results")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_vec);

        debug!("IMAP sending SEARCH response: {} results", results.len());

        let ids: Vec<String> = results
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n.to_string()))
            .collect();

        let response = if ids.is_empty() {
            "* SEARCH\r\n".to_string()
        } else {
            format!("* SEARCH {}\r\n", ids.join(" "))
        };

        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_exists(&self, action: serde_json::Value) -> Result<ActionResult> {
        let count = action.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

        debug!("IMAP sending EXISTS response: {} messages", count);

        let response = format!("* {} EXISTS\r\n", count);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_recent(&self, action: serde_json::Value) -> Result<ActionResult> {
        let count = action.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

        debug!("IMAP sending RECENT response: {} messages", count);

        let response = format!("* {} RECENT\r\n", count);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_flags(&self, action: serde_json::Value) -> Result<ActionResult> {
        let flags = action
            .get("flags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<&str>>()
                    .join(" ")
            })
            .unwrap_or_default();

        debug!("IMAP sending FLAGS response: {}", flags);

        let response = format!("* FLAGS ({})\r\n", flags);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_expunge(&self, action: serde_json::Value) -> Result<ActionResult> {
        let sequence = action
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("Missing 'sequence' field in send_imap_expunge")?;

        debug!("IMAP sending EXPUNGE response for message: {}", sequence);

        let response = format!("* {} EXPUNGE\r\n", sequence);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_imap_select(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Generate SELECT/EXAMINE response with mailbox status
        let exists = action.get("exists").and_then(|v| v.as_u64()).unwrap_or(0);

        let recent = action.get("recent").and_then(|v| v.as_u64());

        let unseen = action.get("unseen").and_then(|v| v.as_u64());

        let uidvalidity = action
            .get("uidvalidity")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        let uidnext = action.get("uidnext").and_then(|v| v.as_u64());

        let flags = action.get("flags").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .join(" ")
        });

        let permanent_flags = action
            .get("permanent_flags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<&str>>()
                    .join(" ")
            });

        let _read_write = action
            .get("read_write")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        debug!(
            "IMAP sending SELECT response: exists={}, recent={:?}, unseen={:?}",
            exists, recent, unseen
        );

        let mut response = String::new();

        // Required responses
        response.push_str(&format!("* {} EXISTS\r\n", exists));

        if let Some(recent) = recent {
            response.push_str(&format!("* {} RECENT\r\n", recent));
        }

        // Optional OK responses with codes
        if let Some(unseen) = unseen {
            response.push_str(&format!(
                "* OK [UNSEEN {}] Message {} is first unseen\r\n",
                unseen, unseen
            ));
        }

        response.push_str(&format!(
            "* OK [UIDVALIDITY {}] UIDs valid\r\n",
            uidvalidity
        ));

        if let Some(uidnext) = uidnext {
            response.push_str(&format!(
                "* OK [UIDNEXT {}] Predicted next UID\r\n",
                uidnext
            ));
        }

        // FLAGS
        if let Some(flags) = flags {
            response.push_str(&format!("* FLAGS ({})\r\n", flags));
        } else {
            response.push_str("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        }

        // PERMANENTFLAGS
        if let Some(perm_flags) = permanent_flags {
            response.push_str(&format!(
                "* OK [PERMANENTFLAGS ({})] Limited\r\n",
                perm_flags
            ));
        } else {
            response.push_str("* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n");
        }

        // Note: We don't send the tagged response here - that should be sent separately
        // via send_imap_response action

        Ok(ActionResult::Output(response.into_bytes()))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ImapProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // IMAP doesn't need async actions for now (all commands are synchronous request/response)
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_imap_greeting_action(),
            send_imap_response_action(),
            send_imap_untagged_action(),
            send_imap_list_action(),
            send_imap_status_action(),
            send_imap_fetch_action(),
            send_imap_search_action(),
            send_imap_select_action(),
            send_imap_exists_action(),
            send_imap_recent_action(),
            send_imap_flags_action(),
            send_imap_expunge_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IMAP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_imap_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>IMAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["imap"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta: exercised against TWO real, independent clients — async-imap (Rust) and
            // python3's stdlib imaplib — each completing login, SELECT, FETCH, SEARCH and
            // LOGOUT. Not Stable: Stable additionally wants spec compliance and scripting
            // support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .implementation(
                "Manual line-based IMAP4rev1 parsing (tag/command/args split), plain TCP only",
            )
            .llm_control("Authentication + mailbox ops + FETCH")
            .e2e_testing(
                "TWO independent clients, neither of them a crate this server frames with (it \
                 frames by hand). \
                 (1) async-imap 0.11, a Rust IMAP client, in \
                 tests/server/imap/e2e_client_test.rs -- eleven tests, none #[ignore]d and none \
                 skip-gated (async-imap is a plain optional dependency the `imap` feature turns \
                 on, so it compiles wherever the feature does). It completes LOGIN success and \
                 failure, CAPABILITY, LIST, SELECT and EXAMINE with the parsed EXISTS count \
                 asserted, FETCH with decoded messages, SEARCH, STATUS, NOOP/LOGOUT and \
                 concurrent sessions -- all through the client's own parser, so a reply it \
                 rejected would fail rather than be counted as bytes on a socket. \
                 (2) python3's stdlib `imaplib`, in tests/server/imap/real_client_test.rs: a \
                 single session of greeting, CAPABILITY, LOGIN, SELECT, SEARCH, FETCH and \
                 LOGOUT, asserted on what imaplib parsed. It adds three things async-imap does \
                 not reach here -- the literal BYTE count (the fetched body carries multi-byte \
                 UTF-8, so a `{n}` counted in characters desynchronises the connection), \
                 that imaplib reads NetGet's answer to its own CAPABILITY command (the \
                 greeting there carries no capability code, so it is the only source), and \
                 select()'s return value, which is the untagged EXISTS count rather \
                 than the tagged completion. It FAILS rather than skips when python3 is absent, \
                 and imaplib needs no install of its own. \
                 Verified non-vacuous by breaking the server twice: `body.len()` made \
                 `body.chars().count()` left the FETCH completing OK while imaplib returned no \
                 FETCH data at all, and removing the `* n EXISTS` line left SELECT completing \
                 OK while imaplib's select() returned [None]. In both cases the TAGGED response \
                 was still correct, which is what a test asserting only on the completion would \
                 have looked at. \
                 This field read `Raw TCP client issuing tagged IMAP commands` for a long time, \
                 which described a test that no longer exists and UNDER-stated the evidence by \
                 the whole distance between a hand-written prober and a real client. \
                 UNPROVEN: IMAPS, STARTTLS, SASL, and literal continuation ('+') handling, none \
                 of which are implemented.",
            )
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(143))
            .well_known_port(143)
            .max_inbound_bytes(crate::server::imap::MAX_COMMAND_BYTES)
            .notes(
                "Tracks session state (NotAuthenticated/Authenticated/Selected/Logout) but stores \
                 no mailboxes or messages - the model answers every FETCH. No IMAPS, no STARTTLS, \
                 no SASL, no literal continuation ('+') handling.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IMAP mail server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an IMAP mail server on port 143"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 143,
                "base_stack": "imap",
                "instruction": "IMAP server with INBOX containing 5 messages, accept login for 'testuser'"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 143,
                "base_stack": "imap",
                "event_handlers": [{
                    "event_pattern": "imap_command",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle IMAP commands\ntag = event.get('tag', 'A001')\ncmd = event.get('command', '').upper()\nif cmd == 'LOGIN':\n    respond([{'type': 'send_imap_response', 'tag': tag, 'status': 'OK', 'message': 'LOGIN completed'}])\nelif cmd == 'SELECT':\n    respond([{'type': 'send_imap_select', 'exists': 5, 'recent': 0}, {'type': 'send_imap_response', 'tag': tag, 'status': 'OK', 'code': 'READ-WRITE', 'message': 'SELECT completed'}])\nelse:\n    respond([{'type': 'send_imap_response', 'tag': tag, 'status': 'OK', 'message': 'Completed'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 143,
                "base_stack": "imap",
                "event_handlers": [{
                    "event_pattern": "imap_command",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_imap_response",
                            "tag": "A001",
                            "status": "OK",
                            "message": "Completed"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for ImapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::imap::ImapServer;
            ImapServer::spawn_with_llm_actions(
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
            .context("Missing 'type' field in action")?
            .to_string();

        let result = match action_type.as_str() {
            "send_imap_greeting" => self.execute_send_imap_greeting(action),
            "send_imap_response" => self.execute_send_imap_response(action),
            "send_imap_untagged" => self.execute_send_imap_untagged(action),
            "send_imap_list" => self.execute_send_imap_list(action),
            "send_imap_status" => self.execute_send_imap_status(action),
            "send_imap_fetch" => self.execute_send_imap_fetch(action),
            "send_imap_search" => self.execute_send_imap_search(action),
            "send_imap_select" => self.execute_send_imap_select(action),
            "send_imap_exists" => self.execute_send_imap_exists(action),
            "send_imap_recent" => self.execute_send_imap_recent(action),
            "send_imap_flags" => self.execute_send_imap_flags(action),
            "send_imap_expunge" => self.execute_send_imap_expunge(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown IMAP action: {}", action_type)),
        };

        // One choke point, so no action can put a mis-framed literal on the wire.
        //
        // `send_imap_response` is the one that needed it — its `response` field relays a
        // pre-framed, model-authored response verbatim — but the check belongs here rather
        // than in that one arm: every other action reaches the same socket, and a guard that
        // covers the path nobody has abused yet is the point of having one. The actions that
        // build their own literals (`send_imap_fetch` counts `body.len()`) are
        // correct-by-construction and pass unchanged.
        match result {
            Ok(ActionResult::Output(bytes)) => {
                validate_imap_literals(&bytes).with_context(|| {
                    format!("refusing to send the {action_type} response as framed")
                })?;
                Ok(ActionResult::Output(bytes))
            }
            other => other,
        }
    }
}

// ============================================================================
// Action Definitions
// ============================================================================

fn send_imap_greeting_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_greeting".to_string(),
        description: "The untagged '* OK [CAPABILITY ...]' greeting, sent once when a client \
                      connects. Its capability list is also NetGet's answer to the CAPABILITY \
                      command, so list only what your instruction says the server supports; \
                      IMAP4rev1 is always included."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "hostname".to_string(),
                type_hint: "string".to_string(),
                description: "Server hostname (default: localhost)".to_string(),
                required: false,
            },
            Parameter {
                name: "capabilities".to_string(),
                type_hint: "array".to_string(),
                description: "Capabilities beyond IMAP4rev1, one per entry (default: none)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_imap_greeting",
            "hostname": "mail.example.com",
            "capabilities": ["IMAP4rev1"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP greeting {hostname}")
                .with_debug("IMAP send_imap_greeting: {hostname}"),
        ),
    }
}

fn send_imap_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_response".to_string(),
        description: "Send an IMAP response line. Normally used for the tagged completion of a \
                      command: give 'tag' and 'status' and NetGet assembles '<tag> <status> \
                      [code] message'. Alternatively give 'response' alone to emit one \
                      pre-formatted line verbatim (useful for untagged banners)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "tag".to_string(),
                type_hint: "string".to_string(),
                description: "Command tag echoed from the client's request (e.g. 'A001'). \
                              Required unless 'response' is used."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "string".to_string(),
                description: "Response status: OK, NO, or BAD (default: OK)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable text after the status".to_string(),
                required: false,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Optional response code in brackets (e.g., READ-WRITE, READ-ONLY)"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "response".to_string(),
                type_hint: "string".to_string(),
                description: "A complete response line to send as-is, replacing tag/status/\
                              message/code (e.g. '* OK IMAP4rev1 Service Ready'). CRLF is added \
                              if missing."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_imap_response",
            "tag": "A001",
            "status": "OK",
            "message": "completed"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP {tag} {status}")
                .with_debug("IMAP send_imap_response: {tag} {status} {message}"),
        ),
    }
}

fn send_imap_untagged_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_untagged".to_string(),
        description: "Send untagged IMAP response (informational data)".to_string(),
        parameters: vec![
            Parameter {
                name: "response_type".to_string(),
                type_hint: "string".to_string(),
                description: "Type of untagged response (e.g., OK, BYE, NO, BAD, CAPABILITY)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Response data".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_imap_untagged",
            "response_type": "OK",
            "data": "[PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP * {response_type}")
                .with_debug("IMAP send_imap_untagged: {response_type}"),
        ),
    }
}

fn send_imap_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_list".to_string(),
        description: "The answer to LIST: one '* LIST' line per mailbox the instruction \
                      says exists, and no other. NetGet adds the tagged OK. The example's \
                      mailbox names are placeholders; never send them."
            .to_string(),
        parameters: vec![Parameter {
            name: "mailboxes".to_string(),
            type_hint: "array".to_string(),
            description: "Array of mailbox objects with name, delimiter, and flags".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_list",
            "mailboxes": [
                {
                    "name": "Example-Folder-A",
                    "delimiter": "/",
                    "flags": []
                },
                {
                    "name": "Example-Folder-B",
                    "delimiter": "/",
                    "flags": []
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP LIST {mailboxes_len} mailboxes")
                .with_debug("IMAP send_imap_list: {mailboxes_len} mailboxes"),
        ),
    }
}

fn send_imap_status_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_status".to_string(),
        description: "Send IMAP STATUS response with mailbox status information".to_string(),
        parameters: vec![
            Parameter {
                name: "mailbox".to_string(),
                type_hint: "string".to_string(),
                description: "Mailbox name".to_string(),
                required: true,
            },
            Parameter {
                name: "items".to_string(),
                type_hint: "object".to_string(),
                description: "Status items (MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN)"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_imap_status",
            "mailbox": "INBOX",
            "items": {
                "MESSAGES": 5,
                "RECENT": 2,
                "UIDNEXT": 1006,
                "UIDVALIDITY": 1234567890,
                "UNSEEN": 3
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP STATUS {mailbox}")
                .with_debug("IMAP send_imap_status: {mailbox}"),
        ),
    }
}

fn send_imap_fetch_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_fetch".to_string(),
        description: "Send IMAP FETCH response with message data".to_string(),
        parameters: vec![
            Parameter {
                name: "sequence".to_string(),
                type_hint: "number".to_string(),
                description: "Message sequence number".to_string(),
                required: true,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "object".to_string(),
                description: "Message data (FLAGS, UID, RFC822.SIZE, BODY[], ENVELOPE, etc.)"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_imap_fetch",
            "sequence": 1,
            "data": {
                "FLAGS": ["\\Seen"],
                "UID": 1001,
                "RFC822.SIZE": 2048,
                "BODY[]": "From: sender@example.com\r\nSubject: Test\r\n\r\nHello World"
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP FETCH {sequence}")
                .with_debug("IMAP send_imap_fetch: sequence={sequence}"),
        ),
    }
}

fn send_imap_search_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_search".to_string(),
        description: "Send IMAP SEARCH response with matching message IDs".to_string(),
        parameters: vec![Parameter {
            name: "results".to_string(),
            type_hint: "array".to_string(),
            description: "Array of message sequence numbers matching search criteria".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_search",
            "results": [1, 3, 5]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP SEARCH {results_len} results")
                .with_debug("IMAP send_imap_search: {results_len} results"),
        ),
    }
}

fn send_imap_exists_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_exists".to_string(),
        description: "Send IMAP EXISTS response indicating number of messages in mailbox"
            .to_string(),
        parameters: vec![Parameter {
            name: "count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of messages that exist".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_exists",
            "count": 5
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP {count} EXISTS")
                .with_debug("IMAP send_imap_exists: {count}"),
        ),
    }
}

fn send_imap_recent_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_recent".to_string(),
        description: "Send IMAP RECENT response indicating number of recent messages".to_string(),
        parameters: vec![Parameter {
            name: "count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of recent messages".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_recent",
            "count": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP {count} RECENT")
                .with_debug("IMAP send_imap_recent: {count}"),
        ),
    }
}

fn send_imap_flags_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_flags".to_string(),
        description: "Send IMAP FLAGS response with available message flags".to_string(),
        parameters: vec![Parameter {
            name: "flags".to_string(),
            type_hint: "array".to_string(),
            description: "Array of available flags".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_flags",
            "flags": ["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP FLAGS")
                .with_debug("IMAP send_imap_flags: {flags_len} flags"),
        ),
    }
}

fn send_imap_expunge_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_expunge".to_string(),
        description: "Send IMAP EXPUNGE response indicating a message was permanently removed"
            .to_string(),
        parameters: vec![Parameter {
            name: "sequence".to_string(),
            type_hint: "number".to_string(),
            description: "Sequence number of the expunged message".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_imap_expunge",
            "sequence": 3
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP {sequence} EXPUNGE")
                .with_debug("IMAP send_imap_expunge: {sequence}"),
        ),
    }
}

fn send_imap_select_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_imap_select".to_string(),
        description: "The answer to SELECT/EXAMINE: the untagged block every client reads, \
                      starting with '* <exists> EXISTS' - the mailbox's message count - then \
                      RECENT, UIDVALIDITY, UIDNEXT, FLAGS and PERMANENTFLAGS. NetGet adds the \
                      tagged OK. A bare tagged OK is not an answer to SELECT: without EXISTS the \
                      client does not know how many messages there are."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "exists".to_string(),
                type_hint: "number".to_string(),
                description: "Number of messages in mailbox".to_string(),
                required: true,
            },
            Parameter {
                name: "recent".to_string(),
                type_hint: "number".to_string(),
                description: "Number of recent messages".to_string(),
                required: false,
            },
            Parameter {
                name: "unseen".to_string(),
                type_hint: "number".to_string(),
                description: "Sequence number of first unseen message".to_string(),
                required: false,
            },
            Parameter {
                name: "uidvalidity".to_string(),
                type_hint: "number".to_string(),
                description: "UID validity value (default: 1)".to_string(),
                required: false,
            },
            Parameter {
                name: "uidnext".to_string(),
                type_hint: "number".to_string(),
                description: "Predicted next UID".to_string(),
                required: false,
            },
            Parameter {
                name: "flags".to_string(),
                type_hint: "array".to_string(),
                description: "Available message flags".to_string(),
                required: false,
            },
            Parameter {
                name: "permanent_flags".to_string(),
                type_hint: "array".to_string(),
                description: "Permanent message flags".to_string(),
                required: false,
            },
            Parameter {
                name: "read_write".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether mailbox is read-write (default: true)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_imap_select",
            "exists": 5,
            "recent": 2,
            "unseen": 3,
            "uidvalidity": 1,
            "uidnext": 6,
            "flags": ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"],
            "permanent_flags": ["\\Deleted", "\\Seen", "\\*"],
            "read_write": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IMAP SELECT {exists} msgs")
                .with_debug("IMAP send_imap_select: exists={exists}, recent={recent}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data from client before processing".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(LogTemplate::new().with_debug("IMAP waiting for more data")),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the IMAP connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("IMAP connection closed")
                .with_debug("IMAP close_connection"),
        ),
    }
}

// ============================================================================
// Event Types
// ============================================================================

pub static IMAP_CONNECTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_connection",
        "Initial IMAP connection established - send greeting",
        json!({
            "type": "send_imap_greeting",
            "hostname": "mail.example.com",
            "capabilities": ["IMAP4rev1"]
        }),
    )
    .with_parameters(vec![])
    // An IMAP greeting is an *untagged* line, so all three of these produce a valid one:
    // `send_imap_greeting` builds `* OK [CAPABILITY ...] ... Service Ready`, while
    // `send_imap_untagged` and `send_imap_response`'s single-string `response` form let the
    // model write the banner verbatim. Only `send_imap_greeting` used to be advertised, so a
    // model - or a test mock - answering with the raw banner it was told to send had its
    // action rejected as unknown, retried, and the connection then died before the greeting
    // was ever written.
    .with_actions(vec![
        send_imap_greeting_action(),
        send_imap_untagged_action(),
        send_imap_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("IMAP connection from {client_ip}")
            .with_debug("IMAP connection from {client_ip}:{client_port}")
            .with_trace("IMAP connection: {json_pretty(.)}"),
    )
});

pub static IMAP_AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_auth",
        "IMAP LOGIN command received - authenticate user",
        json!({
            "type": "send_imap_response",
            "tag": "A001",
            "status": "OK",
            "message": "LOGIN completed"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "tag".to_string(),
            type_hint: "string".to_string(),
            description: "Command tag".to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username for authentication".to_string(),
            required: true,
        },
        Parameter {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "Password for authentication".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which action answers this LOGIN".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![send_imap_response_action(), close_connection_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("IMAP LOGIN {client_ip} user={username}")
            .with_debug("IMAP auth from {client_ip}:{client_port}, user={username}")
            .with_trace("IMAP auth: {json_pretty(.)}"),
    )
});

pub static IMAP_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_command",
        "IMAP command received from client (SELECT, LIST, FETCH, STORE, SEARCH, LOGOUT, ...). \
         LOGIN is not delivered here - it raises imap_auth instead - and CAPABILITY is answered \
         by NetGet from the greeting's list. Untagged responses come first; the one tagged \
         response carrying the client's tag completes the command, and NetGet adds it when you \
         send only untagged data. answer_with names the action for this command.",
        json!([
            {"type": "send_imap_exists", "count": 5},
            {"type": "send_imap_response", "tag": "A002", "status": "OK", "code": "READ-WRITE", "message": "SELECT completed"}
        ]),
    )
    .with_parameters(vec![
        Parameter {
            name: "tag".to_string(),
            type_hint: "string".to_string(),
            description: "Command tag".to_string(),
            required: true,
        },
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "IMAP command (SELECT, LIST, FETCH, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which action answers this command, when its name says".to_string(),
            required: false,
        },
        Parameter {
            name: "args".to_string(),
            type_hint: "string".to_string(),
            description: "Command arguments".to_string(),
            required: false,
        },
        Parameter {
            name: "session_state".to_string(),
            type_hint: "string".to_string(),
            description:
                "Current session state (NotAuthenticated, Authenticated, Selected, Logout)"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "authenticated_user".to_string(),
            type_hint: "string".to_string(),
            description: "Authenticated username (if any)".to_string(),
            required: false,
        },
        Parameter {
            name: "selected_mailbox".to_string(),
            type_hint: "string".to_string(),
            description: "Currently selected mailbox (if any)".to_string(),
            required: false,
        },
    ])
    // Must list every action that can legitimately answer a command: `call_llm` builds the
    // model's tool list from here, not from `get_sync_actions()`. `send_imap_select` was
    // missing, so the one action that emits a complete SELECT/EXAMINE response was unreachable
    // over the LLM path even though the protocol's own script example uses it.
    .with_actions(vec![
        send_imap_response_action(),
        send_imap_untagged_action(),
        send_imap_list_action(),
        send_imap_status_action(),
        send_imap_select_action(),
        send_imap_fetch_action(),
        send_imap_search_action(),
        send_imap_exists_action(),
        send_imap_recent_action(),
        send_imap_flags_action(),
        send_imap_expunge_action(),
        wait_for_more_action(),
        close_connection_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("IMAP {client_ip} {tag} {command}")
            .with_debug("IMAP command from {client_ip}:{client_port}: {tag} {command} {args}")
            .with_trace("IMAP command: {json_pretty(.)}"),
    )
});

/// `imap_command` as raised for a command with one data answer: the same event id, offering that
/// answer's action and `send_imap_response` (for a NO or BAD), with a description naming the
/// command instead of listing every command there is.
///
/// Offered the whole vocabulary, llama3.1:8b answered LIST with a bare tagged OK - or a tagged
/// OK reading "Login successful. Folders: INBOX, Archive, Receipts." - in 6 of 8 replays of one
/// captured prompt; its reasoning said "User wants to log in", primed by the general
/// description's sentence about LOGIN. Offered `send_imap_list` and `send_imap_response` under a
/// description that names LIST, it answered with the list in 8 of 8. The id is unchanged, so
/// handlers for `imap_command` match as before, and `get_imap_event_types` still declares the one
/// event with every action.
static COMMAND_EVENTS: LazyLock<Vec<(&'static [&'static str], EventType)>> = LazyLock::new(|| {
    let narrowed = |description: &str, answer: ActionDefinition| {
        let mut event = IMAP_COMMAND_EVENT.clone();
        event.description = description.to_string();
        event.response_example = answer.example.clone();
        event.alternative_examples.clear();
        event.actions = vec![answer, send_imap_response_action()];
        event
    };
    vec![
        (
            &["LIST", "LSUB"][..],
            narrowed(
                "The client sent LIST (or LSUB), asking which mailboxes the account has. Answer \
                 with send_imap_list, one entry per mailbox; NetGet adds the tagged OK. \
                 send_imap_response with status NO or BAD refuses the command.",
                send_imap_list_action(),
            ),
        ),
        (
            &["SELECT", "EXAMINE"][..],
            narrowed(
                "The client sent SELECT (or EXAMINE), opening the mailbox named in args. Answer \
                 with send_imap_select, whose exists is the number of messages in that mailbox; \
                 NetGet adds the tagged OK. send_imap_response with status NO refuses it when \
                 there is no such mailbox.",
                send_imap_select_action(),
            ),
        ),
    ]
});

/// The event to raise for `command`: its narrowed `imap_command` when it has one, the declared
/// event with every action otherwise.
pub fn command_event(command: &str) -> &'static EventType {
    COMMAND_EVENTS
        .iter()
        .find(|(commands, _)| commands.iter().any(|c| c.eq_ignore_ascii_case(command)))
        .map(|(_, event)| event)
        .unwrap_or(&IMAP_COMMAND_EVENT)
}

pub fn get_imap_event_types() -> Vec<EventType> {
    vec![
        IMAP_CONNECTION_EVENT.clone(),
        IMAP_AUTH_EVENT.clone(),
        IMAP_COMMAND_EVENT.clone(),
    ]
}
