//! WebDAV protocol actions.
//!
//! WebDAV (RFC 4918) is answered here method-by-method: the server owns the HTTP framing and
//! the DAV:multistatus XML, and the **model owns every byte of content**. There is no
//! filesystem behind this protocol — not on disk, not in memory. A `GET` returns what the
//! model says it returns; a `PROPFIND` lists what the model says is there; a `PUT` succeeds
//! only because the model answered with a success status.
//!
//! This replaced a `dav_server::memfs::MemFs`-backed implementation. That version stored real
//! bytes in the process, which is the storage a protocol is forbidden to implement, and it
//! dropped the `OllamaClient` on startup so the server instruction was read by nobody. The
//! `DavFileSystem` route was considered and rejected: `dav-server` calls `metadata()` once for
//! the target and again for every directory entry, so a model-backed `DavFileSystem` costs a
//! model round-trip per *property*, not per request. Answering the verbs directly costs
//! exactly one round-trip per request and lets the model choose the status code, which the
//! `FsError` enum cannot express.
//!
//! **Three actions, one event.** `webdav_request` fires for every method the model is allowed
//! to answer; the model replies with `send_webdav_listing` (PROPFIND -> 207 multistatus),
//! `send_webdav_file` (GET/HEAD -> 200 + body), or `send_webdav_status` (everything else:
//! 201, 204, 404, 405, 409, 423, 507...). No action means the request is *refused* with 503,
//! never silently accepted — see `build_webdav_response` in `mod.rs`.
//!
//! Nothing here carries raw bytes or base64. File content is a string; a directory listing is
//! an array of `{name, is_collection, size, content_type}` objects and the XML is generated
//! from it.

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

/// WebDAV protocol action handler
pub struct WebDavProtocol;

impl WebDavProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebDavProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// XML / URI helpers
//
// WebDAV response bodies are XML and hrefs are URIs, so everything the model
// supplies has to be encoded before it is spliced into either. Both encoders
// are deliberately conservative: a name is percent-encoded down to the
// unreserved set before it becomes an href, and every text node is XML-escaped.
// ============================================================================

/// Escape a string for use as XML character data or an attribute value.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a path for use inside `<D:href>`.
///
/// Only RFC 3986 unreserved characters and `/` survive unencoded. That is stricter than it
/// needs to be, but a name the model invented may contain anything at all, and an
/// under-encoded href produces a multistatus body that XML parsers reject outright.
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Decode `%XX` escapes in a request path. Invalid escapes are left verbatim, and bytes that
/// are not valid UTF-8 are replaced rather than rejected — the path is attacker-controlled.
pub(crate) fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An RFC 1123 / IMF-fixdate timestamp, the only format `getlastmodified` may use.
///
/// Every WebDAV client parses this field, and several (including `reqwest_dav`) treat a file
/// entry without a parseable `getlastmodified` as a decode error, so one is always emitted
/// even when the model supplied none.
fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Ensure a path starts with `/`.
fn absolute(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

/// Ensure a collection path starts and ends with `/`.
fn as_collection(path: &str) -> String {
    let p = absolute(path);
    if p.ends_with('/') {
        p
    } else {
        format!("{}/", p)
    }
}

/// The last segment of a path, used as `displayname`.
fn display_name(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// One `<D:response>` element of a multistatus body.
struct DavResource {
    href: String,
    name: String,
    is_collection: bool,
    size: u64,
    content_type: String,
    last_modified: String,
}

impl DavResource {
    fn render(&self, out: &mut String) {
        out.push_str("<D:response><D:href>");
        out.push_str(&xml_escape(&percent_encode_path(&self.href)));
        out.push_str("</D:href><D:propstat><D:prop><D:displayname>");
        out.push_str(&xml_escape(&self.name));
        out.push_str("</D:displayname><D:getlastmodified>");
        out.push_str(&xml_escape(&self.last_modified));
        out.push_str("</D:getlastmodified>");
        if self.is_collection {
            out.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
        } else {
            out.push_str("<D:resourcetype/>");
            out.push_str(&format!(
                "<D:getcontentlength>{}</D:getcontentlength>",
                self.size
            ));
        }
        out.push_str("<D:getcontenttype>");
        out.push_str(&xml_escape(&self.content_type));
        out.push_str("</D:getcontenttype></D:prop><D:status>HTTP/1.1 200 OK</D:status>");
        out.push_str("</D:propstat></D:response>");
    }
}

fn render_multistatus(resources: &[DavResource]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">",
    );
    for r in resources {
        r.render(&mut out);
    }
    out.push_str("</D:multistatus>");
    out
}

/// Wrap a status/headers/body triple in the `ActionResult::Output` envelope that
/// `build_webdav_response` (`mod.rs`) turns into the real HTTP response.
fn webdav_output(
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
) -> Result<ActionResult> {
    let header_map: serde_json::Map<String, serde_json::Value> = headers
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
    let payload = json!({
        "status": status,
        "headers": serde_json::Value::Object(header_map),
        "body": body,
    });
    Ok(ActionResult::Output(serde_json::to_vec(&payload)?))
}

/// Read a status code that a model may have quoted (`200` or `"200"`).
fn parse_status(value: &serde_json::Value) -> Option<u16> {
    let n = match value {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }?;
    if (100..=599).contains(&n) {
        Some(n as u16)
    } else {
        None
    }
}

/// Read a field that should be text but may arrive as any JSON value.
fn as_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ============================================================================
// Protocol trait
// ============================================================================

impl Protocol for WebDavProtocol {
    /// No async actions: WebDAV is purely reactive, like HTTP. Nothing happens on a WebDAV
    /// server except in response to a request.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_webdav_listing_action(),
            send_webdav_file_action(),
            send_webdav_status_action(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![WEBDAV_REQUEST_EVENT.clone()]
    }

    fn protocol_name(&self) -> &'static str {
        "WebDAV"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WEBDAV"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["webdav", "dav"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against TWO real and independent WebDAV clients —
            // `reqwest_dav` (PROPFIND parsed into typed entries, a PUT/GET round-trip,
            // MKCOL, a refusal) and the real `curl` binary issuing PROPFIND/MKCOL/PUT/GET/
            // COPY, with the multistatus body read back as XML. Neither test is `#[ignore]`d
            // and neither skips: the curl one FAILS when curl is absent. That is the
            // evidence Beta asks for, from two implementations rather than one.
            //
            // Not Stable: the property model is fixed (no PROPPATCH dead-property storage),
            // locks are accepted and never enforced, and neither spec compliance nor
            // scripting support has been reviewed.
            //
            // This block previously stacked two contradictory paragraphs — one arguing
            // "Not Beta", one arguing "Beta" — immediately above `.state(Beta)`, and
            // `CLAUDE.md` had copied the first. That is the shape the root CLAUDE.md warns
            // about for `ssh`; keep one argument here, for the rating actually declared.
            .state(DevelopmentState::Beta)
            .implementation(
                "hyper v1.0 HTTP/1.1 with WebDAV methods answered directly; DAV:multistatus \
                 XML generated from model-supplied entries. No filesystem of any kind.",
            )
            .llm_control(
                "Everything the client observes: directory listings, file content, and the \
                 status code of every write (PUT/MKCOL/DELETE/COPY/MOVE/PROPPATCH)",
            )
            .e2e_testing(
                "TWO independent clients. \
                 (1) reqwest_dav + mocked LLM, tests/server/webdav/test.rs: PROPFIND listing \
                 parsed into typed entries through the library's own serde_xml_rs schema, \
                 PUT/GET round-trip, MKCOL, refusal. \
                 (2) the real `curl` binary, tests/server/webdav/real_client_test.rs: \
                 PROPFIND, MKCOL, PUT, GET and COPY in one session. curl is a GENERIC HTTP \
                 client, which the root CLAUDE.md rules out as evidence for a protocol layered \
                 ON HTTP -- but PROPFIND, MKCOL and COPY are not HTTP verbs, 207 is not an \
                 HTTP status, and DAV:multistatus is not an HTTP document, so for the layer \
                 this server actually implements curl is a real WebDAV client. It adds what \
                 reqwest_dav cannot: the multistatus is read as XML rather than deserialised \
                 into a fixed schema, so a body that is not well-formed fails outright; one \
                 entry is named `notes & drafts.txt`, which requires RFC 3986 percent-encoding \
                 in the href and XML escaping in the displayname -- two different rules on the \
                 same string; and COPY's Destination header is echoed back through the model, \
                 so the assertion is that a WebDAV header was parsed rather than that a 201 \
                 came back. \
                 It FAILS rather than skips when curl is absent, and is not #[ignore]d. \
                 Verified non-vacuous by breaking the server twice: dropping xml_escape from \
                 displayname still answered 207 but made the body invalid XML (`Cannot find \
                 ';' after '&'`), and dropping percent_encode_path from the href left a \
                 well-formed document whose href was `/documents/notes & drafts.txt`. \
                 UNPROVEN by either client: PROPPATCH, LOCK/UNLOCK enforcement, Depth: \
                 infinity, binary bodies, authentication and TLS.",
            )
            .notes(
                "There is no storage: a PUT is remembered only if the model chooses to \
                 remember it (server memory), so a GET after a PUT returns whatever the model \
                 says. Text content only - no binary file bodies. OPTIONS, LOCK and UNLOCK are \
                 answered by the server without a model call; locks are never enforced. No \
                 authentication, no TLS, no PROPPATCH dead-property storage.",
            )
            .max_inbound_bytes(crate::server::webdav::MAX_REQUEST_BODY)
            .request_only(
                "WebDAV is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "WebDAV file server with an LLM-supplied virtual filesystem"
    }
    fn example_prompt(&self) -> &'static str {
        "Serve a WebDAV share on port 8080 with a /documents folder containing readme.txt"
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model invents and remembers the filesystem.
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "webdav",
                "instruction": "Serve a WebDAV share whose root contains a 'documents' \
                                collection and a file 'readme.txt' holding 'Hello from \
                                NetGet'. Accept PUT (201 for a new path, 204 for an existing \
                                one) and record what was written in memory so a later GET \
                                returns it."
            }),
            // Script mode: a deterministic read-only share, no model call per request.
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "webdav",
                "event_handlers": [{
                    "event_pattern": "webdav_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import sys, json\n\
                                 e = json.load(sys.stdin)['event']\n\
                                 m, p = e['method'], e['path']\n\
                                 files = {'/readme.txt': 'Hello from NetGet'}\n\
                                 if m == 'PROPFIND' and p in ('/', ''):\n\
                                 \x20   a = [{'type': 'send_webdav_listing', 'path': '/',\n\
                                 \x20         'entries': [{'name': 'readme.txt', 'size': 17,\n\
                                 \x20                      'content_type': 'text/plain'}]}]\n\
                                 elif m in ('GET', 'HEAD') and p in files:\n\
                                 \x20   a = [{'type': 'send_webdav_file', 'content': files[p],\n\
                                 \x20         'content_type': 'text/plain'}]\n\
                                 else:\n\
                                 \x20   a = [{'type': 'send_webdav_status', 'status': 404}]\n\
                                 print(json.dumps({'actions': a}))"
                    }
                }]
            }),
            // Static mode: an empty, read-only share. Every request gets the same refusal.
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "webdav",
                "event_handlers": [{
                    "event_pattern": "webdav_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_webdav_status",
                            "status": 404,
                            "body": "Not Found"
                        }]
                    }
                }]
            }),
        )
    }
}

// ============================================================================
// Server trait
// ============================================================================

impl Server for WebDavProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::webdav::WebDavServer;
            WebDavServer::spawn_with_llm_actions(
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
            "send_webdav_listing" => self.execute_send_webdav_listing(&action),
            "send_webdav_file" => self.execute_send_webdav_file(&action),
            "send_webdav_status" => self.execute_send_webdav_status(&action),
            other => Err(anyhow::anyhow!(
                "Unknown WebDAV action '{}'. WebDAV understands send_webdav_listing, \
                 send_webdav_file and send_webdav_status.",
                other
            )),
        }
    }
}

impl WebDavProtocol {
    /// Build a 207 Multi-Status body from the resource the request named plus, for a
    /// collection, the entries the model listed inside it.
    fn execute_send_webdav_listing(&self, action: &serde_json::Value) -> Result<ActionResult> {
        let raw_path = action
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .trim();
        let is_collection = action
            .get("is_collection")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let now = http_date_now();
        let last_modified = action
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or(&now)
            .to_string();

        let self_href = if is_collection {
            as_collection(raw_path)
        } else {
            absolute(raw_path)
        };

        let mut resources = vec![DavResource {
            name: display_name(&self_href),
            is_collection,
            size: action.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            content_type: action
                .get("content_type")
                .and_then(|v| v.as_str())
                .unwrap_or(if is_collection {
                    "httpd/unix-directory"
                } else {
                    "application/octet-stream"
                })
                .to_string(),
            last_modified: last_modified.clone(),
            href: self_href.clone(),
        }];

        // Entries are optional: a Depth: 0 PROPFIND, or a PROPFIND on a file, lists only the
        // resource itself. An `entries` value that is present but not an array is a model
        // mistake worth reporting rather than ignoring, since ignoring it silently produces a
        // listing that looks empty instead of wrong.
        match action.get("entries") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(items)) => {
                let base = as_collection(&self_href);
                for (i, item) in items.iter().enumerate() {
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim_matches('/'))
                        .filter(|s| !s.is_empty())
                        .with_context(|| {
                            format!(
                                "send_webdav_listing entry #{} has no non-empty 'name'; every \
                                 entry needs the file or folder name it should be listed under",
                                i
                            )
                        })?;
                    let entry_is_collection = item
                        .get("is_collection")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let href = if entry_is_collection {
                        format!("{}{}/", base, name)
                    } else {
                        format!("{}{}", base, name)
                    };
                    resources.push(DavResource {
                        href,
                        name: name.to_string(),
                        is_collection: entry_is_collection,
                        size: item.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                        content_type: item
                            .get("content_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or(if entry_is_collection {
                                "httpd/unix-directory"
                            } else {
                                "application/octet-stream"
                            })
                            .to_string(),
                        last_modified: item
                            .get("last_modified")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&last_modified)
                            .to_string(),
                    });
                }
            }
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "send_webdav_listing 'entries' must be an array of \
                     {{name, is_collection, size, content_type}} objects, got {}",
                    other
                ))
            }
        }

        webdav_output(
            207,
            vec![(
                "Content-Type".to_string(),
                "application/xml; charset=utf-8".to_string(),
            )],
            render_multistatus(&resources),
        )
    }

    /// Return file content for a GET/HEAD.
    fn execute_send_webdav_file(&self, action: &serde_json::Value) -> Result<ActionResult> {
        let content = action
            .get("content")
            .map(as_text)
            .context("send_webdav_file requires 'content' (the file's text content)")?;

        let status = match action.get("status") {
            None | Some(serde_json::Value::Null) => 200,
            Some(v) => parse_status(v).with_context(|| {
                format!(
                    "send_webdav_file 'status' {} is not an HTTP status code between 100 and 599",
                    v
                )
            })?,
        };

        let content_type = action
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("text/plain; charset=utf-8")
            .to_string();

        webdav_output(
            status,
            vec![("Content-Type".to_string(), content_type)],
            content,
        )
    }

    /// Answer with a bare status: the result of a write, or a refusal.
    fn execute_send_webdav_status(&self, action: &serde_json::Value) -> Result<ActionResult> {
        let status_value = action
            .get("status")
            .context("send_webdav_status requires 'status' (e.g. 201 for a created resource)")?;
        let status = parse_status(status_value).with_context(|| {
            format!(
                "send_webdav_status 'status' {} is not an HTTP status code between 100 and 599",
                status_value
            )
        })?;

        let body = action.get("body").map(as_text).unwrap_or_default();

        let headers = action
            .get("headers")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k.clone(), as_text(v)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        webdav_output(status, headers, body)
    }
}

// ============================================================================
// Action definitions
// ============================================================================

fn send_webdav_listing_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_webdav_listing".to_string(),
        description:
            "Answer a PROPFIND with a 207 Multi-Status listing. This is the ONLY way to make a \
             directory or a file's properties visible to a WebDAV client. The response always \
             describes the resource named by 'path' itself, plus one entry per element of \
             'entries' (which you omit for Depth: 0, or when the path is a file). There is no \
             filesystem behind this server: whatever you list here IS the directory, so keep it \
             consistent with what you have listed before and with any PUT you accepted. The \
             DAV:multistatus XML is generated for you - never write XML into these fields."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "The path being listed. Echo the 'path' field of the webdav_request \
                    event exactly; the client matches the href in the reply against the URL it \
                    requested, so a different path makes the listing useless to it."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "entries".to_string(),
                type_hint: "array".to_string(),
                description: "The members of this collection, as an array of objects. Each: \
                    'name' (required, a single file or folder name, no slashes), 'is_collection' \
                    (boolean, default false), 'size' (number, byte length of the file's content, \
                    default 0), 'content_type' (string, e.g. \"text/plain\"), 'last_modified' \
                    (RFC 1123 date string, defaults to now). Omit or use [] when the request had \
                    Depth: 0 or when 'path' is a file."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "is_collection".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether 'path' itself is a collection (directory). Default true. \
                    Set false when answering a PROPFIND on a single file."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "size".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Byte length of the resource at 'path' when it is a file (is_collection false)."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "MIME type of the resource at 'path'. Defaults to \
                    httpd/unix-directory for a collection, application/octet-stream for a file."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "last_modified".to_string(),
                type_hint: "string".to_string(),
                description: "RFC 1123 date, e.g. \"Wed, 10 Apr 2024 14:00:00 GMT\". Defaults to \
                    the current time, and is inherited by entries that do not set their own."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_webdav_listing",
            "path": "/",
            "entries": [
                { "name": "documents", "is_collection": true },
                { "name": "readme.txt", "size": 17, "content_type": "text/plain" }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> 207 {path} ({output_bytes}B)")
                .with_debug("WebDAV multistatus for {path}")
                .with_trace("WebDAV listing: {json_pretty(.)}"),
        ),
    }
}

fn send_webdav_file_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_webdav_file".to_string(),
        description:
            "Return the content of a file for a GET or HEAD request. The body is sent as UTF-8 \
             text in one piece; binary files (images, archives) cannot be produced, and there is \
             no way to stream or resume. If the path should not exist, use send_webdav_status \
             with 404 instead of returning empty content."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "The file's full content as text. Must be consistent with the size \
                    you reported for this path in any send_webdav_listing."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "MIME type sent as Content-Type. Default \"text/plain; charset=utf-8\"."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status, default 200. Use 206 only if you really are answering \
                    a Range request with a partial body."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_webdav_file",
            "content": "Hello from NetGet",
            "content_type": "text/plain"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {status} file ({output_bytes}B)")
                .with_debug("WebDAV file body: {output_bytes}B, type={content_type}")
                .with_trace("WebDAV file: {json_pretty(.)}"),
        ),
    }
}

fn send_webdav_status_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_webdav_status".to_string(),
        description:
            "Answer with a status code and no file body. This is how every write is accepted or \
             refused - PUT, DELETE, MKCOL, COPY, MOVE, PROPPATCH - and how a missing path is \
             reported. RFC 4918 statuses worth knowing: 201 Created (PUT that created a new \
             resource, successful MKCOL), 204 No Content (PUT that overwrote an existing one, \
             successful DELETE/MOVE/COPY over an existing target), 403 Forbidden (read-only \
             share), 404 Not Found, 405 Method Not Allowed (MKCOL on a path that already \
             exists), 409 Conflict (parent collection does not exist), 412 Precondition Failed \
             (Overwrite: F and the destination exists), 507 Insufficient Storage. Refusing is \
             always a valid answer; saying nothing at all is not, and produces a 503."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code between 100 and 599.".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Optional explanatory text. Leave it out for 201/204, which must \
                    have no body."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional response headers as a flat name->value object, e.g. \
                    {\"Location\": \"/moved/here.txt\"}. Content-Length and Date are added \
                    automatically; headers that are not legal HTTP are dropped."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_webdav_status",
            "status": 201
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {status}")
                .with_debug("WebDAV status {status}")
                .with_trace("WebDAV status: {json_pretty(.)}"),
        ),
    }
}

pub static SEND_WEBDAV_LISTING_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_webdav_listing_action);
pub static SEND_WEBDAV_FILE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_webdav_file_action);
pub static SEND_WEBDAV_STATUS_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_webdav_status_action);

// ============================================================================
// Event type
// ============================================================================

/// Emitted once per WebDAV request that the model is allowed to answer.
///
/// OPTIONS, LOCK and UNLOCK do not raise it: those are protocol handshakes with no content to
/// decide, and are answered by the server itself (see `mod.rs`). Everything else does —
/// GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, POST.
pub static WEBDAV_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webdav_request",
        "WebDAV request received (PROPFIND, GET, PUT, MKCOL, DELETE, COPY, MOVE, PROPPATCH)",
        json!({
            "type": "send_webdav_listing",
            "path": "/",
            "entries": [
                { "name": "documents", "is_collection": true },
                { "name": "readme.txt", "size": 17, "content_type": "text/plain" }
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "WebDAV/HTTP method: PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, COPY, \
                MOVE, PROPPATCH or POST."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Requested path, percent-decoded, without query string (e.g. \
                '/documents/readme.txt'). Echo this back in send_webdav_listing."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "depth".to_string(),
            type_hint: "string".to_string(),
            description: "Depth header for PROPFIND/COPY/MOVE: \"0\" (this resource only), \
                \"1\" (this resource and its immediate members) or \"infinity\". Present only \
                when the client sent it; PROPFIND without it means infinity."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Target path of a COPY or MOVE, taken from the Destination header and \
                reduced to a path."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "overwrite".to_string(),
            type_hint: "string".to_string(),
            description: "Overwrite header of a COPY/MOVE: \"T\" (replace the destination) or \
                \"F\" (fail with 412 if it exists)."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "All request headers as a name->value object.".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Request body as UTF-8 text: the file content on a PUT, the XML \
                <propfind>/<propertyupdate> document on PROPFIND/PROPPATCH. Empty string when \
                there is no body. Lossy when body_is_binary is true."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "body_bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the request body in bytes before UTF-8 decoding.".to_string(),
            required: false,
        },
        Parameter {
            name: "body_is_binary".to_string(),
            type_hint: "boolean".to_string(),
            description: "Present and true when the body is not valid UTF-8, meaning 'body' is a \
                lossy rendering and the exact bytes are not available to you."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_WEBDAV_LISTING_ACTION.clone(),
        SEND_WEBDAV_FILE_ACTION.clone(),
        SEND_WEBDAV_STATUS_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_webdav_file",
        "content": "Hello from NetGet",
        "content_type": "text/plain"
    }))
    .with_alternative_example(json!({
        "type": "send_webdav_status",
        "status": 201
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} {method} {path} -> {status} ({duration_ms}ms)")
            .with_debug("WebDAV {method} {path} depth={depth} from {client_ip}")
            .with_trace("WebDAV request: {json_pretty(.)}"),
    )
});
