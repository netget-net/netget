//! `curl` — the **second** independent client for the WebDAV server.
//!
//! The rest of this directory drives `reqwest_dav`. That is a genuine third-party
//! implementation, but it is **one** implementation, and a rating resting on one client is a
//! rating resting on that client's leniency. Three times in this repository a second, stricter
//! peer showed that no conformant implementation could complete a call at all — `etcd` and
//! `grpc` emitted no gRPC trailers, `mysql` offered an auth plugin MySQL 9.0 had deleted — and
//! in all three the *error* path was accidentally correct and the tests asserted on it.
//!
//! # Why curl counts here, when the root `CLAUDE.md` rules out generic HTTP clients
//!
//! That rule rules out a generic HTTP client as evidence for a protocol layered *on* HTTP —
//! `reqwest` proves an HTTP server answers, not that the protocol above it is right. The
//! qualification is that **`PROPFIND`, `MKCOL` and `COPY` are not HTTP verbs**. They are
//! defined by RFC 4918 and by nothing else; a `207 Multi-Status` is a WebDAV status; the
//! `Destination` and `Depth` headers are WebDAV headers; and a `DAV:multistatus` body is a
//! WebDAV document. curl issuing those is a WebDAV client for the layer that matters, and it
//! is what an operator reaches for when they want to see the bytes.
//!
//! What curl adds over `reqwest_dav`, concretely:
//!
//! - **The multistatus body is read as XML, not as a struct.** `reqwest_dav` deserialises into
//!   its own schema, so it sees the fields it knows about and quietly tolerates the rest. Here
//!   the body is parsed with `quick-xml`, and a body that is **not well-formed XML at all**
//!   fails — which is exactly what an under-escaped `displayname` produces, and a deserialiser
//!   fed the same bytes would fail with a vaguer error much later, if at all.
//! - **`href` percent-encoding against `displayname` XML-escaping.** One entry here is named
//!   `notes & drafts.txt`. RFC 3986 says the `href` must carry `%20` and `%26`; XML says the
//!   `displayname` must carry `&amp;` and be read back as a literal `&`. The two rules pull in
//!   opposite directions on the same string and the server has to apply each in its own place.
//! - **Verbs `reqwest_dav`'s API never issues here.** `COPY` with a `Destination` header is
//!   driven, and the model echoes the destination it was given back into the response body, so
//!   the assertion is that the header reached the model rather than that a 201 came back.
//!
//! # Non-vacuity: what was broken, and what curl's body then showed
//!
//! Verified by breaking the server and re-reading what curl received.
//!
//! 1. **`displayname` stopped being XML-escaped** (`DavResource::render` in
//!    `src/server/webdav/actions.rs`: `xml_escape(&self.name)` → `&self.name`). curl still got
//!    `207` and a body that *looked* fine to the eye, but the bare `&` makes it invalid XML.
//!    The parse failed with
//!    `Error while escaping character at range 6..18: Cannot find ';' after '&'`
//!    and the test failed there rather than on any assertion. A status-code check would have
//!    passed, and so would a `body.contains("<D:href>")` check.
//! 2. **`href` stopped being percent-encoded** (`percent_encode_path(&self.href)` →
//!    `self.href`). The document stayed well-formed, so nothing failed to parse; the href came
//!    back as `/documents/notes & drafts.txt` and the test failed naming the expected
//!    `/documents/notes%20%26%20drafts.txt`.
//!
//! Both were reverted; `git diff src/server/webdav/` is empty.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features webdav \
//!       --test server -- server::webdav::real_client --test-threads=8

use crate::helpers::{self, E2EResult, NetGetConfig};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// The entry whose name forces percent-encoding and XML-escaping to disagree.
const AWKWARD_NAME: &str = "notes & drafts.txt";
/// What RFC 3986 requires of that name inside a `<D:href>`.
const AWKWARD_HREF: &str = "/documents/notes%20%26%20drafts.txt";
/// The file body the model serves for GET, and the bytes curl must print back.
const FILE_BODY: &str = "the quarterly figures are in the other folder\n";

/// Fail — never skip — unless a usable `curl` exists, and say which one it is.
///
/// A `println!("SKIP: curl is not installed")` and `Ok(())` is a silent pass on every runner
/// without it, and a maturity rating resting on a test like that rests on nothing wherever the
/// suite actually runs (`tests/server/npm/e2e_test.rs` states the same rule in its own words).
async fn require_curl() -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new("curl")
            .arg("--version")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "`curl --version` did not finish within 30s")?;

    match out {
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("curl (version unknown)")
            .trim()
            .to_string()),
        Ok(out) => Err(format!(
            "`curl --version` exited {}: this test's whole point is driving the real curl \
             binary against NetGet's WebDAV server",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "curl is not available ({e}): this test drives the real `curl` binary through \
             PROPFIND/MKCOL/PUT/GET/COPY, which is the SECOND independent client the WebDAV \
             server's Beta rating rests on, and skipping it would leave that rating resting on \
             `reqwest_dav` alone. Install it with `brew install curl` / \
             `apt-get install -y curl`."
        )
        .into()),
    }
}

/// One HTTP exchange as curl reported it.
struct CurlResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl CurlResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Run curl with `-i` and split the response into status line, headers and body.
///
/// `tokio::process::Command`, not `std::process`: `#[tokio::test]` runs a current-thread
/// runtime, and a blocking `output()` parks the only worker — which is also the task draining
/// the netget child's stdout and stderr. The pipes fill, netget blocks inside a log call while
/// it is serving this very request, and curl times out against a server that is behaving
/// perfectly. The symptom looks exactly like a protocol bug.
async fn curl(args: &[&str], what: &str) -> E2EResult<CurlResponse> {
    let out = timeout(
        Duration::from_secs(60),
        Command::new("curl")
            // -s quiet, -S still report errors, -i include the response headers on stdout,
            // --http1.1 because that is all the server speaks, `Expect:` to suppress the
            // 100-continue curl would otherwise negotiate for a body (which would put a
            // second header block on stdout and make the split below wrong).
            .args(["-sS", "-i", "--http1.1"])
            .args(["-H", "Expect:"])
            .args(["--max-time", "45"])
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("curl {what} did not finish within 60s"))??;

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(format!(
            "curl {what} exited {} — it could not complete the request.\nstderr:\n{stderr}",
            out.status
        )
        .into());
    }

    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("curl {what} produced no header/body boundary:\n{raw}"))?;

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("curl {what} produced an empty response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("curl {what}: unparseable status line {status_line:?}"))?;

    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    Ok(CurlResponse {
        status,
        headers,
        body: body.to_string(),
    })
}

/// One `<D:response>` element, as read back out of the XML curl received.
#[derive(Debug, Default, PartialEq)]
struct DavResponse {
    href: String,
    displayname: String,
    is_collection: bool,
    contentlength: Option<String>,
    contenttype: String,
    getlastmodified: String,
    status: String,
}

/// Parse a `DAV:multistatus` body into its responses.
///
/// A real XML parse, not a substring match. Two things follow from that and both are the point:
/// a body that is not well-formed fails here rather than passing a `body.contains("<D:href>")`
/// check, and every text value comes back **unescaped**, so `notes &amp; drafts.txt` is
/// compared against the literal `notes & drafts.txt` the model actually wrote.
///
/// Element names are matched on the *local* name, so the server's choice of `D:` as the `DAV:`
/// prefix is not baked into the assertions.
fn parse_multistatus(xml: &str) -> E2EResult<Vec<DavResponse>> {
    /// Report an XML failure on stdout as well as through the error.
    ///
    /// Returning `Err` from the test drops the mock config with expectations still unmet, and
    /// that guard panics with a message of its own ("expected exactly 5, got 1") — which
    /// would otherwise be the only thing a reader sees. The diagnosis has to be printed to
    /// survive.
    fn ill_formed(detail: &str, xml: &str) -> Box<dyn std::error::Error + Send + Sync> {
        let msg = format!(
            "the multistatus body curl received is not well-formed XML: {detail}\nbody:\n{xml}"
        );
        println!("  !! {msg}");
        msg.into()
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut out: Vec<DavResponse> = Vec::new();
    let mut current: Option<DavResponse> = None;
    // The element whose text we are collecting, by local name.
    let mut field: Option<String> = None;
    let mut saw_multistatus = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local.as_str() {
                    "multistatus" => saw_multistatus = true,
                    "response" => current = Some(DavResponse::default()),
                    other => field = Some(other.to_string()),
                }
            }
            Ok(Event::Empty(ref e)) => {
                // `<D:collection/>` is the only thing that makes a resource a collection, and
                // it is an empty element, so it never produces a Start/Text pair.
                if e.local_name().as_ref() == b"collection" {
                    if let Some(c) = current.as_mut() {
                        c.is_collection = true;
                    }
                }
            }
            Ok(Event::Text(e)) => {
                // `unescape` is where a bare `&` in a `displayname` is caught: the reader
                // itself is happy to hand back the raw text, and only resolving the entity
                // reference discovers there is no entity there.
                let text = match e.unescape() {
                    Ok(t) => t.to_string(),
                    Err(err) => return Err(ill_formed(&err.to_string(), xml)),
                };
                if let (Some(c), Some(f)) = (current.as_mut(), field.as_ref()) {
                    match f.as_str() {
                        "href" => c.href = text,
                        "displayname" => c.displayname = text,
                        "getcontentlength" => c.contentlength = Some(text),
                        "getcontenttype" => c.contenttype = text,
                        "getlastmodified" => c.getlastmodified = text,
                        "status" => c.status = text,
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                if e.local_name().as_ref() == b"response" {
                    if let Some(c) = current.take() {
                        out.push(c);
                    }
                }
                field = None;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(ill_formed(&e.to_string(), xml)),
            _ => {}
        }
        buf.clear();
    }

    if !saw_multistatus {
        return Err(ill_formed("no DAV:multistatus element", xml));
    }
    Ok(out)
}

/// One netget server; five curl invocations covering four WebDAV-only verbs plus GET.
///
/// LLM calls: 1 startup + PROPFIND + MKCOL + PUT + GET + COPY = **6**.
#[tokio::test]
async fn curl_completes_a_webdav_session_against_the_webdav_server() -> E2EResult<()> {
    let version = require_curl().await?;
    println!("\n=== E2E: real curl client ({version}) against the WebDAV server ===");

    let prompt = "listen on port {AVAILABLE_PORT} using webdav stack. Serve a /documents \
         collection; answer writes with 201 Created.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // ONE rule branching on the method. Five rules on `webdav_request` would be
            // first-match-wins: the first would answer every request and the other four would
            // report zero calls.
            .on_event("webdav_request")
            .respond_with_actions_from_event(|event| {
                let method = event
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                let path = event
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                match method.as_str() {
                    "PROPFIND" => serde_json::json!([{
                        "type": "send_webdav_listing",
                        "path": path,
                        "is_collection": true,
                        "entries": [
                            {"name": "readme.txt", "size": 42,
                             "content_type": "text/plain; charset=utf-8"},
                            {"name": "images", "is_collection": true},
                            // The name that makes percent-encoding and XML-escaping disagree.
                            {"name": AWKWARD_NAME, "size": 128,
                             "content_type": "text/plain; charset=utf-8"}
                        ]
                    }]),
                    "MKCOL" => serde_json::json!([{
                        "type": "send_webdav_status",
                        "status": 201,
                        "headers": {"Location": path}
                    }]),
                    "PUT" => serde_json::json!([{
                        "type": "send_webdav_status",
                        "status": 201,
                        "headers": {"ETag": "\"put-1\""}
                    }]),
                    "GET" => serde_json::json!([{
                        "type": "send_webdav_file",
                        "content": FILE_BODY,
                        "content_type": "text/plain; charset=utf-8"
                    }]),
                    // The Destination header is WebDAV's, not HTTP's. Echoing it back into the
                    // body is what turns "a 201 came back" into "the header reached the model".
                    "COPY" => serde_json::json!([{
                        "type": "send_webdav_status",
                        "status": 201,
                        "body": format!(
                            "copied {} to {}",
                            path,
                            event.get("destination").and_then(|v| v.as_str()).unwrap_or("<none>")
                        )
                    }]),
                    // Anything else fails loudly on the client side rather than hanging it.
                    other => serde_json::json!([{
                        "type": "send_webdav_status",
                        "status": 400,
                        "body": format!("unexpected method {other} in this test")
                    }]),
                }
            })
            .expect_calls(5)
            .and()
            .on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Serve /documents; answer writes with 201 Created"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let base = format!("http://127.0.0.1:{}", server.port);
    println!("  WebDAV server at {base}");

    // ---- PROPFIND: the verb that is WebDAV and not HTTP ----
    let propfind_body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#;
    let url = format!("{base}/documents/");
    let res = curl(
        &[
            "-X",
            "PROPFIND",
            "-H",
            "Depth: 1",
            "-H",
            "Content-Type: application/xml; charset=utf-8",
            "--data-binary",
            propfind_body,
            &url,
        ],
        "PROPFIND",
    )
    .await?;
    println!("  PROPFIND -> {}\n{}", res.status, res.body);

    assert_eq!(
        res.status, 207,
        "RFC 4918 §9.1: PROPFIND answers 207 Multi-Status. curl got {} with body:\n{}",
        res.status, res.body
    );
    assert!(
        res.header("Content-Type")
            .unwrap_or_default()
            .starts_with("application/xml"),
        "the multistatus was not served as XML: {:?}",
        res.header("Content-Type")
    );

    let responses = parse_multistatus(&res.body)?;
    assert_eq!(
        responses.len(),
        4,
        "expected the collection itself plus three entries, got {responses:#?}"
    );

    // The collection itself, first, with a trailing slash and a DAV:collection resourcetype.
    assert_eq!(responses[0].href, "/documents/");
    assert!(
        responses[0].is_collection,
        "the collection's own response is not a DAV:collection: {:#?}",
        responses[0]
    );
    assert_eq!(
        responses[0].contentlength, None,
        "a collection must not carry getcontentlength"
    );

    let find = |name: &str| -> &DavResponse {
        responses
            .iter()
            .find(|r| r.displayname == name)
            .unwrap_or_else(|| {
                panic!(
                    "no response with displayname {name:?}. curl received:\n{:#?}",
                    responses
                )
            })
    };

    let readme = find("readme.txt");
    assert_eq!(readme.href, "/documents/readme.txt");
    assert!(!readme.is_collection);
    assert_eq!(readme.contentlength.as_deref(), Some("42"));
    assert_eq!(readme.contenttype, "text/plain; charset=utf-8");
    assert!(
        readme.getlastmodified.ends_with(" GMT"),
        "getlastmodified is not an RFC 1123 date: {:?}",
        readme.getlastmodified
    );
    assert_eq!(readme.status, "HTTP/1.1 200 OK");

    let images = find("images");
    assert_eq!(
        images.href, "/documents/images/",
        "a nested collection's href must end in a slash"
    );
    assert!(images.is_collection);
    assert_eq!(images.contentlength, None);

    // The whole reason this entry exists. `displayname` came back through `Event::unescape`,
    // so the literal `&` here proves the server wrote `&amp;`; the href proves it wrote the
    // RFC 3986 escapes, which are a different rule applied to the same string.
    let awkward = find(AWKWARD_NAME);
    assert_eq!(
        awkward.href, AWKWARD_HREF,
        "the href is not percent-encoded. RFC 3986 requires %20 for the spaces and %26 for the \
         ampersand; a client that resolved this href verbatim would request a different URL."
    );
    assert_eq!(awkward.contentlength.as_deref(), Some("128"));

    // ---- MKCOL: a WebDAV verb with no HTTP equivalent ----
    let url = format!("{base}/documents/reports/");
    let res = curl(&["-X", "MKCOL", &url], "MKCOL").await?;
    println!("  MKCOL -> {}", res.status);
    assert_eq!(
        res.status, 201,
        "MKCOL did not answer 201 Created.\nbody:\n{}",
        res.body
    );
    assert_eq!(
        res.header("Location"),
        Some("/documents/reports/"),
        "the Location header the model chose did not reach curl"
    );

    // ---- PUT ----
    let url = format!("{base}/documents/notes.txt");
    let res = curl(
        &[
            "-X",
            "PUT",
            "-H",
            "Content-Type: text/plain",
            "--data-binary",
            FILE_BODY,
            &url,
        ],
        "PUT",
    )
    .await?;
    println!("  PUT -> {}", res.status);
    assert_eq!(
        res.status, 201,
        "PUT did not answer 201.\nbody:\n{}",
        res.body
    );
    assert_eq!(
        res.header("ETag"),
        Some("\"put-1\""),
        "the ETag the model chose did not reach curl"
    );

    // ---- GET: the bytes, exactly ----
    let res = curl(&[&url], "GET").await?;
    println!("  GET -> {} body={:?}", res.status, res.body);
    assert_eq!(res.status, 200);
    assert_eq!(
        res.body, FILE_BODY,
        "curl did not read back the file body the model wrote"
    );
    assert_eq!(
        res.header("Content-Length"),
        Some(FILE_BODY.len().to_string().as_str()),
        "Content-Length disagrees with the body curl received — which is the one header a \
         client uses to decide how much to read"
    );

    // ---- COPY: the Destination header, read back through the model ----
    let dest = format!("{base}/documents/notes-copy.txt");
    let res = curl(
        &[
            "-X",
            "COPY",
            "-H",
            &format!("Destination: {dest}"),
            "-H",
            "Overwrite: F",
            &url,
        ],
        "COPY",
    )
    .await?;
    println!("  COPY -> {} body={:?}", res.status, res.body);
    assert_eq!(
        res.status, 201,
        "COPY did not answer 201.\nbody:\n{}",
        res.body
    );
    // curl sent `Destination: http://127.0.0.1:<port>/documents/notes-copy.txt` — RFC 4918
    // §10.3 makes Destination an absolute URI — and the server resolves it against itself
    // before handing the model a path. So what proves the header was parsed rather than
    // ignored is that the model was given the *path*, which appears nowhere in the request
    // line: the request line named `/documents/notes.txt`.
    assert_eq!(
        res.body, "copied /documents/notes.txt to /documents/notes-copy.txt",
        "the Destination header curl sent did not reach the model as a resolved path — the \
         body it echoed is what proves the server parsed a WebDAV header rather than ignoring \
         it. curl sent Destination: {dest}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ curl completed a real WebDAV session\n");
    Ok(())
}
