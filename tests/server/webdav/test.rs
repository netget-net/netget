//! End-to-end WebDAV tests for NetGet.
//!
//! Driven by `reqwest_dav`, a real WebDAV client library: PROPFIND bodies are parsed with the
//! same `serde_xml_rs` schema a production client uses, so a malformed multistatus, a missing
//! `getlastmodified`, or an href that does not match the requested URL all fail here rather
//! than passing a "the status was 207" check.
//!
//! The point of every test is that **the model decides**. There is no filesystem behind this
//! server, so a listing that appears, a file that reads back, and a write that is refused are
//! each traceable to a specific mocked model answer. The PUT/GET test proves it directly: the
//! bytes the client GETs are the bytes the *mock* captured off the PUT event, so if the request
//! body never reached the model the round-trip fails.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use reqwest_dav::list_cmd::{ListEntity, ListMultiStatus};
use reqwest_dav::re_exports::serde_xml_rs;
use reqwest_dav::{Auth, ClientBuilder, Depth};
use std::sync::{Arc, Mutex};

fn dav_client(port: u16) -> E2EResult<reqwest_dav::Client> {
    Ok(ClientBuilder::new()
        .set_host(format!("http://127.0.0.1:{}", port))
        .set_auth(Auth::Anonymous)
        .build()?)
}

/// PROPFIND: the model supplies the directory, the server renders the multistatus, and a real
/// client parses it back into typed entries.
///
/// LLM calls: 2 (startup + one PROPFIND).
#[tokio::test]
async fn test_webdav_propfind_listing() -> E2EResult<()> {
    println!("\n=== E2E Test: WebDAV PROPFIND listing ===");

    let prompt = "listen on port {AVAILABLE_PORT} using webdav stack. The share root holds a \
                  documents folder and a readme.txt";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Event rules first: they are the specific ones.
            .on_event("webdav_request")
            .and_event_data_contains("method", "PROPFIND")
            // Depth is read off the request header, so a missing/garbled depth fails to match
            // and the request 500s instead of quietly listing the wrong thing.
            .and_event_data_contains("depth", "1")
            .respond_with_actions_from_event(|event_data| {
                // Echo the path back, exactly as a model is instructed to.
                let path = event_data["path"].as_str().unwrap_or("").to_string();
                serde_json::json!([{
                    "type": "send_webdav_listing",
                    "path": path,
                    "entries": [
                        { "name": "documents", "is_collection": true },
                        { "name": "readme.txt", "size": 17, "content_type": "text/plain" }
                    ]
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Serve a share with documents/ and readme.txt"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("WebDAV server started on port {}", server.port);
    assert_eq!(
        server.stack, "WebDAV",
        "Expected a WebDAV server, got {}",
        server.stack
    );

    let dav = dav_client(server.port)?;
    let response = dav.list_raw("/", Depth::Number(1)).await?;

    assert_eq!(
        response.status().as_u16(),
        207,
        "RFC 4918 §9.1: PROPFIND answers 207 Multi-Status"
    );
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.contains("xml"),
        "a multistatus body must be XML, got content-type {content_type:?}"
    );
    let dav_header = response
        .headers()
        .get("dav")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        dav_header.contains('1'),
        "RFC 4918 §10.1: a DAV-compliant response advertises its compliance class, got {dav_header:?}"
    );

    let body = response.text().await?;
    println!("PROPFIND body:\n{body}");

    // Parsed with the client library's own schema: this fails on malformed XML, on a
    // <D:response> without a propstat, and on a file entry whose getlastmodified is missing or
    // not an HTTP date.
    let parsed: ListMultiStatus = serde_xml_rs::from_str(&body)?;
    assert_eq!(
        parsed.responses.len(),
        3,
        "Depth: 1 must list the collection itself plus its two members; body was:\n{body}"
    );

    let entities = parsed
        .responses
        .into_iter()
        .map(ListEntity::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    match &entities[0] {
        ListEntity::Folder(folder) => assert_eq!(
            folder.href, "/",
            "the first response must be the collection that was asked for"
        ),
        other => panic!("root must be listed as a collection, got {other:?}"),
    }
    match &entities[1] {
        ListEntity::Folder(folder) => assert_eq!(
            folder.href, "/documents/",
            "a member marked is_collection must get a collection href ending in /"
        ),
        other => panic!("documents must be listed as a collection, got {other:?}"),
    }
    match &entities[2] {
        ListEntity::File(file) => {
            assert_eq!(file.href, "/readme.txt");
            assert_eq!(
                file.content_length, 17,
                "the size the model reported must survive into getcontentlength"
            );
            assert_eq!(file.content_type, "text/plain");
        }
        other => panic!("readme.txt must be listed as a file, got {other:?}"),
    }

    println!("✓ PROPFIND listing round-tripped through a real WebDAV client");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// PUT then GET: the content the client reads back is the content the model was handed on the
/// PUT, which is the whole claim of a storage-free WebDAV server.
///
/// LLM calls: 3 (startup + PUT + GET).
#[tokio::test]
async fn test_webdav_put_then_get_round_trip() -> E2EResult<()> {
    println!("\n=== E2E Test: WebDAV PUT then GET ===");

    // The mock plays the part of a model using server memory: it remembers what the PUT
    // carried and serves it back on the GET. If the request body never reaches the model, the
    // GET returns the sentinel and the assertion below fails.
    let stored: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stored_on_put = stored.clone();
    let stored_on_get = stored.clone();

    let prompt = "listen on port {AVAILABLE_PORT} using webdav stack. Accept uploads and serve \
                  them back";

    let config = NetGetConfig::new(prompt).with_mock(move |mock| {
        mock.on_event("webdav_request")
            .and_event_data_contains("method", "PUT")
            .and_event_data_contains("path", "/notes.txt")
            .respond_with_actions_from_event(move |event_data| {
                let body = event_data["body"].as_str().unwrap_or("").to_string();
                *stored_on_put.lock().unwrap() = Some(body);
                serde_json::json!([{ "type": "send_webdav_status", "status": 201 }])
            })
            .expect_calls(1)
            .and()
            .on_event("webdav_request")
            .and_event_data_contains("method", "GET")
            .and_event_data_contains("path", "/notes.txt")
            .respond_with_actions_from_event(move |_| {
                let content = stored_on_get
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "<the PUT body never reached the model>".to_string());
                serde_json::json!([{
                    "type": "send_webdav_file",
                    "content": content,
                    "content_type": "text/plain"
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Remember uploaded files and serve them back"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("WebDAV server started on port {}", server.port);

    let dav = dav_client(server.port)?;

    let put = dav.put_raw("/notes.txt", "Hello WebDAV!").await?;
    assert_eq!(
        put.status().as_u16(),
        201,
        "RFC 4918 §9.7.1: creating a new resource answers 201 Created — and 201 here is the \
         model's decision, not the server's"
    );

    let fetched = dav.get_raw("/notes.txt").await?;
    assert_eq!(fetched.status().as_u16(), 200, "the file must be GETtable");
    let fetched_type = fetched
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        fetched_type.contains("text/plain"),
        "the model's content_type must reach the wire, got {fetched_type:?}"
    );
    assert_eq!(
        fetched.text().await?,
        "Hello WebDAV!",
        "GET must return the bytes the model saw on the PUT"
    );

    println!("✓ PUT body reached the model and came back through GET");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// The three ways a WebDAV request ends that are not "here is your file": an accepted write, a
/// refused one, and a model that never answers at all.
///
/// Also asserts that OPTIONS costs **no** model call — it is answered by the server. If it did
/// reach the LLM, no mock rule would match it, the mock would return HTTP 500, and
/// `verify_mocks` would report the unexpected call.
///
/// LLM calls: 4 (startup + MKCOL + DELETE + GET). OPTIONS: 0.
#[tokio::test]
async fn test_webdav_write_statuses_refusal_and_options() -> E2EResult<()> {
    println!("\n=== E2E Test: WebDAV write statuses, refusal, OPTIONS ===");

    let prompt = "listen on port {AVAILABLE_PORT} using webdav stack. Allow new folders but \
                  refuse deletions";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("webdav_request")
            .and_event_data_contains("method", "MKCOL")
            .respond_with_actions(serde_json::json!([{
                "type": "send_webdav_status",
                "status": 201
            }]))
            .expect_calls(1)
            .and()
            .on_event("webdav_request")
            .and_event_data_contains("method", "DELETE")
            .respond_with_actions(serde_json::json!([{
                "type": "send_webdav_status",
                "status": 403,
                "body": "this share is read-only"
            }]))
            .expect_calls(1)
            .and()
            // A model that answers, but with nothing that produces a WebDAV response. The
            // server must refuse (503), not invent a permissive default.
            .on_event("webdav_request")
            .and_event_data_contains("method", "GET")
            .respond_with_actions(serde_json::json!([{
                "type": "show_message",
                "message": "thinking about it"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("webdav")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "WebDAV",
                "instruction": "Allow MKCOL, refuse DELETE"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("WebDAV server started on port {}", server.port);

    let dav = dav_client(server.port)?;

    let mkcol = dav.mkcol_raw("/newdir/").await?;
    assert_eq!(
        mkcol.status().as_u16(),
        201,
        "RFC 4918 §9.3.1: a successful MKCOL answers 201 Created"
    );

    let deleted = dav.delete_raw("/newdir/").await?;
    assert_eq!(
        deleted.status().as_u16(),
        403,
        "the model refused the delete, and its refusal must reach the client verbatim"
    );
    assert!(
        deleted.text().await?.contains("read-only"),
        "the model's explanation must reach the client"
    );

    // No usable action -> 503, distinct from any status the model can pick, so "it refused"
    // and "it never answered" are never confused.
    let unanswered = dav.get_raw("/anything.txt").await?;
    assert_eq!(
        unanswered.status().as_u16(),
        503,
        "a model answer with no send_webdav_* action must fail closed with 503, never a \
         permissive default"
    );

    // OPTIONS is a handshake, answered by the server itself.
    let http = reqwest::Client::new();
    let options = http
        .request(
            reqwest::Method::OPTIONS,
            format!("http://127.0.0.1:{}/", server.port),
        )
        .send()
        .await?;
    assert_eq!(options.status().as_u16(), 200, "OPTIONS must answer 200");
    let allow = options
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    for method in ["PROPFIND", "MKCOL", "PUT", "LOCK"] {
        assert!(
            allow.contains(method),
            "OPTIONS must advertise {method} in Allow, got {allow:?}"
        );
    }

    println!("✓ write statuses, refusal, fail-closed 503 and LLM-free OPTIONS all verified");

    // Passes only if OPTIONS made no LLM call: every rule's expect_calls(1) is exact.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}
