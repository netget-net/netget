//! End-to-end tests for the OCI Distribution v2 registry server.
//!
//! Three tests, deliberately front-loaded so one server covers many endpoints:
//!
//! | Test | LLM calls | What it proves |
//! |---|---|---|
//! | `test_oci_registry_pull_path` | 9 | the whole pull path, with digests re-verified against an external `shasum` |
//! | `test_oci_registry_refuses_mismatched_content` | 4 | fail-closed on a digest mismatch; 401 challenge; NAME_UNKNOWN |
//! | `test_oci_registry_against_crane` | 1 | a real, independent OCI client accepts what we serve |
//!
//! Every assertion is protocol-level: decoded manifest JSON, descriptor digests,
//! `Docker-Content-Digest`, media types and error envelopes. Nothing asserts merely
//! that a connection opened.
//!
//! All traffic is to 127.0.0.1. No external registry is ever contacted.


use super::digest_test::{CONFIG_DIGEST, CONFIG_JSON, LAYER_DIGEST, LAYER_TEXT};
use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

const REPO: &str = "library/alpine";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The manifest the model "invents", carrying **deliberately wrong** digests and
/// sizes. The server must overwrite them from the supplied blob content; if it did
/// not, `crane` and every other real client would reject the image.
fn invented_manifest() -> Value {
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 1
        },
        "layers": [{
            "mediaType": LAYER_MEDIA_TYPE,
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "size": 1
        }],
        "annotations": {"org.opencontainers.image.title": "netget-invented"}
    })
}

fn manifest_action() -> Value {
    json!([{
        "type": "send_oci_manifest",
        "manifest": invented_manifest(),
        "blobs": [
            {"role": "config", "content": CONFIG_JSON, "encoding": "utf8",
             "media_type": CONFIG_MEDIA_TYPE},
            {"role": "layer", "content": LAYER_TEXT, "encoding": "utf8",
             "media_type": LAYER_MEDIA_TYPE}
        ]
    }])
}

/// Hash bytes with `shasum -a 256` — an implementation NetGet does not own — so the
/// `Docker-Content-Digest` assertion is not a check of the code against itself.
/// Returns `None` if `shasum` is unavailable, in which case the caller skips only
/// that one cross-check.
fn external_sha256(bytes: &[u8]) -> Option<String> {
    use std::io::Write;
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("payload.bin");
    std::fs::File::create(&path).ok()?.write_all(bytes).ok()?;
    let out = Command::new("shasum")
        .arg("-a")
        .arg("256")
        .arg(&path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let hex = stdout.split_whitespace().next()?;
    Some(format!("sha256:{}", hex))
}

fn header(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Assert an OCI error envelope and return the parsed error object.
async fn assert_error_envelope(resp: reqwest::Response, expected_code: &str) -> Value {
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("expected a JSON error envelope, got {e}"));
    let errors = body
        .get("errors")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("no 'errors' array in {body} (status {status})"));
    assert!(!errors.is_empty(), "empty 'errors' array in {body}");
    assert_eq!(
        errors[0]["code"], expected_code,
        "wrong error code in {body} (status {status})"
    );
    assert!(
        errors[0].get("message").and_then(|m| m.as_str()).is_some(),
        "error object carries no message: {body}"
    );
    errors[0].clone()
}

// ---------------------------------------------------------------------------
// Test 1 — the whole pull path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_oci_registry_pull_path() -> E2EResult<()> {
    let prompt = "Open an OCI container registry on port {AVAILABLE_PORT} hosting library/alpine.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("OCI container registry")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "oci_registry",
                "instruction": "OCI registry hosting library/alpine"
            }]))
            .expect_calls(1)
            .and()
            .on_event("oci_catalog_request")
            .respond_with_actions(json!([{
                "type": "send_oci_catalog",
                "repositories": ["library/alpine", "team/api"]
            }]))
            .expect_calls(1)
            .and()
            // A repository the registry does not have: the model's refusal path,
            // which must be structurally distinct from silence.
            .on_event("oci_tags_request")
            .and_event_data_contains("name", "ghost/repo")
            .respond_with_actions(json!([{
                "type": "send_oci_error",
                "code": "NAME_UNKNOWN",
                "message": "repository ghost/repo is not hosted here"
            }]))
            .expect_calls(1)
            .and()
            .on_event("oci_tags_request")
            .and_event_data_contains("name", REPO)
            .respond_with_actions(json!([{
                "type": "send_oci_tags",
                "tags": ["latest", "3.20", "3.19"]
            }]))
            .expect_calls(1)
            .and()
            // One rule answers the manifest by tag, the HEAD, and the by-digest
            // fetch: identical content, so the digests must agree across all three.
            .on_event("oci_manifest_request")
            .and_event_data_contains("name", REPO)
            .respond_with_actions(manifest_action())
            .expect_calls(3)
            .and()
            .on_event("oci_blob_request")
            .and_event_data_contains("digest", CONFIG_DIGEST)
            .respond_with_actions(json!([{
                "type": "send_oci_blob",
                "content": CONFIG_JSON,
                "encoding": "utf8",
                "media_type": CONFIG_MEDIA_TYPE
            }]))
            .expect_calls(1)
            .and()
            .on_event("oci_blob_request")
            .and_event_data_contains("digest", LAYER_DIGEST)
            .respond_with_actions(json!([{
                "type": "send_oci_blob",
                "content": LAYER_TEXT,
                "encoding": "utf8",
                "media_type": LAYER_MEDIA_TYPE
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    let base = format!("http://127.0.0.1:{}", server.port);
    println!("OCI registry started at {base}");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // --- 1. GET /v2/ : the probe every client sends first. No LLM call (auto mode).
    let resp = client.get(format!("{base}/v2/")).send().await?;
    assert_eq!(resp.status(), 200, "GET /v2/ must succeed");
    assert_eq!(
        header(&resp, "docker-distribution-api-version"),
        "registry/2.0",
        "clients use this header to confirm the endpoint is a v2 registry"
    );
    assert_eq!(resp.text().await?, "{}");

    // --- 2. Catalog
    let resp = client.get(format!("{base}/v2/_catalog")).send().await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert_eq!(
        body["repositories"],
        json!(["library/alpine", "team/api"]),
        "catalog must be {{\"repositories\": [...]}}"
    );

    // --- 3. Tag list
    let resp = client
        .get(format!("{base}/v2/{REPO}/tags/list"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert_eq!(body["name"], REPO, "tag list must echo the repository name");
    assert_eq!(body["tags"], json!(["latest", "3.20", "3.19"]));

    // --- 4. Manifest by tag: the crux.
    let resp = client
        .get(format!("{base}/v2/{REPO}/manifests/latest"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header(&resp, "content-type"),
        MANIFEST_MEDIA_TYPE,
        "an image manifest must not be served as a manifest list"
    );
    let manifest_digest = header(&resp, "docker-content-digest");
    assert!(
        manifest_digest.starts_with("sha256:") && manifest_digest.len() == 71,
        "Docker-Content-Digest missing or malformed: {manifest_digest:?}"
    );
    assert_eq!(
        header(&resp, "etag"),
        format!("\"{manifest_digest}\""),
        "ETag must carry the content digest"
    );
    let manifest_bytes = resp.bytes().await?.to_vec();

    // The property real clients enforce: the advertised digest IS the hash of the
    // bytes served. Verified with an implementation NetGet does not own.
    match external_sha256(&manifest_bytes) {
        Some(external) => assert_eq!(
            external, manifest_digest,
            "Docker-Content-Digest does not match `shasum -a 256` of the served manifest"
        ),
        None => println!("(shasum unavailable - skipped the external digest cross-check)"),
    }

    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    assert_eq!(manifest["schemaVersion"], 2);
    // The model wrote sha256:0000… and sha256:1111…; the server must have replaced
    // both with the real hashes of the content it supplied.
    assert_eq!(
        manifest["config"]["digest"], CONFIG_DIGEST,
        "config descriptor digest was not recomputed from the supplied content"
    );
    assert_eq!(manifest["config"]["size"], CONFIG_JSON.len());
    assert_eq!(
        manifest["layers"][0]["digest"], LAYER_DIGEST,
        "layer descriptor digest was not recomputed from the supplied content"
    );
    assert_eq!(manifest["layers"][0]["size"], LAYER_TEXT.len());
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.title"], "netget-invented",
        "model-authored annotations must survive descriptor rewriting"
    );

    // --- 5. HEAD the same manifest: real clients use this for `crane digest`.
    let resp = client
        .head(format!("{base}/v2/{REPO}/manifests/latest"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header(&resp, "docker-content-digest"),
        manifest_digest,
        "HEAD must report the same digest as GET"
    );
    assert_eq!(
        header(&resp, "content-length"),
        manifest_bytes.len().to_string(),
        "HEAD must report the body length it would have sent"
    );
    assert!(resp.bytes().await?.is_empty(), "HEAD must send no body");

    // --- 6. Manifest by digest: the server recomputes and enforces equality.
    let resp = client
        .get(format!("{base}/v2/{REPO}/manifests/{manifest_digest}"))
        .send()
        .await?;
    assert_eq!(
        resp.status(),
        200,
        "fetching the manifest by the digest we were just given must succeed"
    );
    assert_eq!(header(&resp, "docker-content-digest"), manifest_digest);
    assert_eq!(
        resp.bytes().await?.to_vec(),
        manifest_bytes,
        "by-tag and by-digest must return byte-identical manifests"
    );

    // --- 7. Config blob: served bytes must hash to the digest that named them.
    let resp = client
        .get(format!("{base}/v2/{REPO}/blobs/{CONFIG_DIGEST}"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-type"), CONFIG_MEDIA_TYPE);
    assert_eq!(header(&resp, "docker-content-digest"), CONFIG_DIGEST);
    let config_bytes = resp.bytes().await?.to_vec();
    assert_eq!(
        config_bytes,
        CONFIG_JSON.as_bytes(),
        "config blob body must be exactly the supplied content"
    );
    if let Some(external) = external_sha256(&config_bytes) {
        assert_eq!(
            external, CONFIG_DIGEST,
            "the served config blob does not hash to the digest it was served under"
        );
    }
    // And it must be a parseable image config, not opaque bytes.
    let cfg: Value = serde_json::from_slice(&config_bytes)?;
    assert_eq!(cfg["architecture"], "amd64");

    // --- 8. Layer blob
    let resp = client
        .get(format!("{base}/v2/{REPO}/blobs/{LAYER_DIGEST}"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "docker-content-digest"), LAYER_DIGEST);
    let layer_bytes = resp.bytes().await?.to_vec();
    assert_eq!(layer_bytes, LAYER_TEXT.as_bytes());
    if let Some(external) = external_sha256(&layer_bytes) {
        assert_eq!(external, LAYER_DIGEST);
    }

    // --- 9. Unknown repository: an explicit refusal, not silence.
    let resp = client
        .get(format!("{base}/v2/ghost/repo/tags/list"))
        .send()
        .await?;
    assert_eq!(resp.status(), 404);
    assert_error_envelope(resp, "NAME_UNKNOWN").await;

    // --- The following cost no LLM call: they are refused before the model is asked.

    // Push is not implemented, and says so rather than pretending.
    let resp = client
        .post(format!("{base}/v2/{REPO}/blobs/uploads/"))
        .send()
        .await?;
    assert_eq!(resp.status(), 405, "push must be refused, not accepted");
    assert_error_envelope(resp, "UNSUPPORTED").await;

    let resp = client
        .put(format!("{base}/v2/{REPO}/manifests/v2"))
        .body("{}")
        .send()
        .await?;
    assert_eq!(resp.status(), 405, "manifest PUT must be refused");
    assert_error_envelope(resp, "UNSUPPORTED").await;

    // Invalid repository name (uppercase is not in the OCI grammar).
    let resp = client
        .get(format!("{base}/v2/Library/Alpine/tags/list"))
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    assert_error_envelope(resp, "NAME_INVALID").await;

    // Malformed digest.
    let resp = client
        .get(format!("{base}/v2/{REPO}/blobs/sha256:nothex"))
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    assert_error_envelope(resp, "DIGEST_INVALID").await;

    // Unsupported digest algorithm: refused honestly rather than faked.
    let resp = client
        .get(format!("{base}/v2/{REPO}/blobs/sha512:{}", "a".repeat(128)))
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    assert_error_envelope(resp, "DIGEST_INVALID").await;

    // Not a /v2/ route at all.
    let resp = client.get(format!("{base}/healthz")).send().await?;
    assert_eq!(resp.status(), 404);
    assert_error_envelope(resp, "UNSUPPORTED").await;

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2 — fail-closed behaviour
// ---------------------------------------------------------------------------

/// The single most important test in this suite.
///
/// A registry that serves bytes under a digest they do not hash to defeats the
/// entire point of content addressing, and — because NetGet has no blob store —
/// the model *will* eventually return content that does not match. This asserts
/// the server refuses rather than serving it, and that a model with no answer
/// produces an error rather than a plausible default.
#[tokio::test]
async fn test_oci_registry_refuses_mismatched_content() -> E2EResult<()> {
    let prompt =
        "Open an OCI container registry on port {AVAILABLE_PORT} that requires a bearer token.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("OCI container registry")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "oci_registry",
                "startup_params": {"version_check": "llm"},
                "instruction": "Token-protected OCI registry"
            }]))
            .expect_calls(1)
            .and()
            // version_check=llm, so GET /v2/ reaches the model and it demands a token.
            .on_event("oci_version_check")
            .respond_with_actions(json!([{
                "type": "send_oci_auth_challenge",
                "realm": "https://auth.test.invalid/token",
                "service": "netget.test.invalid",
                "scope": "repository:library/alpine:pull",
                "message": "a bearer token is required"
            }]))
            .expect_calls(1)
            .and()
            // The model returns content that does NOT hash to the requested digest.
            .on_event("oci_blob_request")
            .respond_with_actions(json!([{
                "type": "send_oci_blob",
                "content": "this is emphatically not the config blob",
                "encoding": "utf8"
            }]))
            .expect_calls(1)
            .and()
            // The model answers a manifest request with a valid action that is not
            // an OCI reply. The turn succeeds; the registry still has nothing to
            // serve. Silence must not become a plausible manifest.
            .on_event("oci_manifest_request")
            .respond_with_actions(json!([{
                "type": "show_message",
                "message": "a client asked for a manifest I have no answer for"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    let base = format!("http://127.0.0.1:{}", server.port);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // --- 1. The version probe now reaches the model, which demands a token.
    let resp = client.get(format!("{base}/v2/")).send().await?;
    assert_eq!(resp.status(), 401);
    let challenge = header(&resp, "www-authenticate");
    assert!(
        challenge.starts_with("Bearer realm=\"https://auth.test.invalid/token\""),
        "malformed WWW-Authenticate: {challenge:?}"
    );
    assert!(
        challenge.contains("service=\"netget.test.invalid\"")
            && challenge.contains("scope=\"repository:library/alpine:pull\""),
        "challenge must carry service and scope: {challenge:?}"
    );
    assert_error_envelope(resp, "UNAUTHORIZED").await;

    // --- 2. Digest mismatch: the registry must refuse to serve.
    let resp = client
        .get(format!("{base}/v2/{REPO}/blobs/{CONFIG_DIGEST}"))
        .send()
        .await?;
    assert_eq!(
        resp.status(),
        404,
        "content that does not hash to the requested digest must never be served"
    );
    let err = assert_error_envelope(resp, "BLOB_UNKNOWN").await;
    assert_eq!(
        err["detail"]["requested"], CONFIG_DIGEST,
        "the refusal must name what was asked for"
    );
    let computed = err["detail"]["computed"].as_str().unwrap_or_default();
    assert!(
        computed.starts_with("sha256:") && computed != CONFIG_DIGEST,
        "the refusal must name what the content actually hashed to: {err}"
    );

    // --- 3. No usable action: fail-closed with a distinct code, not a fake manifest.
    let resp = client
        .get(format!("{base}/v2/{REPO}/manifests/latest"))
        .send()
        .await?;
    assert_eq!(
        resp.status(),
        500,
        "an LLM that produced no answer must not look like a successful pull"
    );
    let err = assert_error_envelope(resp, "UNKNOWN").await;
    assert!(
        err["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no usable response"),
        "the no-answer path must be self-describing: {err}"
    );

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3 — a real, independent OCI client
// ---------------------------------------------------------------------------

/// Drive the registry with `crane` (google/go-containerregistry), which re-hashes
/// everything it fetches. This is the strongest evidence available that the digests
/// are real: crane errors out on a mismatch rather than warning.
///
/// Handlers are deterministic (static + one script), so this costs exactly one LLM
/// call — the server start — and crane can make as many requests as it likes.
///
/// **This test fails rather than skips when `crane` or `python3` is missing**, and
/// that is the point of it. It used to print "crane not installed - skipping" and
/// return `Ok(())`, so on any runner without crane it was a green pass that had
/// asserted nothing — while this file's own header claims "a real, independent OCI
/// client accepts what we serve" and `metadata()` claims validation "against crane
/// 0.21.6". A silent skip is how a maturity claim outlives the thing that justified
/// it; `tests/server/npm/e2e_test.rs::test_npm_with_real_cli` is the shape copied
/// here. The cost is that `crane` and `python3` are now requirements wherever this
/// suite runs — deliberately, because the alternative is an unfalsifiable claim.
///
/// `python3` is needed for the blob-dispatching *script handler*, not by crane.
///
/// `flavor = "multi_thread"`: every `crane` invocation below is a **blocking**
/// `std::process::Command`, and the in-process mock Ollama server is spawned onto
/// this test's own runtime. On the default current-thread runtime a blocking crane
/// call holds the only worker, so the moment any handler misses and falls through to
/// the model, crane waits on netget, netget waits on the mock, and the mock cannot
/// run because crane owns the thread. Today's handlers are all deterministic so it
/// happens not to deadlock; that is luck, not design.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oci_registry_against_crane() -> E2EResult<()> {
    match Command::new("crane").arg("version").output() {
        Ok(out) if out.status.success() => {
            println!("crane {}", String::from_utf8_lossy(&out.stdout).trim())
        }
        Ok(out) => {
            return Err(format!(
                "`crane version` exited {}: this test's whole point is driving the real \
                 google/go-containerregistry client against NetGet's registry",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "crane is not available ({e}): this test's whole point is driving the real \
                 google/go-containerregistry client against NetGet's registry, and skipping \
                 it would leave the OCI registry's real-client claim resting on nothing. \
                 Install it with `brew install crane` or from \
                 https://github.com/google/go-containerregistry/releases"
            )
            .into())
        }
    }
    match Command::new("python3").arg("--version").output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return Err(format!(
                "`python3 --version` exited {}: the blob script handler needs it",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "python3 is not available ({e}): the blob-dispatching script handler needs \
                 it, and without the handler this test would fall through to the model"
            )
            .into())
        }
    }

    // Dispatches a blob request on the requested digest. A static handler cannot:
    // there are two blobs with different digests and one event.
    let blob_script = format!(
        r#"import json,sys
i=json.load(sys.stdin)
d=i.get("event",{{}}).get("digest","")
C={config_literal}
L={layer_literal}
if d=="{config_digest}":
    a=[{{"type":"send_oci_blob","content":C,"encoding":"utf8","media_type":"{config_mt}"}}]
elif d=="{layer_digest}":
    a=[{{"type":"send_oci_blob","content":L,"encoding":"utf8","media_type":"{layer_mt}"}}]
else:
    a=[{{"type":"send_oci_error","code":"BLOB_UNKNOWN","message":"no such blob"}}]
sys.stdout.write(json.dumps({{"actions":a}}))
"#,
        // Emit the fixtures as JSON string literals, which are also valid Python.
        config_literal = serde_json::to_string(CONFIG_JSON).unwrap(),
        layer_literal = serde_json::to_string(LAYER_TEXT).unwrap(),
        config_digest = CONFIG_DIGEST,
        layer_digest = LAYER_DIGEST,
        config_mt = CONFIG_MEDIA_TYPE,
        layer_mt = LAYER_MEDIA_TYPE,
    );

    let prompt = "Open an OCI container registry on port {AVAILABLE_PORT} for crane to pull from.";
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("OCI container registry")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "oci_registry",
                "instruction": "Deterministic OCI registry for a real client",
                "event_handlers": [
                    {
                        "event_pattern": "oci_catalog_request",
                        "handler": {"type": "static", "actions": [{
                            "type": "send_oci_catalog",
                            "repositories": [REPO]
                        }]}
                    },
                    {
                        "event_pattern": "oci_tags_request",
                        "handler": {"type": "static", "actions": [{
                            "type": "send_oci_tags",
                            "tags": ["latest", "3.20"]
                        }]}
                    },
                    {
                        "event_pattern": "oci_manifest_request",
                        "handler": {"type": "static", "actions": manifest_action()}
                    },
                    {
                        "event_pattern": "oci_blob_request",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": blob_script
                        }
                    }
                ]
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    let registry = format!("127.0.0.1:{}", server.port);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let crane = |args: Vec<String>| -> (bool, String, String) {
        let out = Command::new("crane")
            .args(&args)
            .arg("--insecure")
            .output()
            .expect("crane should be runnable");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )
    };

    // crane catalog
    let (ok, stdout, stderr) = crane(vec!["catalog".into(), registry.clone()]);
    assert!(ok, "crane catalog failed: {stderr}");
    assert!(
        stdout.lines().any(|l| l.trim() == REPO),
        "crane catalog did not list {REPO}: {stdout:?}"
    );

    // crane ls
    let (ok, stdout, stderr) = crane(vec!["ls".into(), format!("{registry}/{REPO}")]);
    assert!(ok, "crane ls failed: {stderr}");
    let tags: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert!(tags.contains(&"latest"), "crane ls output: {stdout:?}");
    assert!(tags.contains(&"3.20"), "crane ls output: {stdout:?}");

    // crane manifest — crane parses this and rejects a malformed one.
    let (ok, stdout, stderr) = crane(vec!["manifest".into(), format!("{registry}/{REPO}:latest")]);
    assert!(ok, "crane manifest failed: {stderr}");
    let manifest: Value = serde_json::from_str(&stdout)?;
    assert_eq!(manifest["config"]["digest"], CONFIG_DIGEST);
    assert_eq!(manifest["layers"][0]["digest"], LAYER_DIGEST);

    // crane digest — crane computes this itself from the manifest bytes, so it
    // agreeing with our Docker-Content-Digest is an independent verification.
    let (ok, crane_digest, stderr) =
        crane(vec!["digest".into(), format!("{registry}/{REPO}:latest")]);
    assert!(ok, "crane digest failed: {stderr}");
    assert!(
        crane_digest.starts_with("sha256:"),
        "crane digest output: {crane_digest:?}"
    );

    // Fetching by the digest crane computed must work, which only holds if crane's
    // hash of our bytes equals our own.
    let (ok, stdout, stderr) = crane(vec![
        "manifest".into(),
        format!("{registry}/{REPO}@{crane_digest}"),
    ]);
    assert!(
        ok,
        "crane could not fetch the manifest by the digest it computed: {stderr}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&stdout)?,
        manifest,
        "by-tag and by-digest manifests differ"
    );

    // crane config — fetches the config blob and verifies its digest against the
    // manifest descriptor. This is the assertion that the whole design exists for.
    let (ok, stdout, stderr) = crane(vec!["config".into(), format!("{registry}/{REPO}:latest")]);
    assert!(ok, "crane config failed (digest verification): {stderr}");
    assert_eq!(
        stdout, CONFIG_JSON,
        "crane returned a config blob different from what we served"
    );

    // crane blob — the layer, fetched by digest and verified.
    let (ok, stdout, stderr) = crane(vec![
        "blob".into(),
        format!("{registry}/{REPO}@{LAYER_DIGEST}"),
    ]);
    assert!(ok, "crane blob failed: {stderr}");
    assert_eq!(stdout, LAYER_TEXT);

    println!("crane accepted the registry: catalog, ls, manifest, digest, config, blob");

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    Ok(())
}
