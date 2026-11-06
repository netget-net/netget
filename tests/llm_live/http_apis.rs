//! Live-LLM suite for the HTTP-API protocols.
//!
//! All of these speak HTTP, so they *could* be driven on the wire; these cases
//! work at the event layer instead, because each protocol's correctness lives
//! in the action payload (which fields the envelope must carry) rather than in
//! the transport, and one case per event covers the whole surface at one model
//! call each. Where the executor computes something from the payload — OCI
//! recomputes the SHA-256 of what it serves, Git derives every commit SHA —
//! the case asserts the payload the executor needs to get that right.
//!
//! COVERS: kubernetes: k8s_list_request, k8s_get_request, k8s_write_request
//! COVERS: npm: NPM_PACKAGE_REQUEST, NPM_TARBALL_REQUEST, NPM_LIST_REQUEST, NPM_SEARCH_REQUEST
//! COVERS: pypi: pypi_request
//! COVERS: maven: maven_artifact_request
//! COVERS: oci-registry: oci_version_check, oci_catalog_request, oci_tags_request, oci_manifest_request, oci_blob_request
//! COVERS: ollama: ollama_generate_request, ollama_chat_request, ollama_models_request
//! COVERS: openapi: openapi_request
//! COVERS: openid: openid_request
//! COVERS: oauth2: oauth2_authorize, oauth2_token, oauth2_introspect
//! COVERS: s3: s3_request
//! COVERS: sqs: sqs_request
//! COVERS: dynamo: dynamo_request
//! COVERS: git: git_info_refs, git_upload_pack
//! COVERS: mercurial: hg_capabilities, hg_heads, hg_branchmap, hg_listkeys, hg_getbundle
//! COVERS: hls: hls_playlist_request, hls_segment_request
//! COVERS: webdav: webdav_request
//! COVERS: mcp: mcp_initialize, mcp_resources_list, mcp_resources_read, mcp_tools_list, mcp_tools_call, mcp_prompts_list, mcp_prompts_get
//! COVERS: torrent-tracker: tracker_announce_request, tracker_scrape_request

use crate::helpers::llm_live::live_llm_enabled;
use crate::helpers::llm_live_case::{EventCase, ParamCheck};
use crate::helpers::E2EResult;
use serde_json::json;

// ---------------------------------------------------------------------------
// Kubernetes — kubectl decodes a List, an object, or a Status; nothing else.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn k8s_list_returns_objects() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Kubernetes",
        "You are a Kubernetes apiserver for a small cluster. The default \
         namespace runs one pod, web-0, image nginx:1.27, phase Running. List \
         it when a client asks.",
        "k8s_list_request",
        json!({
            "method": "GET",
            "path": "/api/v1/namespaces/default/pods",
            "api_group": "",
            "api_version": "v1",
            "group_version": "v1",
            "resource": "pods",
            "user_agent": "kubectl/v1.31.0",
            "as_table": false,
            "namespace": "default"
        }),
    )
    .expect_action("k8s_list_response")
    .check(ParamCheck::custom(
        "items",
        "carries the pod, with the metadata.name kubectl prints",
        |v| {
            let items = v
                .as_array()
                .ok_or_else(|| format!("items must be an array, got {}", v))?;
            let pod = items
                .iter()
                .find(|i| i["metadata"]["name"].as_str() == Some("web-0"))
                .ok_or_else(|| format!("no object named web-0 in the list: {}", v))?;
            if pod["metadata"]["namespace"].as_str() != Some("default") {
                return Err(format!(
                    "the pod must be in the requested namespace: {}",
                    pod
                ));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn k8s_get_missing_object_is_a_404_status() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Kubernetes",
        "You are a Kubernetes apiserver. The default namespace runs exactly one \
         pod, web-0. A request for any other pod must be refused as not found, \
         the way the apiserver reports a missing object.",
        "k8s_get_request",
        json!({
            "method": "GET",
            "path": "/api/v1/namespaces/default/pods/does-not-exist",
            "api_group": "",
            "api_version": "v1",
            "group_version": "v1",
            "resource": "pods",
            "user_agent": "kubectl/v1.31.0",
            "as_table": false,
            "namespace": "default",
            "name": "does-not-exist"
        }),
    )
    .expect_action("k8s_status")
    .check(ParamCheck::equals("code", json!(404)))
    .check(ParamCheck::custom(
        "reason",
        "is the NotFound reason kubectl matches on",
        |v| {
            let s = v.as_str().unwrap_or("");
            if s.eq_ignore_ascii_case("NotFound") {
                Ok(())
            } else {
                Err(format!("expected reason NotFound, got {:?}", v))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn k8s_create_returns_the_admitted_object() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Kubernetes",
        "You are a Kubernetes apiserver that admits every create. Return the \
         object as it now exists in the cluster, freshly created.",
        "k8s_write_request",
        json!({
            "method": "POST",
            "path": "/api/v1/namespaces/default/pods",
            "api_group": "",
            "api_version": "v1",
            "group_version": "v1",
            "resource": "pods",
            "user_agent": "kubectl/v1.31.0",
            "as_table": false,
            "namespace": "default",
            "body": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": { "name": "web-1", "namespace": "default" },
                "spec": { "containers": [{ "name": "web", "image": "nginx:1.27" }] }
            }
        }),
    )
    .expect_action("k8s_object_response")
    .check(ParamCheck::custom(
        "object",
        "is the created pod, named as the client asked",
        |v| {
            if v["metadata"]["name"].as_str() == Some("web-1") {
                Ok(())
            } else {
                Err(format!(
                    "the returned object must be the one that was created (web-1): {}",
                    v
                ))
            }
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// npm — npm/yarn read the metadata document verbatim.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn npm_package_metadata_names_the_package() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "NPM",
        "You are an npm registry. The package netget-live exists at version \
         1.2.3 and is described as a live test fixture. Serve its metadata.",
        "NPM_PACKAGE_REQUEST",
        json!({
            "method": "GET",
            "path": "/netget-live",
            "query": "",
            "description": "package metadata request"
        }),
    )
    .expect_action("npm_package_metadata")
    .check(ParamCheck::custom(
        "metadata",
        "names the requested package and its version",
        |v| {
            if v["name"].as_str() != Some("netget-live") {
                return Err(format!("metadata must name the requested package: {}", v));
            }
            if !v.to_string().contains("1.2.3") {
                return Err(format!("metadata must carry the version 1.2.3: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

/// The real .tgz used by the tarball cases: a gzipped tar holding one
/// `package/package.json`. Generated once and pinned, because the point of
/// the test is that the model relays the bytes *given to it* — a tarball is
/// the one npm response that cannot be invented.
const NETGET_LIVE_TGZ_B64: &str = "H4sIAI0lgmoC/+3NvQrCMBSG4cxehZxZYxJrB+8myKHUn7Q0tYt470YdBGcRwfdZ3sO3nD7uDrHRVf+s3\
    ecumQ9zRV1VjxbvdW7jX/d9974Owcyd+YJzHuNQ3pv/dJEUTypbSTo2Oi6P7aSykEmH3Hap7N4Gu5brzAAAAAAAAAAAAAAAAAAAfskNxBOA2gAoAAA=";

/// Serving a tarball is *relaying*, not authoring: the encoded bytes are in
/// the instruction and must come back byte-for-byte.
///
/// This asserts more than "looks like base64" now, because a lenient check is
/// what let the real bug hide — netget used to `unwrap_or_default()` the
/// decode, so anything undecodable became an **HTTP 200 with a zero-byte
/// body** and `npm install` failed deep inside tar extraction with nothing
/// pointing back at the model's answer.
#[tokio::test]
async fn npm_tarball_relays_the_supplied_bytes() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "NPM",
        format!(
            "You are an npm registry serving exactly one package, netget-live \
             1.2.3. Its tarball, base64-encoded, is:\n{}\nServe that package \
             when it is requested.",
            NETGET_LIVE_TGZ_B64
        ),
        "NPM_TARBALL_REQUEST",
        json!({
            "method": "GET",
            "path": "/netget-live/-/netget-live-1.2.3.tgz",
            "query": "",
            "description": "tarball request"
        }),
    )
    .expect_action("npm_package_tarball")
    .check(ParamCheck::custom(
        "tarball_data",
        "the supplied base64, complete and unaltered",
        |v| {
            let s = v
                .as_str()
                .ok_or_else(|| format!("tarball_data must be a base64 string, got {}", v))?;
            let s = s.trim();
            if s.contains("...") || s.contains('\u{2026}') {
                return Err(format!(
                    "tarball_data was abbreviated ({:?}…). The server decodes it before \
                     sending, so an elided string is not a package — it is a decode \
                     failure",
                    s.chars().take(24).collect::<String>()
                ));
            }
            let expected: String = NETGET_LIVE_TGZ_B64
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let got: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if got == expected {
                Ok(())
            } else {
                Err(format!(
                    "the tarball must be relayed byte-for-byte: a .tgz is binary and \
                     cannot be regenerated. Expected {} base64 chars, got {}",
                    expected.len(),
                    got.len()
                ))
            }
        },
    ))
    .run()
    .await
}

/// With no tarball to serve, the honest answer is a 404 — not an invented
/// one. This is the fail-closed half of the same contract: a fabricated
/// tarball is undecodable, and undecodable now means a 500 rather than a
/// silent empty 200.
#[tokio::test]
async fn npm_missing_tarball_is_a_404_not_an_invention() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "NPM",
        "You are an npm registry that hosts only the package 'netget-live'. \
         You have no other package and no tarball for any other name.",
        "NPM_TARBALL_REQUEST",
        json!({
            "method": "GET",
            "path": "/left-pad/-/left-pad-1.3.0.tgz",
            "query": "",
            "description": "tarball request"
        }),
    )
    .expect_action("npm_error")
    .check(ParamCheck::custom(
        "status_code",
        "404 — the package does not exist here",
        |v| {
            let code = v.as_u64().or_else(|| v.as_str()?.trim().parse().ok());
            match code {
                Some(404) => Ok(()),
                Some(c) => Err(format!(
                    "a package this registry does not host is 404; npm branches on the \
                     code and a {} sends it down a retry path instead of reporting the \
                     package missing",
                    c
                )),
                None => Err(format!("status_code is missing or not a number: {}", v)),
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn npm_list_returns_packages() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "NPM",
        "You are an npm registry hosting exactly one package, netget-live at \
         version 1.2.3. Answer a request for the full package listing.",
        "NPM_LIST_REQUEST",
        json!({
            "method": "GET",
            "path": "/-/all",
            "query": "",
            "description": "package list request"
        }),
    )
    .expect_action("npm_package_list")
    .check(ParamCheck::custom("packages", "lists netget-live", |v| {
        if v.get("netget-live").is_some() {
            Ok(())
        } else {
            Err(format!(
                "the hosted package must appear in the listing: {}",
                v
            ))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn npm_search_returns_result_envelope() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "NPM",
        "You are an npm registry hosting one package, netget-live. A search for \
         it must come back in the registry's search format, which carries an \
         objects array and a total count.",
        "NPM_SEARCH_REQUEST",
        json!({
            "method": "GET",
            "path": "/-/v1/search",
            "query": "text=netget-live",
            "description": "search request"
        }),
    )
    .expect_action("npm_package_search")
    .check(ParamCheck::custom(
        "results",
        "carries the objects array and total the npm client reads",
        |v| {
            if v["objects"].as_array().is_none() {
                return Err(format!("search results must carry an objects array: {}", v));
            }
            if v["total"].as_u64().is_none() {
                return Err(format!("search results must carry a total: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// PyPI — pip parses PEP 503 anchor HTML.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pypi_simple_index_is_anchor_html() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "PyPI",
        "You are a PyPI simple index (PEP 503). The project netget-live has one \
         file, netget_live-1.2.3-py3-none-any.whl. Serve its project page as \
         HTML with an anchor per file, as pip expects.",
        "pypi_request",
        json!({
            "method": "GET",
            "uri": "/simple/netget-live/",
            "path": "/simple/netget-live/",
            "headers": { "user-agent": "pip/24.0" },
            "body": "",
            "request_type": "list_files",
            "package_name": "netget-live"
        }),
    )
    .expect_action("send_pypi_response")
    .check(ParamCheck::equals("status", json!(200)))
    .check(ParamCheck::custom(
        "body",
        "is HTML carrying an anchor for the file (PEP 503)",
        |v| {
            let s = v.as_str().unwrap_or("");
            if !s.contains("<a ") && !s.contains("<A ") {
                return Err(format!(
                    "pip parses anchors out of this page; no <a> element found: {:?}",
                    s
                ));
            }
            if !s.contains("netget_live-1.2.3") {
                return Err(format!("the page must link the project's file: {:?}", s));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// Maven
// ---------------------------------------------------------------------------

#[tokio::test]
async fn maven_pom_is_served_as_xml() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Maven",
        "You are a Maven repository hosting com.example:mylib:1.0.0. Serve its \
         POM, which is an XML document naming that group, artifact and version.",
        "maven_artifact_request",
        json!({
            "method": "GET",
            "uri": "/com/example/mylib/1.0.0/mylib-1.0.0.pom",
            "group_id": "com.example",
            "artifact_id": "mylib",
            "version": "1.0.0",
            "classifier": null,
            "extension": "pom",
            "is_metadata": false,
            "is_checksum": false,
            "checksum_type": null,
            "headers": { "user-agent": "Apache-Maven/3.9.6" }
        }),
    )
    .expect_action("send_maven_artifact")
    .check(ParamCheck::custom(
        "body",
        "is a POM naming the requested coordinates",
        |v| {
            let s = v.as_str().unwrap_or("");
            for needle in ["com.example", "mylib", "1.0.0"] {
                if !s.contains(needle) {
                    return Err(format!("the POM must name {}: {:?}", needle, s));
                }
            }
            if !s.contains("<project") {
                return Err(format!("a POM is an XML <project> document: {:?}", s));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// OCI registry — the executor re-hashes what it serves, so the payload has to
// be the real content.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oci_version_check_admits_anonymous_pulls() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OCI-Registry",
        "You are an OCI registry that allows anonymous pulls and needs no \
         token. A client probing the v2 endpoint should simply be admitted.",
        "oci_version_check",
        json!({
            "method": "GET",
            "path": "/v2/",
            "authorization": null,
            "user_agent": "docker/25.0.0",
            "client": "docker"
        }),
    )
    .expect_action("send_oci_version_ok")
    .run()
    .await
}

#[tokio::test]
async fn oci_catalog_lists_repositories() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OCI-Registry",
        "You are an OCI registry hosting exactly one repository, \
         library/alpine. Answer a catalog request with it.",
        "oci_catalog_request",
        json!({
            "method": "GET",
            "path": "/v2/_catalog",
            "authorization": null,
            "user_agent": "docker/25.0.0",
            "client": "docker",
            "page_size": null,
            "last": null
        }),
    )
    .expect_action("send_oci_catalog")
    .check(ParamCheck::custom(
        "repositories",
        "lists library/alpine",
        |v| {
            let repos = v
                .as_array()
                .ok_or_else(|| format!("repositories must be an array, got {}", v))?;
            if repos.iter().any(|r| r.as_str() == Some("library/alpine")) {
                Ok(())
            } else {
                Err(format!(
                    "expected the hosted repository library/alpine, got {}",
                    v
                ))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn oci_tags_lists_the_repository_tags() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OCI-Registry",
        "You are an OCI registry. The repository library/alpine has exactly one \
         tag, latest. Answer a tag listing with it.",
        "oci_tags_request",
        json!({
            "method": "GET",
            "path": "/v2/library/alpine/tags/list",
            "authorization": null,
            "user_agent": "docker/25.0.0",
            "client": "docker",
            "name": "library/alpine",
            "page_size": null,
            "last": null
        }),
    )
    .expect_action("send_oci_tags")
    .check(ParamCheck::custom("tags", "lists the tag latest", |v| {
        let tags = v
            .as_array()
            .ok_or_else(|| format!("tags must be an array, got {}", v))?;
        if tags.iter().any(|t| t.as_str() == Some("latest")) {
            Ok(())
        } else {
            Err(format!("expected the tag latest, got {}", v))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn oci_manifest_is_a_v2_manifest_document() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OCI-Registry",
        "You are an OCI registry serving library/alpine:latest. Return the \
         image manifest for it, and supply the config and layer content so the \
         registry can compute their digests.",
        "oci_manifest_request",
        json!({
            "method": "GET",
            "path": "/v2/library/alpine/manifests/latest",
            "authorization": null,
            "user_agent": "docker/25.0.0",
            "client": "docker",
            "name": "library/alpine",
            "reference": "latest",
            "by_digest": false,
            "accept": "application/vnd.oci.image.manifest.v1+json"
        }),
    )
    .expect_action("send_oci_manifest")
    .check(ParamCheck::custom(
        "manifest",
        "is a schemaVersion 2 manifest with a config and layers",
        |v| {
            if v["schemaVersion"].as_u64() != Some(2) {
                return Err(format!("an OCI image manifest is schemaVersion 2: {}", v));
            }
            if v["config"].is_null() {
                return Err(format!("the manifest must describe a config: {}", v));
            }
            if v["layers"].as_array().is_none() {
                return Err(format!("the manifest must carry a layers array: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn oci_blob_returns_content_for_the_digest() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OCI-Registry",
        "You are an OCI registry. A client is pulling the image config blob of \
         library/alpine, which is the JSON document {\"architecture\": \
         \"amd64\", \"os\": \"linux\"}. Return exactly that content.",
        "oci_blob_request",
        json!({
            "method": "GET",
            "path": "/v2/library/alpine/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "authorization": null,
            "user_agent": "docker/25.0.0",
            "client": "docker",
            "name": "library/alpine",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "accept": "application/vnd.oci.image.config.v1+json"
        }),
    )
    .expect_action("send_oci_blob")
    .check(ParamCheck::custom(
        "content",
        "is the instructed config document",
        |v| {
            let s = v.as_str().unwrap_or("");
            if s.contains("amd64") && s.contains("linux") {
                Ok(())
            } else {
                Err(format!("expected the instructed config content, got {:?}", s))
            }
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ollama_generate_returns_completion_text() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Ollama",
        "You are an Ollama server standing in for the model llama2. Answer a \
         generate request by completing the prompt.",
        "ollama_generate_request",
        json!({
            "model": "llama2",
            "prompt": "The capital of France is",
            "stream": false
        }),
    )
    .expect_action("ollama_generate_response")
    .check(ParamCheck::contains("response_text", "Paris"))
    .run()
    .await
}

#[tokio::test]
async fn ollama_chat_returns_assistant_message() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Ollama",
        "You are an Ollama server standing in for the model llama2. Answer a \
         chat request with the assistant's reply to the user's last message.",
        "ollama_chat_request",
        json!({
            "model": "llama2",
            "messages": [{ "role": "user", "content": "Say the word netget-live and nothing else." }],
            "stream": false
        }),
    )
    .expect_action("ollama_chat_response")
    .check(ParamCheck::contains("message_content", "netget-live"))
    .run()
    .await
}

#[tokio::test]
async fn ollama_models_lists_what_is_served() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Ollama",
        "You are an Ollama server that serves exactly two models: llama2 and \
         mistral. Answer a request for the model list.",
        "ollama_models_request",
        json!({}),
    )
    .expect_action("ollama_models_response")
    .check(ParamCheck::custom(
        "models",
        "lists both served models",
        |v| {
            let s = v.to_string();
            if s.contains("llama2") && s.contains("mistral") {
                Ok(())
            } else {
                Err(format!("expected both llama2 and mistral, got {}", v))
            }
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// OpenAPI / OpenID / OAuth2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_route_returns_the_documented_shape() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OpenAPI",
        "You implement an API whose GET /todos returns a JSON array of todo \
         objects, each with id, title and done. There is one todo: id 1, title \
         Buy milk, not done.",
        "openapi_request",
        json!({
            "method": "GET",
            "path": "/todos",
            "uri": "/todos",
            "headers": { "accept": "application/json" },
            "body": "",
            "spec_info": { "spec_loaded": true, "spec_valid": true },
            "matched_route": {
                "operation_id": "listTodos",
                "path_template": "/todos",
                "path_params": {},
                "operation": "get"
            }
        }),
    )
    .expect_action("send_openapi_response")
    .check(ParamCheck::equals("status_code", json!(200)))
    .check(ParamCheck::custom(
        "body",
        "is a JSON array carrying the documented todo",
        |v| {
            let s = v.as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(s.trim())
                .map_err(|e| format!("body must be JSON ({}): {:?}", e, s))?;
            let arr = parsed
                .as_array()
                .ok_or_else(|| format!("GET /todos returns an array: {}", parsed))?;
            if arr.is_empty() || !s.contains("Buy milk") {
                return Err(format!("expected the documented todo, got {:?}", s));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn openid_discovery_document_is_complete() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OpenID",
        "You are an OpenID Connect provider whose issuer is \
         http://localhost:8080, with the standard authorize, token, userinfo \
         and JWKS endpoints under it. Answer the discovery request.",
        "openid_request",
        json!({
            "method": "GET",
            "path": "/.well-known/openid-configuration",
            "query_params": {},
            "headers": { "accept": "application/json" },
            "body": "",
            "form_data": {},
            "endpoint_type": "discovery"
        }),
    )
    .expect_action("send_discovery_document")
    .check(ParamCheck::contains("issuer", "http://localhost:8080"))
    .check(ParamCheck::non_empty("authorization_endpoint"))
    .check(ParamCheck::non_empty("token_endpoint"))
    .check(ParamCheck::non_empty("userinfo_endpoint"))
    .check(ParamCheck::non_empty("jwks_uri"))
    .run()
    .await
}

#[tokio::test]
async fn oauth2_authorize_echoes_state() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OAuth2",
        "You are an OAuth2 authorization server. The client demo-client is \
         registered and its user is already signed in, so an authorization \
         request should be granted with a fresh authorization code. The state \
         parameter is the client's CSRF token and must come back unchanged.",
        "oauth2_authorize",
        json!({
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost/callback",
            "scope": "openid profile",
            "state": "xyzABC123"
        }),
    )
    .expect_action("oauth2_authorize_response")
    .check(ParamCheck::equals("state", json!("xyzABC123")))
    .check(ParamCheck::non_empty("code"))
    .run()
    .await
}

#[tokio::test]
async fn oauth2_token_returns_bearer_token() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OAuth2",
        "You are an OAuth2 authorization server. The authorization code \
         AUTH_CODE_xyz123 was issued to demo-client and is still valid, so \
         exchange it for an access token.",
        "oauth2_token",
        json!({
            "grant_type": "authorization_code",
            "code": "AUTH_CODE_xyz123",
            "redirect_uri": "http://localhost/callback",
            "client_id": "demo-client",
            "client_secret": "s3cret",
            "refresh_token": null,
            "username": null,
            "password": null,
            "scope": null
        }),
    )
    .expect_action("oauth2_token_response")
    .check(ParamCheck::non_empty("access_token"))
    .check(ParamCheck::custom("token_type", "is Bearer", |v| {
        if v.as_str().unwrap_or("").eq_ignore_ascii_case("bearer") {
            Ok(())
        } else {
            Err(format!("expected token_type Bearer, got {:?}", v))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn oauth2_introspect_reports_an_unknown_token_inactive() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "OAuth2",
        "You are an OAuth2 authorization server. You have issued exactly one \
         access token, ACCESS_xyz123. Introspecting any other token must report \
         it as not active — never treat an unknown token as valid.",
        "oauth2_introspect",
        json!({
            "token": "SOME_TOKEN_WE_NEVER_ISSUED",
            "token_type_hint": "access_token"
        }),
    )
    .expect_action("oauth2_introspect_response")
    .check(ParamCheck::equals("active", json!(false)))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// AWS-shaped APIs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s3_get_object_returns_content() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "S3",
        "You are an S3-compatible object store. The bucket my-bucket holds one \
         object, hello.txt, whose contents are the text netget-live-object. \
         Serve reads of it.",
        "s3_request",
        json!({
            "operation": "GetObject",
            "bucket": "my-bucket",
            "key": "hello.txt",
            "request_details": { "method": "GET", "path": "/my-bucket/hello.txt", "body_size": 0 }
        }),
    )
    .expect_action("send_s3_object")
    .check(ParamCheck::contains("content", "netget-live-object"))
    .run()
    .await
}

#[tokio::test]
async fn sqs_send_message_returns_a_message_id() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "SQS",
        "You are an SQS-compatible queue service. Accept the message and answer \
         in the SendMessage response format, which carries a MessageId.",
        "sqs_request",
        json!({
            "operation": "SendMessage",
            "queue_url": "http://localhost:9324/queue/test",
            "request_body": "{\"QueueUrl\":\"http://localhost:9324/queue/test\",\"MessageBody\":\"hello\"}"
        }),
    )
    .expect_action("send_sqs_response")
    .check(ParamCheck::equals("status_code", json!(200)))
    .check(ParamCheck::custom(
        "body",
        "is a JSON-protocol SendMessage response carrying a MessageId",
        |v| {
            let s = v.as_str().unwrap_or("").trim();
            // SQS has two wire protocols and the model must pick the one this
            // server speaks. netget answers with Content-Type
            // application/x-amz-json-1.0, so a legacy Query-API XML document is
            // unparseable here no matter how correct it looks — and that is
            // exactly what a model reaches for, because the XML form dominates
            // older SQS documentation.
            if s.starts_with("<?xml") || s.starts_with('<') {
                return Err(format!(
                    "this is the legacy Query API's XML response. This endpoint sends \
                     Content-Type: application/x-amz-json-1.0, so the body must be a JSON \
                     object — an <SendMessageResponse> document cannot be parsed by a \
                     client here. Got: {}",
                    s.chars().take(160).collect::<String>()
                ));
            }
            let parsed: serde_json::Value = serde_json::from_str(s)
                .map_err(|e| format!("the SQS body must be JSON ({}): {:?}", e, s))?;
            if parsed["MessageId"].as_str().is_none() {
                return Err(format!("SendMessage must return a MessageId: {}", parsed));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn dynamo_get_item_returns_typed_attributes() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "DynamoDB",
        "You are a DynamoDB-compatible store. The table users holds one item \
         with id user-123 and name Alice. DynamoDB attributes are typed, so a \
         string is written {\"S\": \"...\"}. Serve GetItem from that table.",
        "dynamo_request",
        json!({
            "operation": "GetItem",
            "table_name": "users",
            "request_body": "{\"TableName\":\"users\",\"Key\":{\"id\":{\"S\":\"user-123\"}}}"
        }),
    )
    .expect_action("send_dynamo_response")
    .check(ParamCheck::equals("status_code", json!(200)))
    .check(ParamCheck::custom(
        "body",
        "returns the item with DynamoDB-typed attribute values",
        |v| {
            let s = v.as_str().unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(s.trim())
                .map_err(|e| format!("the DynamoDB body must be JSON ({}): {:?}", e, s))?;
            let item = &parsed["Item"];
            if item.is_null() {
                return Err(format!("GetItem must return an Item: {}", parsed));
            }
            if item["id"]["S"].as_str() != Some("user-123") {
                return Err(format!(
                    "attributes are typed — id must be {{\"S\": \"user-123\"}}: {}",
                    item
                ));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// Git / Mercurial — the SHAs are computed by the server from this content, so
// both events must describe the same repository.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn git_info_refs_describes_the_repository() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Git",
        "You are a Git server hosting the repository netget-live on branch \
         main, containing one file README.md whose contents are '# netget \
         live'. Answer the ref advertisement with that repository.",
        "git_info_refs",
        json!({
            "repository": "netget-live",
            "user_agent": "git/2.45.0",
            "client_ip": "127.0.0.1"
        }),
    )
    .expect_action("git_repository")
    .check(ParamCheck::equals("branch", json!("main")))
    .check(ParamCheck::custom(
        "files",
        "carries README.md with its contents (the server hashes exactly this)",
        |v| {
            let files = v
                .as_array()
                .ok_or_else(|| format!("files must be an array, got {}", v))?;
            let readme = files
                .iter()
                .find(|f| f["path"].as_str() == Some("README.md"))
                .ok_or_else(|| format!("no README.md in the repository: {}", v))?;
            if readme["content"].as_str().unwrap_or("").trim().is_empty() {
                return Err(format!("README.md has no content: {}", readme));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn git_upload_pack_describes_the_same_repository() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Git",
        "You are a Git server hosting the repository netget-live on branch \
         main, containing one file README.md whose contents are '# netget \
         live'. A client is fetching it; return that same repository content, \
         unchanged from the ref advertisement, or the commit it wants will not \
         be in the pack.",
        "git_upload_pack",
        json!({
            "repository": "netget-live",
            "wants": ["0000000000000000000000000000000000000000"],
            "haves": [],
            "capabilities": ["multi_ack", "side-band-64k"],
            "client_ip": "127.0.0.1"
        }),
    )
    .expect_action("git_repository")
    .check(ParamCheck::equals("branch", json!("main")))
    .check(ParamCheck::custom("files", "carries README.md", |v| {
        let files = v
            .as_array()
            .ok_or_else(|| format!("files must be an array, got {}", v))?;
        if files
            .iter()
            .any(|f| f["path"].as_str() == Some("README.md"))
        {
            Ok(())
        } else {
            Err(format!("no README.md in the pack content: {}", v))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn hg_capabilities_are_advertised() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Mercurial",
        "You are a Mercurial server that supports the branchmap, getbundle and \
         listkeys commands. Advertise those capabilities.",
        "hg_capabilities",
        json!({ "repository": "netget-live", "client_ip": "127.0.0.1" }),
    )
    .expect_action("hg_capabilities")
    .check(ParamCheck::custom(
        "capabilities",
        "advertises getbundle, without which a clone cannot start",
        |v| {
            let caps = v
                .as_array()
                .ok_or_else(|| format!("capabilities must be an array, got {}", v))?;
            if caps.iter().any(|c| c.as_str() == Some("getbundle")) {
                Ok(())
            } else {
                Err(format!(
                    "expected getbundle among the capabilities, got {}",
                    v
                ))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn hg_heads_are_full_node_ids() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Mercurial",
        "You are a Mercurial server. The repository has a single head whose \
         changeset node id is 1234567890abcdef1234567890abcdef12345678. Report \
         the heads.",
        "hg_heads",
        json!({ "repository": "netget-live", "client_ip": "127.0.0.1" }),
    )
    .expect_action("hg_heads")
    .check(ParamCheck::custom(
        "heads",
        "are 40-character hex node ids (shorter ones are dropped on the wire)",
        |v| {
            let heads = v
                .as_array()
                .ok_or_else(|| format!("heads must be an array, got {}", v))?;
            let head = heads
                .first()
                .and_then(|h| h.as_str())
                .ok_or_else(|| format!("expected at least one head, got {}", v))?;
            if head.len() != 40 || !head.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "a Mercurial node id is exactly 40 hex characters; got {:?}",
                    head
                ));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn hg_branchmap_maps_branches_to_heads() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Mercurial",
        "You are a Mercurial server with a single branch, default, whose head \
         is 1234567890abcdef1234567890abcdef12345678. Answer the branch map.",
        "hg_branchmap",
        json!({ "repository": "netget-live", "client_ip": "127.0.0.1" }),
    )
    .expect_action("hg_branchmap")
    .check(ParamCheck::custom(
        "branches",
        "maps the default branch to its head",
        |v| {
            if v.get("default").is_some() {
                Ok(())
            } else {
                Err(format!("expected the default branch in the map: {}", v))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn hg_listkeys_answers_the_namespace() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Mercurial",
        "You are a Mercurial server with no bookmarks at all. Answer a request \
         for the bookmarks namespace with an empty set of keys.",
        "hg_listkeys",
        json!({
            "repository": "netget-live",
            "namespace": "bookmarks",
            "client_ip": "127.0.0.1"
        }),
    )
    .expect_action("hg_listkeys")
    .check(ParamCheck::custom("keys", "is a key/value object", |v| {
        if v.is_object() {
            Ok(())
        } else {
            Err(format!(
                "keys must be an object of name to value, got {}",
                v
            ))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn hg_getbundle_sends_a_bundle() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Mercurial",
        "You are a Mercurial server for repository 'netget-live'. Its history is one commit, \
         'Initial commit', adding README with the text 'Hello from NetGet'. A client is \
         cloning; send it that history.",
        "hg_getbundle",
        json!({
            "repository": "netget-live",
            "heads": "",
            "common": "",
            "client_ip": "127.0.0.1"
        }),
    )
    .expect_action("hg_repository")
    .check(ParamCheck::custom(
        "commits",
        "is a non-empty array of commits with messages",
        |v| match v.as_array() {
            Some(commits)
                if !commits.is_empty()
                    && commits
                        .iter()
                        .all(|c| c.get("message").is_some_and(|m| m.is_string())) =>
            {
                Ok(())
            }
            _ => Err(format!("expected commits with messages, got {:?}", v)),
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// HLS / WebDAV
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hls_playlist_describes_segments() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "HLS",
        "You are an HLS server publishing a finished (VOD) stream of two \
         six-second segments, seg0.ts and seg1.ts. Answer the playlist request \
         by describing those segments.",
        "hls_playlist_request",
        json!({
            "peer_addr": "127.0.0.1:50301",
            "connection_id": "conn-1",
            "path": "/stream/index.m3u8",
            "method": "GET"
        }),
    )
    .expect_action("hls_playlist_response")
    .check(ParamCheck::custom(
        "segments",
        "lists both segments with durations",
        |v| {
            let segs = v
                .as_array()
                .ok_or_else(|| format!("segments must be an array, got {}", v))?;
            if segs.len() < 2 {
                return Err(format!("expected the two instructed segments, got {}", v));
            }
            for s in segs {
                if s["uri"].as_str().is_none() {
                    return Err(format!("each segment needs a uri: {}", s));
                }
                if s["duration"].as_f64().is_none() {
                    return Err(format!(
                        "each segment needs a duration, or #EXTINF cannot be written: {}",
                        s
                    ));
                }
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn hls_segment_returns_body_with_media_type() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "HLS",
        "You are an HLS server. A player is fetching the transport-stream \
         segment seg0.ts; return its body and say what media type it is.",
        "hls_segment_request",
        json!({
            "peer_addr": "127.0.0.1:50302",
            "connection_id": "conn-1",
            "path": "/stream/seg0.ts",
            "method": "GET"
        }),
    )
    .expect_action("hls_segment_response")
    .check(ParamCheck::custom(
        "content_type",
        "is the MPEG-TS media type a player expects",
        |v| {
            let s = v.as_str().unwrap_or("").to_lowercase();
            if s.contains("mp2t") || s.contains("mpeg") {
                Ok(())
            } else {
                Err(format!(
                    "expected video/mp2t for a .ts segment, got {:?}",
                    v
                ))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn webdav_propfind_lists_the_collection() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "WebDAV",
        "You are a WebDAV server. The root collection holds one folder, \
         documents, and one file, readme.txt. Answer a listing of the root, \
         echoing back the path that was asked for.",
        "webdav_request",
        json!({
            "method": "PROPFIND",
            "path": "/",
            "depth": "1",
            "destination": null,
            "overwrite": null,
            "headers": { "depth": "1", "content-type": "application/xml" },
            "body": "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>",
            "body_bytes": 92,
            "body_is_binary": false
        }),
    )
    .expect_action("send_webdav_listing")
    .check(ParamCheck::equals("path", json!("/")))
    .check(ParamCheck::custom(
        "entries",
        "lists both children of the collection",
        |v| {
            let entries = v
                .as_array()
                .ok_or_else(|| format!("entries must be an array, got {}", v))?;
            let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
            if names.contains(&"documents") && names.contains(&"readme.txt") {
                Ok(())
            } else {
                Err(format!(
                    "expected documents and readme.txt, got {:?}",
                    names
                ))
            }
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// MCP — every response is the JSON-RPC result object for that method.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_initialize_negotiates_capabilities() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server named netget-mcp at version 0.1.0, offering \
         resources, tools and prompts. Answer the client's initialize \
         handshake.",
        "mcp_initialize",
        json!({
            "method": "initialize",
            "client_info": { "name": "netget-live-client", "version": "1.0.0" },
            "protocol_version": "2024-11-05",
            "capabilities": {}
        }),
    )
    .expect_action("mcp_initialize_response")
    .check(ParamCheck::custom(
        "response",
        "carries protocolVersion, capabilities and serverInfo",
        |v| {
            for key in ["protocolVersion", "capabilities", "serverInfo"] {
                if v.get(key).is_none() {
                    return Err(format!(
                        "the initialize result must carry {} — a client aborts \
                         the handshake without it: {}",
                        key, v
                    ));
                }
            }
            if v["serverInfo"]["name"].as_str().is_none() {
                return Err(format!("serverInfo must name the server: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn mcp_tools_list_describes_input_schema() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server offering exactly one tool, calculate, which \
         evaluates a mathematical expression given as a string parameter named \
         expression. List your tools.",
        "mcp_tools_list",
        json!({ "method": "tools/list" }),
    )
    .expect_action("mcp_tools_list_response")
    .check(ParamCheck::custom(
        "response",
        "lists calculate with an input schema a client can call it from",
        |v| {
            let tools = v["tools"]
                .as_array()
                .ok_or_else(|| format!("the result must carry a tools array: {}", v))?;
            let tool = tools
                .iter()
                .find(|t| t["name"].as_str() == Some("calculate"))
                .ok_or_else(|| format!("no tool named calculate: {}", v))?;
            if tool["inputSchema"].is_null() {
                return Err(format!(
                    "a tool without an inputSchema cannot be called: {}",
                    tool
                ));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn mcp_tools_call_returns_content() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server offering the tool calculate, which evaluates the \
         expression it is given. A client is calling it with 2+2.",
        "mcp_tools_call",
        json!({
            "method": "tools/call",
            "name": "calculate",
            "arguments": { "expression": "2+2" }
        }),
    )
    .expect_action("mcp_tools_call_response")
    .check(ParamCheck::custom(
        "response",
        "returns the result as content blocks carrying 4",
        |v| {
            let content = v["content"]
                .as_array()
                .ok_or_else(|| format!("a tool result carries a content array: {}", v))?;
            if content.is_empty() {
                return Err(format!("the content array is empty: {}", v));
            }
            if !v.to_string().contains('4') {
                return Err(format!("2+2 should evaluate to 4: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn mcp_resources_list_describes_uris() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server exposing exactly one resource: the file \
         README.md, addressed as file:///README.md, which is markdown.",
        "mcp_resources_list",
        json!({ "method": "resources/list" }),
    )
    .expect_action("mcp_resources_list_response")
    .check(ParamCheck::custom(
        "response",
        "lists the resource by URI",
        |v| {
            let resources = v["resources"]
                .as_array()
                .ok_or_else(|| format!("the result must carry a resources array: {}", v))?;
            if resources
                .iter()
                .any(|r| r["uri"].as_str() == Some("file:///README.md"))
            {
                Ok(())
            } else {
                Err(format!("expected the resource file:///README.md: {}", v))
            }
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn mcp_resources_read_returns_contents() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server exposing file:///README.md, whose text is \
         '# netget live'. A client is reading it.",
        "mcp_resources_read",
        json!({ "method": "resources/read", "uri": "file:///README.md" }),
    )
    .expect_action("mcp_resources_read_response")
    .check(ParamCheck::custom(
        "response",
        "returns the contents of the requested URI",
        |v| {
            let contents = v["contents"]
                .as_array()
                .ok_or_else(|| format!("a read result carries a contents array: {}", v))?;
            let first = contents
                .first()
                .ok_or_else(|| format!("contents is empty: {}", v))?;
            if first["uri"].as_str() != Some("file:///README.md") {
                return Err(format!("the content must name the URI read: {}", first));
            }
            if !v.to_string().contains("netget live") {
                return Err(format!("expected the file's text: {}", v));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn mcp_prompts_list_describes_prompts() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server offering exactly one prompt, code-review, \
         described as 'Review a diff'. List your prompts.",
        "mcp_prompts_list",
        json!({ "method": "prompts/list" }),
    )
    .expect_action("mcp_prompts_list_response")
    .check(ParamCheck::custom("response", "lists code-review", |v| {
        let prompts = v["prompts"]
            .as_array()
            .ok_or_else(|| format!("the result must carry a prompts array: {}", v))?;
        if prompts
            .iter()
            .any(|p| p["name"].as_str() == Some("code-review"))
        {
            Ok(())
        } else {
            Err(format!("expected the prompt code-review: {}", v))
        }
    }))
    .run()
    .await
}

#[tokio::test]
async fn mcp_prompts_get_returns_messages() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "MCP",
        "You are an MCP server offering the prompt code-review, which asks the \
         model to review a diff. A client is fetching it, so return the \
         messages that make up the prompt.",
        "mcp_prompts_get",
        json!({
            "method": "prompts/get",
            "name": "code-review",
            "arguments": {}
        }),
    )
    .expect_action("mcp_prompts_get_response")
    .check(ParamCheck::custom(
        "response",
        "returns the prompt's messages with roles",
        |v| {
            let messages = v["messages"]
                .as_array()
                .ok_or_else(|| format!("a prompt result carries a messages array: {}", v))?;
            let first = messages
                .first()
                .ok_or_else(|| format!("messages is empty: {}", v))?;
            if first["role"].as_str().is_none() {
                return Err(format!("each message needs a role: {}", first));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

// ---------------------------------------------------------------------------
// BitTorrent tracker — compact must be echoed or real clients reject the reply.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tracker_announce_returns_peers_and_interval() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Torrent-Tracker",
        "You are a BitTorrent tracker. One other peer is on this torrent, at \
         127.0.0.1 port 51413, and it is a seed. Answer the announce, telling \
         the client to come back in 1800 seconds. The client asked for the \
         compact peer format, and the reply must use the format it asked for.",
        "tracker_announce_request",
        json!({
            "request_type": "announce",
            "path": "/announce",
            "info_hash": "123456789abcdef0123456789abcdef012345678",
            "compact": 1,
            "peer_id": "2d5452303030312d787878787878787878787878",
            "port": 51413,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "event": "started",
            "numwant": 50
        }),
    )
    .expect_action("send_announce_response")
    .check(ParamCheck::custom(
        "interval",
        "tells the client when to re-announce",
        |v| match v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        {
            Some(i) if i > 0 => Ok(()),
            _ => Err(format!(
                "interval must be a positive number of seconds, got {}",
                v
            )),
        },
    ))
    .check(ParamCheck::custom(
        "peers",
        "carries the peer that is on the torrent",
        |v| {
            let peers = v
                .as_array()
                .ok_or_else(|| format!("peers must be an array, got {}", v))?;
            let peer = peers
                .first()
                .ok_or_else(|| format!("expected the one known peer, got {}", v))?;
            if peer["port"].as_u64() != Some(51413) {
                return Err(format!("the peer's port must be the one given: {}", peer));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

#[tokio::test]
async fn tracker_scrape_is_keyed_by_info_hash() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "Torrent-Tracker",
        "You are a BitTorrent tracker. The torrent being scraped has one seed, \
         no leechers, and has been downloaded once. Answer the scrape; the \
         statistics are keyed by the torrent's info hash.",
        "tracker_scrape_request",
        json!({
            "request_type": "scrape",
            "path": "/scrape",
            "info_hash": "123456789abcdef0123456789abcdef012345678",
            "compact": 0
        }),
    )
    .expect_action("send_scrape_response")
    .check(ParamCheck::custom(
        "files",
        "is keyed by the requested info hash (other keys are dropped on the wire)",
        |v| {
            let obj = v
                .as_object()
                .ok_or_else(|| format!("files must be an object keyed by info hash, got {}", v))?;
            let entry = obj
                .get("123456789abcdef0123456789abcdef012345678")
                .ok_or_else(|| {
                    format!(
                        "no entry for the scraped info hash — a differently keyed \
                         entry is dropped and the client sees nothing: {}",
                        v
                    )
                })?;
            if entry["complete"].as_u64().is_none() {
                return Err(format!("each entry reports 'complete' (seeds): {}", entry));
            }
            Ok(())
        },
    ))
    .run()
    .await
}

/// RFC 7009 §2.2 fixes the revocation response: **200 whether or not the
/// token existed**, so an attacker cannot probe token validity through this
/// endpoint. netget sends that reply itself and the event is
/// `with_no_actions()` — so the model must not try to shape a response, and
/// the useful thing it can do is record the revocation.
#[tokio::test]
async fn oauth2_revoke_is_recorded_not_answered() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    EventCase::new(
        "oauth2",
        "You are an OAuth2 authorization server. Keep track of which tokens \
         have been revoked so you can stop honouring them later.",
        "oauth2_revoke",
        json!({
            "token": "ACCESS_netget7431",
            "token_type_hint": "access_token"
        }),
    )
    .expect_action("append_memory")
    .or_action("set_memory")
    .or_action("append_to_log")
    .check_action(|a| {
        if a.to_string().contains("ACCESS_netget7431") {
            Ok(())
        } else {
            Err(format!(
                "the note must name the revoked token (ACCESS_netget7431) or it cannot \
                 be honoured later; got {}",
                a
            ))
        }
    })
    .run()
    .await
}
