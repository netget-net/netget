//! OCI Distribution Specification v1.1 registry actions.
//!
//! # The content-addressability problem
//!
//! OCI is content-addressable: a manifest names its config and layer blobs by
//! `sha256:<hex>`, and every real client (crane, docker, skopeo, oras, containerd)
//! re-hashes the bytes it receives and rejects the image if the hash disagrees.
//! NetGet forbids a protocol from implementing storage, so there is no blob store
//! to hash at push time and read back at pull time.
//!
//! The resolution used here is **the server always computes, and never trusts**:
//!
//! - The model supplies *content*, never a digest-of-that-content. Every `sha256:`
//!   value NetGet puts on the wire is computed by [`sha256_digest`] over exactly the
//!   byte slice that is about to be written to the socket.
//! - `send_oci_manifest` optionally takes the config/layer/child-manifest content in
//!   its `blobs` array. [`apply_blob_descriptors`] overwrites each descriptor's
//!   `digest` and `size` with the real values, so the manifest is self-consistent by
//!   construction and any digest the model invented is discarded before it is hashed.
//! - If the model *does* volunteer a `digest` on `send_oci_blob`, it is verified
//!   against the computed one and a mismatch is an error — never a silent rewrite,
//!   never a pass-through.
//! - When a blob or a manifest is requested *by digest*, `mod.rs` compares the
//!   computed digest of the model's content against the digest the client asked for
//!   and refuses to serve on mismatch (404 `BLOB_UNKNOWN` / `MANIFEST_UNKNOWN`).
//!   That is deliberately fail-closed: serving bytes under the wrong name is exactly
//!   the failure the whole content-addressing scheme exists to prevent.
//!
//! The cost of having no storage is that the model must reproduce byte-identical
//! content when the same blob is fetched twice. Use a script or static event handler
//! (or server memory) for anything a real client will pull; an LLM asked to
//! re-emit the same gzip twice will not manage it.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::sync::LazyLock;
use tracing::{debug, error, warn};

/// Media type used for an image manifest that does not declare its own.
pub const DEFAULT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// Media type used for a manifest list / image index that does not declare its own.
pub const DEFAULT_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
/// Media type used for a config blob descriptor when nothing else says.
pub const DEFAULT_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
/// Media type used for a layer descriptor when nothing else says.
pub const DEFAULT_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// Media type used for a served blob when the action does not say.
pub const DEFAULT_BLOB_MEDIA_TYPE: &str = "application/octet-stream";
pub const MAX_ACTION_DEPTH: usize = 32;
pub const MAX_ACTION_NODES: usize = 65_536;
pub const MAX_ACTION_RETAINED_BYTES: usize = 8 * 1024 * 1024;

pub fn action_within_budget(value: &Value) -> bool {
    crate::utils::json_budget::within_budget(
        value,
        MAX_ACTION_RETAINED_BYTES,
        MAX_ACTION_NODES,
        MAX_ACTION_DEPTH,
    )
}

// ---------------------------------------------------------------------------
// Pure helpers. Public so `tests/server/oci_registry/` can exercise them
// directly — the repo forbids `#[cfg(test)] mod tests` inside `src/`.
// ---------------------------------------------------------------------------

/// `sha256:<lowercase hex>` over `bytes`.
///
/// This is the only place a digest is produced. Nothing in this protocol ever
/// takes a digest from the model and puts it on the wire unverified.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Decode a model-supplied content string according to its declared `encoding`.
///
/// The encodings documented on `send_oci_blob` and on `blobs[].encoding` are
/// exactly the ones decoded here — the `send_tcp_data` defect (documented as
/// hex-accepting, executor did `.as_bytes()`) is the reason this is spelled out.
///
/// `utf8` is the default and the right answer for config blobs, which are JSON.
pub fn decode_content(content: &str, encoding: &str) -> Result<Vec<u8>> {
    match encoding {
        "utf8" | "utf-8" | "text" => Ok(content.as_bytes().to_vec()),
        "hex" => {
            let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
            hex::decode(&cleaned).context("content declared encoding 'hex' but is not valid hex")
        }
        "base64" => {
            let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .context("content declared encoding 'base64' but is not valid base64")
        }
        other => bail!(
            "unknown encoding '{}': expected \"utf8\" (default), \"hex\" or \"base64\"",
            other
        ),
    }
}

/// Decide the `Content-Type` for a manifest response.
///
/// The document's own `mediaType` wins, because those bytes are what the client
/// hashes and parses — a `Content-Type` that disagrees with the embedded
/// `mediaType` is what makes clients reject an otherwise valid image. Failing
/// that, an explicit `media_type` action parameter is used, and failing that the
/// shape decides: a document with a `manifests` array is an index, anything else
/// is an image manifest.
pub fn manifest_media_type(manifest: &Value, explicit: Option<&str>) -> String {
    if let Some(mt) = manifest.get("mediaType").and_then(|v| v.as_str()) {
        if !mt.is_empty() {
            return mt.to_string();
        }
    }
    if let Some(mt) = explicit {
        if !mt.is_empty() {
            return mt.to_string();
        }
    }
    if manifest
        .get("manifests")
        .and_then(|v| v.as_array())
        .is_some()
    {
        DEFAULT_INDEX_MEDIA_TYPE.to_string()
    } else {
        DEFAULT_MANIFEST_MEDIA_TYPE.to_string()
    }
}

/// HTTP status for an OCI error code (spec §Error Codes), used when the model
/// does not pin one explicitly.
pub fn oci_error_status(code: &str) -> u16 {
    match code.to_ascii_uppercase().as_str() {
        "BLOB_UNKNOWN" | "MANIFEST_UNKNOWN" | "NAME_UNKNOWN" => 404,
        "UNAUTHORIZED" => 401,
        "DENIED" => 403,
        "UNSUPPORTED" => 405,
        "TOOMANYREQUESTS" => 429,
        "MANIFEST_BLOB_UNKNOWN"
        | "MANIFEST_INVALID"
        | "NAME_INVALID"
        | "DIGEST_INVALID"
        | "SIZE_INVALID"
        | "TAG_INVALID"
        | "BLOB_UPLOAD_INVALID"
        | "BLOB_UPLOAD_UNKNOWN" => 400,
        _ => 500,
    }
}

/// Render the OCI error envelope: `{"errors":[{"code":…,"message":…,"detail":…}]}`.
pub fn oci_error_body(code: &str, message: &str, detail: Option<&Value>) -> String {
    let mut err = json!({
        "code": code.to_ascii_uppercase(),
        "message": message,
    });
    if let Some(d) = detail {
        err["detail"] = d.clone();
    }
    json!({ "errors": [err] }).to_string()
}

/// A blob whose bytes and digest have been resolved from model-supplied content.
#[derive(Clone, Debug)]
pub struct ResolvedBlob {
    /// `"config"`, `"layer"` or `"manifest"` — which descriptor slot it fills.
    pub role: String,
    /// Media type for the descriptor, if the model gave one.
    pub media_type: Option<String>,
    /// Decoded bytes.
    pub bytes: Vec<u8>,
    /// `sha256:…` computed over `bytes`.
    pub digest: String,
}

/// Turn the `blobs` array of `send_oci_manifest` into resolved, hashed blobs.
pub fn resolve_blobs(blobs: &[Value]) -> Result<Vec<ResolvedBlob>> {
    let mut out = Vec::with_capacity(blobs.len());
    for (i, b) in blobs.iter().enumerate() {
        let obj = b
            .as_object()
            .ok_or_else(|| anyhow!("blobs[{}] must be an object", i))?;
        let role = obj
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("layer")
            .to_ascii_lowercase();
        if !matches!(role.as_str(), "config" | "layer" | "manifest") {
            bail!(
                "blobs[{}].role must be \"config\", \"layer\" or \"manifest\", got \"{}\"",
                i,
                role
            );
        }
        let content = obj
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("blobs[{}] requires a string 'content' field", i))?;
        let encoding = obj
            .get("encoding")
            .and_then(|v| v.as_str())
            .unwrap_or("utf8");
        let bytes = decode_content(content, encoding)
            .with_context(|| format!("blobs[{}] could not be decoded", i))?;
        let digest = sha256_digest(&bytes);
        out.push(ResolvedBlob {
            role,
            media_type: obj
                .get("media_type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            bytes,
            digest,
        });
    }
    Ok(out)
}

/// Build one descriptor, preserving whatever the model already wrote there
/// (`annotations`, `urls`, `platform`) but overwriting `digest` and `size` with
/// the computed values.
fn descriptor(existing: Option<&Value>, blob: &ResolvedBlob, default_media_type: &str) -> Value {
    let mut d = existing
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let media_type = blob
        .media_type
        .clone()
        .or_else(|| {
            d.get("mediaType")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| default_media_type.to_string());
    d.insert("mediaType".into(), json!(media_type));
    d.insert("digest".into(), json!(blob.digest));
    d.insert("size".into(), json!(blob.bytes.len()));
    Value::Object(d)
}

/// Overwrite the manifest's `config`, `layers[]` and `manifests[]` descriptors with
/// digests and sizes computed from the supplied blob content.
///
/// This is what makes an LLM-authored manifest verifiable: whatever the model wrote
/// in a `digest` field is replaced before the manifest is serialized and hashed, so
/// the descriptors and the blobs the registry will later serve cannot disagree.
///
/// Descriptors with no matching blob are left alone and reported in the returned
/// warning list — they will still fail digest verification when the client fetches
/// them, which is correct, but the operator deserves to be told why.
pub fn apply_blob_descriptors(manifest: &mut Value, blobs: &[ResolvedBlob]) -> Result<Vec<String>> {
    if !action_within_budget(manifest) {
        bail!("OCI manifest depth/node/retained-content limit");
    }
    if !manifest.is_object() {
        bail!("manifest must be a JSON object");
    }
    let mut warnings = Vec::new();

    let configs: Vec<&ResolvedBlob> = blobs.iter().filter(|b| b.role == "config").collect();
    if configs.len() > 1 {
        bail!(
            "at most one blob may have role \"config\", got {}",
            configs.len()
        );
    }
    if let Some(cfg) = configs.first() {
        let existing = manifest.get("config").cloned();
        manifest["config"] = descriptor(existing.as_ref(), cfg, DEFAULT_CONFIG_MEDIA_TYPE);
    } else if manifest.get("config").is_some() {
        warnings.push(
            "manifest declares a config descriptor but no blob with role \"config\" was supplied; \
             its digest is unverified and a client fetching it will be refused"
                .to_string(),
        );
    }

    for (key, role, default_mt) in [
        ("layers", "layer", DEFAULT_LAYER_MEDIA_TYPE),
        ("manifests", "manifest", DEFAULT_MANIFEST_MEDIA_TYPE),
    ] {
        let supplied: Vec<&ResolvedBlob> = blobs.iter().filter(|b| b.role == role).collect();
        let declared = manifest
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if supplied.is_empty() {
            if declared > 0 {
                warnings.push(format!(
                    "manifest declares {} entr(y|ies) in \"{}\" but no blob with role \"{}\" was \
                     supplied; those digests are unverified and clients fetching them will be refused",
                    declared, key, role
                ));
            }
            continue;
        }
        let mut arr = manifest
            .get(key)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for (i, blob) in supplied.iter().enumerate() {
            let existing = arr.get(i).cloned();
            let d = descriptor(existing.as_ref(), blob, default_mt);
            if i < arr.len() {
                arr[i] = d;
            } else {
                arr.push(d);
            }
        }
        if declared > supplied.len() {
            warnings.push(format!(
                "manifest declares {} entr(y|ies) in \"{}\" but only {} blob(s) with role \"{}\" \
                 were supplied; the remainder keep unverified digests",
                declared,
                key,
                supplied.len(),
                role
            ));
        }
        manifest[key] = Value::Array(arr);
    }

    Ok(warnings)
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// Emitted for `GET|HEAD /v2/` **only when the `version_check` startup parameter is
/// `"llm"`**. The default (`"auto"`) answers the probe in-process without an LLM
/// call, because every client sends it before every other request. See
/// `src/server/oci_registry/CLAUDE.md`.
pub static OCI_VERSION_CHECK: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oci_version_check",
        "Client probed GET /v2/ to discover whether this is an OCI registry v2 endpoint \
         and whether it needs a token. Answer send_oci_version_ok to admit anonymous \
         pulls, or send_oci_auth_challenge to demand a bearer token.",
        json!({"type": "send_oci_version_ok"}),
    )
    .with_actions(vec![
        version_ok_action(),
        auth_challenge_action(),
        oci_error_action(),
    ])
});

/// Emitted for `GET|HEAD /v2/_catalog`.
pub static OCI_CATALOG_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oci_catalog_request",
        "Client requested the repository catalog (GET /v2/_catalog). Decide which \
         repositories this registry claims to host.",
        json!({"type": "send_oci_catalog", "repositories": ["library/alpine", "team/api"]}),
    )
    .with_actions(vec![
        catalog_action(),
        auth_challenge_action(),
        oci_error_action(),
    ])
});

/// Emitted for `GET|HEAD /v2/{name}/tags/list`.
pub static OCI_TAGS_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oci_tags_request",
        "Client requested the tag list for a repository (GET /v2/{name}/tags/list). \
         Decide which tags exist, or reject the repository with NAME_UNKNOWN.",
        json!({"type": "send_oci_tags", "tags": ["latest", "1.0", "1.0.3"]}),
    )
    .with_actions(vec![
        tags_action(),
        auth_challenge_action(),
        oci_error_action(),
    ])
});

/// Emitted for `GET|HEAD /v2/{name}/manifests/{reference}` (tag or digest).
pub static OCI_MANIFEST_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oci_manifest_request",
        "Client requested an image manifest or index by tag or by digest \
         (GET /v2/{name}/manifests/{reference}). Author the manifest document and, \
         where possible, supply the config/layer content in 'blobs' so NetGet can \
         write real SHA-256 digests into the descriptors.",
        json!({
            "type": "send_oci_manifest",
            "manifest": {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json"},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]
            },
            "blobs": [
                {"role": "config", "content": "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}"},
                {"role": "layer", "content": "hello from a fake layer"}
            ]
        }),
    )
    .with_actions(vec![
        manifest_action(),
        auth_challenge_action(),
        oci_error_action(),
    ])
});

/// Emitted for `GET|HEAD /v2/{name}/blobs/{digest}`.
pub static OCI_BLOB_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oci_blob_request",
        "Client requested a blob by digest (GET /v2/{name}/blobs/{digest}). Return the \
         exact content whose SHA-256 is that digest — NetGet re-hashes what you return \
         and refuses to serve it under a digest it does not match.",
        json!({
            "type": "send_oci_blob",
            "content": "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}",
            "encoding": "utf8",
            "media_type": "application/vnd.oci.image.config.v1+json"
        }),
    )
    .with_actions(vec![
        blob_action(),
        auth_challenge_action(),
        oci_error_action(),
    ])
});

/// Every event this protocol can emit. Clones of the statics `mod.rs` raises, so the
/// documented catalog and the action list `call_llm` advertises cannot drift.
pub fn get_oci_registry_event_types() -> Vec<EventType> {
    vec![
        OCI_VERSION_CHECK.clone(),
        OCI_CATALOG_REQUEST.clone(),
        OCI_TAGS_REQUEST.clone(),
        OCI_MANIFEST_REQUEST.clone(),
        OCI_BLOB_REQUEST.clone(),
    ]
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// OCI Distribution v2 registry protocol (pull path).
pub struct OciRegistryProtocol {}

impl Default for OciRegistryProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl OciRegistryProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl Protocol for OciRegistryProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            version_ok_action(),
            catalog_action(),
            tags_action(),
            manifest_action(),
            blob_action(),
            auth_challenge_action(),
            oci_error_action(),
        ]
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "version_check".to_string(),
            type_hint: "string".to_string(),
            description:
                "How GET /v2/ (the API version probe every client sends before every other \
                 request) is answered. \"auto\" (default) replies 200 with \
                 Docker-Distribution-Api-Version: registry/2.0 in-process, costing no LLM call. \
                 \"llm\" raises the oci_version_check event instead, so the model can demand a \
                 bearer token with send_oci_auth_challenge."
                    .to_string(),
            required: false,
            example: json!("auto"),
            default: None,
        }]
    }

    fn protocol_name(&self) -> &'static str {
        "OCI-Registry"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_oci_registry_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OCI"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately multi-word. A bare "registry", "docker" or "image" would
        // swallow unrelated prompts the way the BLE profiles' "file"/"transfer"
        // did to FTP and NFS.
        vec![
            "oci registry",
            "oci distribution",
            "container registry",
            "docker registry",
            "image registry",
            "registry v2",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(5000)
            .implementation(
                "hyper HTTP/1.1 server implementing the OCI Distribution Spec v1.1 pull path: \
                 GET/HEAD /v2/, /v2/_catalog, /v2/{name}/tags/list, /v2/{name}/manifests/{ref} \
                 (tag or digest) and /v2/{name}/blobs/{digest}, with Docker-Content-Digest, \
                 media-type selection for manifest vs index, and OCI error envelopes",
            )
            .llm_control(
                "The model invents the repository catalog, tag lists, manifest and index \
                 documents, and blob content, and may demand a bearer token. It never supplies \
                 digests: NetGet computes every sha256 over the exact bytes it serves and \
                 refuses to serve content whose hash does not match the digest requested",
            )
            .e2e_testing(
                "Validated against crane (google/go-containerregistry) over plain HTTP on \
                 127.0.0.1 in \
                 tests/server/oci_registry/e2e_test.rs::test_oci_registry_against_crane, \
                 which is not #[ignore]d and now FAILS rather than skips when crane is \
                 absent - until September 2026 it printed \"crane not installed - skipping\" \
                 and returned Ok(()), so this claim rested on a test that passed vacuously \
                 wherever crane was missing: crane catalog, crane ls, \
                 crane manifest (by tag and by the digest crane itself computed), crane digest, \
                 crane config and crane blob all succeed, and crane's own re-hashing of every \
                 manifest and blob it fetches is the assertion. Mocked E2E in \
                 tests/server/oci_registry/e2e_test.rs drives the same endpoints with reqwest \
                 and cross-checks Docker-Content-Digest against `shasum -a 256`; \
                 tests/server/oci_registry/digest_test.rs pins digests to known answers from \
                 the same external oracle",
            )
            .notes(
                "PULL ONLY. Push (POST/PATCH/PUT blob uploads and manifest PUT) is not \
                 implemented and returns 405 with an UNSUPPORTED error envelope rather than \
                 pretending to accept an upload it could never serve back — a registry with no \
                 storage cannot honour a push. Referrers (/v2/{name}/referrers/{digest}) is \
                 likewise 404 UNSUPPORTED, which the spec permits. Only sha256 digests are \
                 supported; any other algorithm is rejected with DIGEST_INVALID. Untested \
                 against docker and containerd (both need an insecure-registries daemon entry, \
                 and no docker daemon was running on the validation machine) and against \
                 skopeo and oras, neither of which is installed there. \
                 Because there is no blob store, the model must return byte-identical content \
                 each time a blob is fetched — use a script or static handler for anything a \
                 real client will pull.",
            )
            .request_only("The OCI registry API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "OCI/Docker container registry (Distribution API v2) with LLM-invented images"
    }

    fn example_prompt(&self) -> &'static str {
        "Be an OCI registry on port 5000 hosting library/alpine with tags latest and 3.20"
    }

    fn group_name(&self) -> &'static str {
        "Package Management"
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 5000,
                "base_stack": "oci_registry",
                "instruction": "You are an OCI container registry. Host one repository, \
                    library/alpine, with tags 'latest' and '3.20'. For a manifest request \
                    return an OCI image manifest and supply the config JSON and a single \
                    text layer in 'blobs' so the digests are real. For a blob request return \
                    exactly the same content you supplied in the manifest."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 5000,
                "base_stack": "oci_registry",
                "event_handlers": [{
                    "event_pattern": "oci_catalog_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return [{'type': 'send_oci_catalog', 'repositories': ['library/alpine']}]"
                    }
                }, {
                    "event_pattern": "oci_tags_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return [{'type': 'send_oci_tags', 'tags': ['latest', '3.20']}]"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 5000,
                "base_stack": "oci_registry",
                "event_handlers": [{
                    "event_pattern": "oci_tags_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_oci_tags",
                            "tags": ["latest", "3.20"]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for OciRegistryProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::server::oci_registry::OciRegistryServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        if !action_within_budget(&action) {
            crate::utils::json_budget::drop_iteratively(action);
            bail!("OCI action depth/node/retained-content limit");
        }
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_oci_version_ok" => Ok(ActionResult::Custom {
                name: "oci_version_ok".to_string(),
                data: json!({}),
            }),
            "send_oci_auth_challenge" => execute_auth_challenge(&action),
            "send_oci_catalog" => execute_catalog(&action),
            "send_oci_tags" => execute_tags(&action),
            "send_oci_manifest" => execute_manifest(&action),
            "send_oci_blob" => execute_blob(&action),
            "send_oci_error" => execute_error(&action),
            other => Err(anyhow!("Unknown OCI registry action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

fn execute_auth_challenge(action: &Value) -> Result<ActionResult> {
    let realm = action
        .get("realm")
        .and_then(|v| v.as_str())
        .context("send_oci_auth_challenge requires a 'realm' URL")?;
    Ok(ActionResult::Custom {
        name: "oci_auth_challenge".to_string(),
        data: json!({
            "realm": realm,
            "service": action.get("service").and_then(|v| v.as_str()),
            "scope": action.get("scope").and_then(|v| v.as_str()),
            "message": action.get("message").and_then(|v| v.as_str())
                .unwrap_or("authentication required"),
        }),
    })
}

fn execute_catalog(action: &Value) -> Result<ActionResult> {
    let repositories = action
        .get("repositories")
        .and_then(|v| v.as_array())
        .context("send_oci_catalog requires a 'repositories' array of strings")?;
    let repos: Vec<String> = repositories
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    debug!("OCI catalog: {} repositories", repos.len());
    Ok(ActionResult::Custom {
        name: "oci_catalog".to_string(),
        data: json!({
            "repositories": repos,
            "next_last": action.get("next_last").and_then(|v| v.as_str()),
        }),
    })
}

fn execute_tags(action: &Value) -> Result<ActionResult> {
    let tags = action
        .get("tags")
        .and_then(|v| v.as_array())
        .context("send_oci_tags requires a 'tags' array of strings")?;
    let tags: Vec<String> = tags
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    debug!("OCI tags: {} tags", tags.len());
    Ok(ActionResult::Custom {
        name: "oci_tags".to_string(),
        data: json!({
            "name": action.get("name").and_then(|v| v.as_str()),
            "tags": tags,
        }),
    })
}

/// Build the manifest bytes and their real digest.
///
/// `manifest` may be a JSON object (the normal case) or a JSON string. A string is
/// served **verbatim** so its bytes — and therefore its digest — are exactly what the
/// model wrote, which matters when reproducing a manifest captured from a real
/// registry. Supplying `blobs` alongside a string forces a re-serialize, because the
/// descriptors have to be rewritten.
fn execute_manifest(action: &Value) -> Result<ActionResult> {
    let raw = action
        .get("manifest")
        .context("send_oci_manifest requires a 'manifest' object (or a JSON string)")?;

    let blobs = match action.get("blobs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => resolve_blobs(a)?,
        Some(other) => bail!("send_oci_manifest 'blobs' must be an array, got {}", other),
    };

    let (mut doc, verbatim) = match raw {
        Value::String(s) => {
            let parsed: Value = serde_json::from_str(s)
                .context("send_oci_manifest 'manifest' was a string but is not valid JSON")?;
            (parsed, Some(s.clone()))
        }
        Value::Object(_) => (raw.clone(), None),
        other => bail!(
            "send_oci_manifest 'manifest' must be an object or a JSON string, got {}",
            other
        ),
    };

    if !action_within_budget(&doc) {
        crate::utils::json_budget::drop_iteratively(doc);
        bail!("OCI manifest depth/node/retained-content limit");
    }
    let body = if let (Some(text), true) = (verbatim.as_ref(), blobs.is_empty()) {
        // Byte-exact passthrough: nothing to rewrite.
        text.clone()
    } else {
        let warnings = apply_blob_descriptors(&mut doc, &blobs)?;
        for w in &warnings {
            warn!("OCI manifest: {}", w);
        }
        serde_json::to_string(&doc).context("manifest could not be serialized")?
    };

    // The digest is computed over exactly the bytes that will be written to the
    // socket, so it cannot be wrong by construction.
    let digest = sha256_digest(body.as_bytes());
    let media_type = manifest_media_type(&doc, action.get("media_type").and_then(|v| v.as_str()));

    debug!(
        "OCI manifest: {} bytes, {}, {}",
        body.len(),
        media_type,
        digest
    );

    Ok(ActionResult::Custom {
        name: "oci_manifest".to_string(),
        data: json!({
            "body": body,
            "digest": digest,
            "media_type": media_type,
        }),
    })
}

fn execute_blob(action: &Value) -> Result<ActionResult> {
    let content = action
        .get("content")
        .and_then(|v| v.as_str())
        .context("send_oci_blob requires a string 'content' field")?;
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");
    let bytes = decode_content(content, encoding)?;
    let digest = sha256_digest(&bytes);

    // A digest volunteered by the model is *verified*, never trusted and never
    // silently replaced. Fail-closed: an inconsistent action produces no response
    // rather than a response served under the wrong name.
    if let Some(claimed) = action.get("digest").and_then(|v| v.as_str()) {
        if !claimed.eq_ignore_ascii_case(&digest) {
            error!(
                "send_oci_blob claimed digest {} but its content hashes to {}; refusing",
                claimed, digest
            );
            bail!(
                "send_oci_blob claimed digest {} but the supplied content hashes to {}. \
                 Do not compute digests yourself — return the content and NetGet will hash it.",
                claimed,
                digest
            );
        }
    }

    debug!("OCI blob: {} bytes, {}", bytes.len(), digest);

    Ok(ActionResult::Custom {
        name: "oci_blob".to_string(),
        data: json!({
            // Internal plumbing only: ActionResult data is JSON, and a blob may be
            // binary. This is not a model-facing field.
            "body_hex": hex::encode(&bytes),
            "digest": digest,
            "media_type": action.get("media_type").and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_BLOB_MEDIA_TYPE),
        }),
    })
}

fn execute_error(action: &Value) -> Result<ActionResult> {
    let code = action
        .get("code")
        .and_then(|v| v.as_str())
        .context("send_oci_error requires a 'code' (e.g. MANIFEST_UNKNOWN)")?
        .to_ascii_uppercase();
    let message = action
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("request refused")
        .to_string();
    // Range-checked, not truncated. `as u16` silently wraps: a model answering
    // `status: 65736` would have produced a **200**, so an explicit refusal would
    // have reached crane as a success carrying an error envelope in the body — the
    // fail-open shape, arrived at by arithmetic. Refuse the action instead; the
    // message goes back to the model, which can retry.
    let status = match action.get("status").and_then(|v| v.as_u64()) {
        None => oci_error_status(&code),
        Some(s) if (400..=599).contains(&s) => s as u16,
        Some(s) => bail!(
            "send_oci_error status {} is not an HTTP error status (400-599). An error \
             envelope must not be served under a 2xx: the client would read it as success.",
            s
        ),
    };
    Ok(ActionResult::Custom {
        name: "oci_error".to_string(),
        data: json!({
            "code": code,
            "message": message,
            "detail": action.get("detail").cloned(),
            "status": status,
        }),
    })
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn version_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_version_ok".to_string(),
        description: "Confirm this endpoint implements the OCI Distribution API v2 and allows \
                      anonymous access (200 with Docker-Distribution-Api-Version: registry/2.0)"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "send_oci_version_ok"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI /v2/ 200 (anonymous)")
                .with_debug("OCI send_oci_version_ok: API version probe accepted"),
        ),
    }
}

fn auth_challenge_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_auth_challenge".to_string(),
        description: "Refuse the request with 401 and a WWW-Authenticate Bearer challenge, \
                      telling the client where to get a token. Use this to make clients \
                      exercise the token-auth flow."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "realm".to_string(),
                type_hint: "string".to_string(),
                description: "Token endpoint URL the client should authenticate against"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "service".to_string(),
                type_hint: "string".to_string(),
                description: "Service name for the token request".to_string(),
                required: false,
            },
            Parameter {
                name: "scope".to_string(),
                type_hint: "string".to_string(),
                description: "Scope the client should request, e.g. \
                              \"repository:library/alpine:pull\""
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable reason placed in the error envelope".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_oci_auth_challenge",
            "realm": "https://auth.example.com/token",
            "service": "registry.example.com",
            "scope": "repository:library/alpine:pull"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI 401 auth challenge (realm={realm})")
                .with_debug("OCI send_oci_auth_challenge: realm={realm} scope={scope}"),
        ),
    }
}

fn catalog_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_catalog".to_string(),
        description: "Return the repository catalog for GET /v2/_catalog".to_string(),
        parameters: vec![
            Parameter {
                name: "repositories".to_string(),
                type_hint: "array".to_string(),
                description: "Repository names, lowercase, slash-separated \
                              (e.g. [\"library/alpine\", \"team/api\"])"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "next_last".to_string(),
                type_hint: "string".to_string(),
                description: "If the catalog is paginated, the repository name to continue \
                              from; emitted as a RFC 5988 Link header"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_oci_catalog",
            "repositories": ["library/alpine", "team/api"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI catalog")
                .with_debug("OCI send_oci_catalog: repository listing returned"),
        ),
    }
}

fn tags_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_tags".to_string(),
        description: "Return the tag list for GET /v2/{name}/tags/list".to_string(),
        parameters: vec![
            Parameter {
                name: "tags".to_string(),
                type_hint: "array".to_string(),
                description: "Tag names for this repository (e.g. [\"latest\", \"3.20\"])"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "Repository name echoed in the response; defaults to the one \
                              the client asked for"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_oci_tags", "tags": ["latest", "3.20"]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI tag list")
                .with_debug("OCI send_oci_tags: tag listing returned"),
        ),
    }
}

fn manifest_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_manifest".to_string(),
        description: "Return an image manifest or image index. NetGet serializes the document, \
                      hashes exactly those bytes, and sets Docker-Content-Digest from the \
                      result — never write a 'digest' yourself. Supply the referenced content \
                      in 'blobs' and NetGet rewrites each descriptor's digest and size with the \
                      real values, which is what makes the image pullable by a real client."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "manifest".to_string(),
                type_hint: "object".to_string(),
                description: "The manifest document: schemaVersion 2, mediaType, config \
                              descriptor and layers array (or a manifests array for an index). \
                              Digest and size fields may be omitted — they are computed."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "blobs".to_string(),
                type_hint: "array".to_string(),
                description: "Content for the descriptors, in order. Each entry is \
                              {role, content, encoding, media_type}: role is \"config\", \
                              \"layer\" or \"manifest\" (index children); content is the blob \
                              text; encoding is \"utf8\" (default), \"hex\" or \"base64\". \
                              Omitting this leaves descriptor digests unverified and any \
                              client fetching those blobs will be refused."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "media_type".to_string(),
                type_hint: "string".to_string(),
                description: "Content-Type override, used only when the manifest document \
                              itself carries no mediaType field"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_oci_manifest",
            "manifest": {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json"},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]
            },
            "blobs": [
                {"role": "config", "content": "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}"},
                {"role": "layer", "content": "hello from a fake layer"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI manifest")
                .with_debug("OCI send_oci_manifest: manifest built and hashed"),
        ),
    }
}

fn blob_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_blob".to_string(),
        description: "Return the content of a blob. NetGet hashes what you return and serves it \
                      only if the hash equals the digest the client asked for, so this must be \
                      byte-identical to the content the manifest was built from."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "The blob content. Config blobs are JSON text; use \"utf8\"."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to decode 'content': \"utf8\" (default), \"hex\" or \
                              \"base64\". All three are decoded by the executor."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "media_type".to_string(),
                type_hint: "string".to_string(),
                description: "Content-Type for the blob (default application/octet-stream)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_oci_blob",
            "content": "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}",
            "encoding": "utf8",
            "media_type": "application/vnd.oci.image.config.v1+json"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI blob")
                .with_debug("OCI send_oci_blob: blob content hashed and returned"),
        ),
    }
}

fn oci_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_oci_error".to_string(),
        description: "Refuse the request with an OCI error envelope. This is the correct answer \
                      for a repository, tag, digest or image this registry does not have."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "OCI error code: NAME_UNKNOWN, MANIFEST_UNKNOWN, BLOB_UNKNOWN, \
                              UNAUTHORIZED, DENIED, UNSUPPORTED, TOOMANYREQUESTS, \
                              NAME_INVALID, DIGEST_INVALID, MANIFEST_INVALID"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable explanation".to_string(),
                required: false,
            },
            Parameter {
                name: "detail".to_string(),
                type_hint: "object".to_string(),
                description: "Structured detail placed in the error object".to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status override; defaults to the status the spec assigns \
                              the code (404 for *_UNKNOWN, 401 UNAUTHORIZED, 403 DENIED)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_oci_error",
            "code": "MANIFEST_UNKNOWN",
            "message": "manifest unknown to this registry"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OCI error {status}: {code}")
                .with_debug("OCI send_oci_error: status={status} code={code} message={message}"),
        ),
    }
}
