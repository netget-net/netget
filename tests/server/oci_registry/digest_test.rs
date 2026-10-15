//! Pure protocol-logic tests for the OCI registry server.
//!
//! Nothing here opens a socket or calls a model. It covers the three things that
//! decide whether a real client will accept what NetGet serves:
//!
//! 1. digests are the real SHA-256 of the bytes,
//! 2. `/v2/…` paths with slash-containing repository names parse correctly,
//! 3. `apply_blob_descriptors` **overwrites** whatever digest the model invented.
//!
//! The expected digests are known answers produced by Apple's `shasum -a 256`, not
//! by NetGet, so this does not check an implementation against itself.


use netget::server::oci_registry::actions::{
    apply_blob_descriptors, decode_content, manifest_media_type, oci_error_body, oci_error_status,
    resolve_blobs, sha256_digest,
};
use netget::server::oci_registry::{
    is_digest_reference, is_valid_repository_name, parse_v2_path, validate_sha256_digest, OciRoute,
    VersionCheckMode,
};
use serde_json::json;

/// Config blob used by the whole suite. Byte-for-byte what `e2e_test.rs` serves.
pub const CONFIG_JSON: &str = r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}}"#;
/// `shasum -a 256` of [`CONFIG_JSON`].
pub const CONFIG_DIGEST: &str =
    "sha256:f1c6cdd9970ec550cf99058a66cec4d54374db8772997cac592b570e38669f28";
/// Layer blob used by the whole suite.
pub const LAYER_TEXT: &str = "netget synthetic layer payload";
/// `shasum -a 256` of [`LAYER_TEXT`].
pub const LAYER_DIGEST: &str =
    "sha256:63d58752a83bb4a1a9ea58242bf5a24af121fafd0c136df04bb505c9d95a0f34";

#[test]
fn sha256_matches_an_external_oracle() {
    // Known answers from `shasum -a 256`, an implementation NetGet does not own.
    assert_eq!(CONFIG_JSON.len(), 151, "fixture drifted");
    assert_eq!(LAYER_TEXT.len(), 30, "fixture drifted");
    assert_eq!(sha256_digest(CONFIG_JSON.as_bytes()), CONFIG_DIGEST);
    assert_eq!(sha256_digest(LAYER_TEXT.as_bytes()), LAYER_DIGEST);
    // RFC 6234 / NIST empty-string vector.
    assert_eq!(
        sha256_digest(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn every_documented_encoding_is_actually_decoded() {
    // The `send_tcp_data` defect was an encoding documented but never decoded.
    // Each of these is named in `send_oci_blob`'s parameter docs.
    assert_eq!(decode_content("hi", "utf8").unwrap(), b"hi");
    assert_eq!(decode_content("hi", "utf-8").unwrap(), b"hi");
    assert_eq!(decode_content("68 69", "hex").unwrap(), b"hi");
    assert_eq!(decode_content("aGk=", "base64").unwrap(), b"hi");
    // Binary that no UTF-8 string could carry.
    assert_eq!(
        decode_content("00ff80", "hex").unwrap(),
        vec![0x00, 0xff, 0x80]
    );
    assert!(decode_content("zz", "hex").is_err());
    assert!(decode_content("hi", "rot13").is_err());
}

#[test]
fn v2_paths_parse_with_slash_containing_repository_names() {
    assert_eq!(parse_v2_path("/v2/"), Some(OciRoute::VersionCheck));
    assert_eq!(parse_v2_path("/v2"), Some(OciRoute::VersionCheck));
    assert_eq!(parse_v2_path("/v2/_catalog"), Some(OciRoute::Catalog));

    assert_eq!(
        parse_v2_path("/v2/library/alpine/tags/list"),
        Some(OciRoute::TagsList {
            name: "library/alpine".into()
        })
    );
    assert_eq!(
        parse_v2_path("/v2/a/b/c/manifests/latest"),
        Some(OciRoute::Manifest {
            name: "a/b/c".into(),
            reference: "latest".into()
        })
    );
    assert_eq!(
        parse_v2_path(&format!("/v2/library/alpine/manifests/{}", CONFIG_DIGEST)),
        Some(OciRoute::Manifest {
            name: "library/alpine".into(),
            reference: CONFIG_DIGEST.into()
        })
    );
    assert_eq!(
        parse_v2_path(&format!("/v2/library/alpine/blobs/{}", LAYER_DIGEST)),
        Some(OciRoute::Blob {
            name: "library/alpine".into(),
            digest: LAYER_DIGEST.into()
        })
    );

    // "/blobs/uploads/" contains "/blobs/" — the push route must win, or a push
    // would be misread as a pull of a blob named "uploads".
    assert_eq!(
        parse_v2_path("/v2/library/alpine/blobs/uploads/"),
        Some(OciRoute::BlobUpload {
            name: "library/alpine".into()
        })
    );
    assert_eq!(
        parse_v2_path("/v2/library/alpine/blobs/uploads/abc-123"),
        Some(OciRoute::BlobUpload {
            name: "library/alpine".into()
        })
    );

    // A repository component may legitimately be called "manifests"; rfind means
    // the *last* separator wins, which is what real registries do.
    assert_eq!(
        parse_v2_path("/v2/manifests/manifests/manifests/v1"),
        Some(OciRoute::Manifest {
            name: "manifests/manifests".into(),
            reference: "v1".into()
        })
    );

    assert_eq!(parse_v2_path("/v1/library/alpine"), None);
    assert_eq!(parse_v2_path("/"), None);
}

#[test]
fn repository_names_follow_the_spec_grammar() {
    assert!(is_valid_repository_name("alpine"));
    assert!(is_valid_repository_name("library/alpine"));
    assert!(is_valid_repository_name("a/b/c"));
    assert!(is_valid_repository_name("my-repo.name_1"));
    for name in ["a__b", "a---b", "a._b", "a..b", "a___b"] {
        assert_eq!(
            is_valid_repository_name(name),
            matches!(name, "a__b" | "a---b")
        );
    }

    assert!(!is_valid_repository_name(""));
    assert!(!is_valid_repository_name("Library/Alpine")); // uppercase
    assert!(!is_valid_repository_name("library//alpine")); // empty component
    assert!(!is_valid_repository_name("/alpine"));
    assert!(!is_valid_repository_name("-alpine")); // must start alphanumeric
    assert!(!is_valid_repository_name("alpine-")); // must end alphanumeric
    assert!(!is_valid_repository_name("alpine!"));
}

#[test]
fn digests_are_validated_and_non_sha256_is_refused_honestly() {
    assert!(validate_sha256_digest(CONFIG_DIGEST).is_ok());
    assert!(validate_sha256_digest("sha256:short").is_err());
    assert!(validate_sha256_digest("notadigest").is_err());
    // Uppercase hex is a different byte string and must not be silently accepted.
    assert!(validate_sha256_digest(&CONFIG_DIGEST.to_uppercase()).is_err());
    // Unsupported algorithms are rejected rather than pretended.
    let err = validate_sha256_digest(&format!("sha512:{}", "a".repeat(128))).unwrap_err();
    assert!(err.contains("sha512"), "got: {err}");

    assert!(is_digest_reference(CONFIG_DIGEST));
    assert!(!is_digest_reference("latest"));
}

#[test]
fn descriptor_digests_invented_by_the_model_are_overwritten() {
    // The model asserts nonsense digests and sizes. This is the crux: whatever it
    // writes must be replaced by the hash of the content it also supplied, or a
    // real client rejects the image.
    let mut manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 999999
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "size": 1,
            "annotations": {"org.opencontainers.image.title": "keep me"}
        }],
        "annotations": {"maintainer": "netget"}
    });

    let blobs = resolve_blobs(&[
        json!({"role": "config", "content": CONFIG_JSON}),
        json!({"role": "layer", "content": LAYER_TEXT}),
    ])
    .unwrap();

    let warnings = apply_blob_descriptors(&mut manifest, &blobs).unwrap();
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

    assert_eq!(manifest["config"]["digest"], CONFIG_DIGEST);
    assert_eq!(manifest["config"]["size"], 151);
    assert_eq!(manifest["layers"][0]["digest"], LAYER_DIGEST);
    assert_eq!(manifest["layers"][0]["size"], 30);
    // Fields the model set that are not digest/size survive.
    assert_eq!(
        manifest["layers"][0]["annotations"]["org.opencontainers.image.title"],
        "keep me"
    );
    assert_eq!(manifest["annotations"]["maintainer"], "netget");
}

#[test]
fn a_descriptor_with_no_supplied_content_is_reported_not_silently_trusted() {
    let mut manifest = json!({
        "schemaVersion": 2,
        "config": {"digest": "sha256:beef", "size": 3},
        "layers": [{"digest": "sha256:cafe", "size": 4}]
    });
    let warnings = apply_blob_descriptors(&mut manifest, &[]).unwrap();
    assert_eq!(
        warnings.len(),
        2,
        "both the unverified config and the unverified layer must be reported: {warnings:?}"
    );
    assert!(warnings.iter().any(|w| w.contains("config")));
    assert!(warnings.iter().any(|w| w.contains("layers")));
}

#[test]
fn index_children_get_real_digests_too() {
    let child = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
    let mut index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "size": 7,
            "platform": {"architecture": "arm64", "os": "linux"}
        }]
    });
    let blobs = resolve_blobs(&[json!({"role": "manifest", "content": child})]).unwrap();
    apply_blob_descriptors(&mut index, &blobs).unwrap();

    assert_eq!(
        index["manifests"][0]["digest"],
        sha256_digest(child.as_bytes())
    );
    assert_eq!(index["manifests"][0]["size"], child.len());
    // The platform block is the whole point of an index and must be preserved.
    assert_eq!(index["manifests"][0]["platform"]["architecture"], "arm64");
}

#[test]
fn content_type_distinguishes_a_manifest_from_an_index() {
    // The document's own mediaType is authoritative: it is inside the bytes the
    // client hashes, so a disagreeing Content-Type is what breaks clients.
    let docker_list =
        json!({"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"});
    assert_eq!(
        manifest_media_type(&docker_list, Some("application/json")),
        "application/vnd.docker.distribution.manifest.list.v2+json"
    );

    // No mediaType in the document: the explicit parameter is used.
    let bare = json!({"schemaVersion": 2});
    assert_eq!(
        manifest_media_type(
            &bare,
            Some("application/vnd.docker.distribution.manifest.v2+json")
        ),
        "application/vnd.docker.distribution.manifest.v2+json"
    );

    // Neither: infer from shape.
    assert_eq!(
        manifest_media_type(&json!({"schemaVersion": 2, "layers": []}), None),
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(
        manifest_media_type(&json!({"schemaVersion": 2, "manifests": []}), None),
        "application/vnd.oci.image.index.v1+json"
    );
}

#[test]
fn error_envelopes_have_the_shape_clients_parse() {
    let body = oci_error_body(
        "manifest_unknown",
        "no such tag",
        Some(&json!({"tag": "v9"})),
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Code is upper-cased: clients match on the canonical spelling.
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    assert_eq!(parsed["errors"][0]["message"], "no such tag");
    assert_eq!(parsed["errors"][0]["detail"]["tag"], "v9");

    assert_eq!(oci_error_status("MANIFEST_UNKNOWN"), 404);
    assert_eq!(oci_error_status("BLOB_UNKNOWN"), 404);
    assert_eq!(oci_error_status("NAME_UNKNOWN"), 404);
    assert_eq!(oci_error_status("UNAUTHORIZED"), 401);
    assert_eq!(oci_error_status("DENIED"), 403);
    assert_eq!(oci_error_status("UNSUPPORTED"), 405);
    assert_eq!(oci_error_status("NAME_INVALID"), 400);
    assert_eq!(oci_error_status("DIGEST_INVALID"), 400);
}

#[test]
fn version_check_mode_rejects_typos_rather_than_defaulting() {
    assert_eq!(
        VersionCheckMode::parse("auto").unwrap(),
        VersionCheckMode::Auto
    );
    assert_eq!(
        VersionCheckMode::parse("LLM").unwrap(),
        VersionCheckMode::Llm
    );
    // A typo must fail the server start, not silently pick a mode.
    assert!(VersionCheckMode::parse("yes").is_err());
}

#[test]
fn resolve_blobs_rejects_a_role_it_cannot_place() {
    assert!(resolve_blobs(&[json!({"role": "sbom", "content": "x"})]).is_err());
    assert!(resolve_blobs(&[json!({"content": 42})]).is_err());
    // Two configs cannot both fill one slot.
    let two = resolve_blobs(&[
        json!({"role": "config", "content": "a"}),
        json!({"role": "config", "content": "b"}),
    ])
    .unwrap();
    let mut manifest = json!({"schemaVersion": 2});
    assert!(apply_blob_descriptors(&mut manifest, &two).is_err());
}
