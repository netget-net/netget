use super::common::*;
use crate::helpers::real_server::{find_binary, InstallHint, RealServer};
use serde_json::{json, Value};
use std::time::Duration;
const MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const WRAPPER: &str = r#"import os,pathlib,sys
binary,directory,port=sys.argv[1:]
root=pathlib.Path(directory)
(root/'home').mkdir();(root/'docker').mkdir();(root/'docker'/'config.json').write_text('{}')
env={'HOME':str(root/'home'),'DOCKER_CONFIG':str(root/'docker'),'PATH':os.environ.get('PATH','')}
os.execve(binary,[binary,'registry','serve','--address','127.0.0.1:'+port],env)
"#;
pub(super) async fn daemon() -> crate::helpers::E2EResult<RealServer> {
    let crane = find_binary("crane").expect(
        "required independent crane0.22.1 peer; install official go-containerregistry release",
    );
    let version = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(&crane)
            .arg("version")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(version.status.success());
    assert_eq!(String::from_utf8_lossy(&version.stdout).trim(), "0.22.1");
    RealServer::builder(
        "python3",
        InstallHint {
            brew: "python3 and crane0.22.1",
            apt: "python3 and pinned official crane0.22.1 release",
        },
    )
    .config_file("crane_peer.py", WRAPPER)
    .args([
        "-u",
        "{dir}/crane_peer.py",
        crane.to_str().unwrap(),
        "{dir}",
        "{port}",
    ])
    .ready_when_log_matches("serving on port")
    .start()
    .await
}
pub(super) async fn seed(origin: &str) -> (String, String, Vec<u8>) {
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let config = b"{}";
    let blob = vec![0, 255, 128];
    let mut digests = Vec::new();
    for b in [config.as_slice(), blob.as_slice()] {
        let d = netget::server::oci_registry::actions::sha256_digest(b);
        let response = http
            .post(format!("{origin}/v2/library/demo/blobs/uploads/"))
            .body(Vec::new())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 202);
        let location = response.headers()["location"].to_str().unwrap();
        let mut u = url::Url::parse(origin).unwrap().join(location).unwrap();
        u.query_pairs_mut().append_pair("digest", &d);
        let response = http
            .put(u)
            .header("Content-Type", "application/octet-stream")
            .body(b.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
        digests.push(d);
    }
    let doc = json!({"schemaVersion":2,"mediaType":MEDIA,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digests[0],"size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":digests[1],"size":3}]});
    let bytes = serde_json::to_vec(&doc).unwrap();
    for tag in ["latest", "second"] {
        let response = http
            .put(format!("{origin}/v2/library/demo/manifests/{tag}"))
            .header("Content-Type", MEDIA)
            .body(bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
    }
    (
        netget::server::oci_registry::actions::sha256_digest(&bytes),
        digests[1].clone(),
        bytes,
    )
}
async fn request(
    state: &netget::state::AppState,
    id: netget::state::ClientId,
    action: Value,
) -> Value {
    let before = latest(state, id).await;
    send(state, id, action).await;
    event(state, id, "oci_result", before).await.1
}
#[tokio::test]
async fn independent_crane_registry_manifest_blob_head_tags_catalog_and_sdk_readback(
) -> crate::helpers::E2EResult<()> {
    let peer = daemon().await?;
    let origin = format!("http://{}", peer.addr());
    let (manifest, blob, bytes) = seed(&origin).await;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(format!("{origin}/v2/library/demo/tags/list?n=100"))
        .send()
        .await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.bytes().await?;
    let netget::client::oci_registry::api::Action::Request(r) =
        netget::client::oci_registry::api::action(
            &json!({"type":"oci_request","operation":"tags","repository":"library/demo"}),
        )?
    else {
        unreachable!()
    };
    let calibrated = netget::client::oci_registry::api::response(&r, status, &headers, &body);
    assert!(
        calibrated.is_ok(),
        "independent native tags refused: {:?}; headers {:?}; body {}",
        calibrated.err(),
        headers,
        String::from_utf8_lossy(&body)
    );
    let state = state();
    let id = client(
        &state,
        origin.clone(),
        json!({}),
        vec![static_handler("*", json!([]))],
    )
    .await;
    let connected = event(&state, id, "oci_connected", 0).await.1;
    assert_eq!(connected["authentication_verified"], false);
    let tags = request(
        &state,
        id,
        json!({"type":"oci_request","operation":"tags","repository":"library/demo"}),
    )
    .await;
    assert_eq!(tags["data"]["tags"], json!(["latest", "second"]));
    let catalog = request(
        &state,
        id,
        json!({"type":"oci_request","operation":"catalog"}),
    )
    .await;
    assert!(catalog["data"]["repositories"]
        .as_array()
        .unwrap()
        .contains(&json!("library/demo")));
    for reference in ["latest", manifest.as_str()] {
        let result=request(&state,id,json!({"type":"oci_request","operation":"manifest","repository":"library/demo","reference":reference})).await;
        assert_eq!(result["data"]["digest"], manifest);
        assert_eq!(result["data"]["digest_verified"], true);
        assert_eq!(result["data"]["manifest"]["layers"][0]["digest"], blob);
    }
    let head=request(&state,id,json!({"type":"oci_request","operation":"manifest_head","repository":"library/demo","reference":manifest})).await;
    assert_eq!(head["data"]["exists"], true);
    assert_eq!(head["data"]["digest_verified"], false);
    let result=request(&state,id,json!({"type":"oci_request","operation":"blob","repository":"library/demo","reference":blob,"expected_size":3})).await;
    assert_eq!(result["data"]["digest_verified"], true);
    assert_eq!(result["data"]["content_omitted"], true);
    assert!(result["data"]["text"].is_null());
    let head=request(&state,id,json!({"type":"oci_request","operation":"blob_head","repository":"library/demo","reference":blob})).await;
    assert_eq!(head["data"]["size"], 3);
    let before = latest(&state, id).await;
    send(&state,id,json!({"type":"oci_request","operation":"manifest","repository":"library/demo","reference":"missing"})).await;
    let failure = event(&state, id, "oci_failure", before).await.1;
    assert_eq!(failure["status"], 404);
    assert_eq!(failure["errors"][0]["code"], "MANIFEST_UNKNOWN");
    let home = tempfile::TempDir::new()?;
    let crane = find_binary("crane").unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(crane)
            .args(["manifest", &format!("{}/library/demo:latest", peer.addr())])
            .env("HOME", home.path())
            .env("DOCKER_CONFIG", home.path())
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(output.status.success(), "independent SDK readback failed");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        serde_json::from_slice::<Value>(&bytes)?
    );
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn native_https_refuses_an_independent_untrusted_certificate() -> crate::helpers::E2EResult<()>
{
    let hint = InstallHint {
        brew: "openssl@3",
        apt: "openssl",
    };
    let peer = RealServer::builder("openssl", hint)
        .setup_command(
            "openssl",
            hint,
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "{dir}/key.pem",
                "-out",
                "{dir}/cert.pem",
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ],
        )
        .args([
            "s_server",
            "-accept",
            "127.0.0.1:{port}",
            "-key",
            "{dir}/key.pem",
            "-cert",
            "{dir}/cert.pem",
            "-www",
        ])
        .ready_when_log_matches("ACCEPT")
        .start()
        .await?;
    let state = state();
    let error = refused_start(
        &state,
        format!("https://{}", peer.addr()),
        json!({"request_timeout_secs":2,"token":"private-token"}),
    )
    .await;
    assert!(!error.is_empty());
    assert!(!error.contains("private-token"));
    assert!(
        error.contains("request"),
        "native TLS request must be refused"
    );
    Ok(())
}

/// Condition 4 of the client bar, from the registry's side: the mocked model lists the tags
/// crane's registry holds, picks `second` out of that listing, and fetches its manifest. The
/// registry's own request log shows that fetch, and the digest the client verified is the one
/// of the manifest the test pushed.
#[tokio::test]
async fn mocked_model_picks_a_tag_from_the_listing_and_crane_serves_its_manifest(
) -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let peer = daemon().await?;
    let origin = format!("http://{}", peer.addr());
    let (manifest, _, _) = seed(&origin).await;
    let config = MockLlmBuilder::new()
        .on_event("oci_connected")
        .respond_with_actions(json!([
            {"type":"oci_request","operation":"tags","repository":"library/demo"}
        ]))
        .expect_calls(1)
        .and()
        .on_event("oci_result")
        .and_event_data_contains("operation", "tags")
        .and_event_data_contains("data", "second")
        .respond_with_actions(json!([
            {"type":"oci_request","operation":"manifest","repository":"library/demo","reference":"second"}
        ]))
        .expect_calls(1)
        .and()
        .on_event("oci_result")
        .and_event_data_contains("operation", "manifest")
        .and_event_data_contains("reference", "second")
        .and_event_data_contains("data", &manifest)
        .respond_with_actions(json!([]))
        .expect_calls(1)
        .and()
        .build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "oci-registry".into(),
        remote_addr: Some(origin),
        instruction: Some("List library/demo's tags and fetch the second one".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    let (tags_entry, _) = event(&state, id, "oci_result", 0).await;
    let (_, result) = event(&state, id, "oci_result", tags_entry).await;
    assert_eq!(result["operation"], "manifest", "{result}");
    assert_eq!(result["reference"], "second", "{result}");
    assert_eq!(result["data"]["digest"], manifest);
    assert_eq!(result["data"]["digest_verified"], true);
    assert!(
        peer.log().contains("GET /v2/library/demo/manifests/second"),
        "crane's registry did not log the model's manifest fetch: {}",
        peer.log()
    );
    state.remove_client(id).await;
    Ok(())
}
