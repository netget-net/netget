//! The Docker Engine API with a mocked model, driven by the real `docker` CLI.
//!
//! One rule answers every `docker_api_request`, branching on `resource` and `id` — the event
//! fields a model reads to decide what to say. The CLI's `/_ping`, the version check, the image
//! /network/volume fallbacks of `docker inspect` and every mutating command are served without
//! the model, and `expect_calls` on the rule is what proves it.
//!
//! LLM calls: 6 — the startup instruction, then `ps -a`, `images`, `inspect ci-agent`,
//! `inspect ghost` (which the model refuses with a 404) and the `/info` the CLI reads while
//! deciding whether to try swarm object types for `ghost`.

use super::real_client_test::{docker, require_tool};
use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::json;

#[tokio::test]
async fn test_docker_cli_against_a_mocked_model() -> E2EResult<()> {
    let bin = require_tool("docker");
    let config =
        NetGetConfig::new("Open a Docker Engine API on port {AVAILABLE_PORT} for a CI host")
            .with_mock(|mock| {
                mock.on_instruction_containing("Docker Engine API")
                    .respond_with_actions(json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "docker",
                        "instruction": "CI host running one build agent container."
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("docker_api_request")
                    .respond_with_actions_from_event(|event| {
                        let agent = json!({
                            "names": ["ci-agent"], "image": "ci/agent:7",
                            "command": ["/bin/agent", "--serve"], "state": "running",
                            "status": "Up 5 days",
                            "ports": [{"private_port": 9000, "public_port": 19000}]
                        });
                        match (event["resource"].as_str(), event["id"].as_str()) {
                            (Some("containers"), _) => {
                                json!([{"type": "send_docker_containers", "containers": [agent]}])
                            }
                            (Some("images"), _) => json!([{
                                "type": "send_docker_images",
                                "images": [{"repo_tags": ["ci/agent:7"], "size": 50_000_000}]
                            }]),
                            (Some("container"), Some("ci-agent")) => {
                                let mut a = agent;
                                a["type"] = json!("send_docker_container");
                                json!([a])
                            }
                            // `docker inspect` of an unknown name asks /info whether this is a
                            // swarm manager before giving up on the swarm object types.
                            (Some("info"), _) => json!([{"type": "send_docker_info"}]),
                            // Answered only when the event itself names the 404: the
                            // `answer_with` a model reads for this request.
                            (Some("container"), Some(other))
                                if event["answer_with"].as_str().is_some_and(|hint| {
                                    hint.contains(&format!("No such container: {other}"))
                                }) =>
                            {
                                json!([{
                                "type": "send_docker_error",
                                "status": 404,
                                "message": format!("No such container: {other}")
                                }])
                            }
                            _ => json!([{"type": "send_docker_error", "status": 500,
                                     "message": "unexpected request in test"}]),
                        }
                    })
                    .expect_calls(5)
                    .and()
            });

    let server = helpers::start_netget_server(config).await?;
    let dir = tempfile::TempDir::new()?;
    let cfg = dir.path();

    let ps = docker(&bin, cfg, server.port, &["ps", "-a"]).await;
    assert!(ps.success, "{}", ps.stderr);
    let row = ps.stdout.lines().nth(1).unwrap_or_default();
    assert!(
        row.contains("ci/agent:7")
            && row.contains("\"/bin/agent --serve\"")
            && row.contains("Up 5 days")
            && row.contains("0.0.0.0:19000->9000/tcp")
            && row.trim_end().ends_with("ci-agent"),
        "{}",
        ps.stdout
    );
    assert_eq!(ps.stdout.lines().filter(|l| !l.is_empty()).count(), 2);

    // The default table, not a --format template: the CLI's own image view.
    let images = docker(&bin, cfg, server.port, &["images"]).await;
    assert!(images.success, "{}", images.stderr);
    assert!(
        images.stdout.contains("ci/agent") && images.stdout.contains("50MB"),
        "{}",
        images.stdout
    );

    let inspect = docker(
        &bin,
        cfg,
        server.port,
        &[
            "inspect",
            "--format",
            "{{.Path}} {{.Args}} {{.State.Status}}",
            "ci-agent",
        ],
    )
    .await;
    assert_eq!(
        inspect.stdout.trim(),
        "/bin/agent [--serve] running",
        "{}",
        inspect.stderr
    );

    // The model's 404 for the container, then the CLI's own fallbacks (image, network,
    // volume…), none of which reach the model.
    let ghost = docker(&bin, cfg, server.port, &["inspect", "ghost"]).await;
    assert!(!ghost.success);
    assert!(
        ghost
            .stderr
            .to_lowercase()
            .contains("no such object: ghost"),
        "{}",
        ghost.stderr
    );

    // Mutating: 501, statically.
    let run = docker(&bin, cfg, server.port, &["create", "ci/agent:7"]).await;
    assert!(!run.success);
    assert!(run.stderr.contains("read-only"), "{}", run.stderr);

    server.wait_for_any(&["decision=model_reject"], 30).await;
    let lines = server.get_output().await;
    for tag in [
        "decision=model_answer",
        "decision=model_reject",
        "decision=fail_closed_not_implemented",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(tag)),
            "expected {tag} in the log:\n{}",
            lines.join("\n")
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Version negotiation from the wire: too new and too old are Docker's own 400s, and every
/// response carries the daemon's identifying headers.
#[tokio::test]
async fn test_docker_version_negotiation_and_headers() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Open a Docker Engine API on port {AVAILABLE_PORT}").with_mock(|mock| {
            mock.on_instruction_containing("Docker Engine API")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "docker",
                    "instruction": "Empty host",
                    "startup_params": {"api_version": "1.45", "engine_version": "26.1.4"}
                }]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;
    let http = reqwest::Client::builder().no_proxy().build()?;
    let base = format!("http://127.0.0.1:{}", server.port);

    let ping = http.head(format!("{base}/_ping")).send().await?;
    assert_eq!(ping.status(), 200);
    assert_eq!(ping.headers()["api-version"], "1.45");
    assert_eq!(ping.headers()["server"], "Docker/26.1.4 (linux)");
    assert_eq!(
        http.get(format!("{base}/v1.45/_ping"))
            .send()
            .await?
            .text()
            .await?,
        "OK"
    );

    let too_new = http
        .get(format!("{base}/v1.46/containers/json"))
        .send()
        .await?;
    assert_eq!(too_new.status(), 400);
    let body: serde_json::Value = too_new.json().await?;
    assert_eq!(
        body["message"],
        "client version 1.46 is too new. Maximum supported API version is 1.45"
    );
    let too_old = http.get(format!("{base}/v1.12/info")).send().await?;
    assert_eq!(too_old.status(), 400);

    let unknown = http
        .get(format!("{base}/v1.45/containers/x/logs"))
        .send()
        .await?;
    assert_eq!(unknown.status(), 404);
    assert_eq!(
        unknown.json::<serde_json::Value>().await?["message"],
        "page not found"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
