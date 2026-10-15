//! NetGet's Docker Engine API against the real `docker` CLI.
//!
//! The CLI is a Go client NetGet did not write: it negotiates the API version from `/_ping`,
//! decodes every document into the Engine's own Go types and renders them — `docker ps`
//! computes the short ID, the `->` port column and the name from our JSON, and fails outright
//! on a shape it cannot decode. That is the evidence a generic HTTP client cannot give.
//!
//! **The machine's real Docker daemon must never be reached.** Every invocation passes
//! `-H tcp://127.0.0.1:<port>` explicitly, removes `DOCKER_HOST`, `DOCKER_CONTEXT`,
//! `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` from the child's environment, and points
//! `DOCKER_CONFIG` at a fresh temp dir so no context, credential helper or CLI hook from the
//! user's own config applies. The assertions then require the output to contain *only* the
//! handler's values: every container, image, network and volume name here carries a
//! `netget-fixture` marker no real daemon would have, and row counts are exact.
//!
//! The servers answer with a **static** handler (one rule carrying one action per route) and
//! the protocol's own **script-mode** example, so no model is involved here; `e2e_test.rs`
//! drives the same CLI against a mocked model.
//!
//! **These tests FAIL, they do not skip, when docker is absent.** Install the CLI with
//! `brew install docker` (macOS) or `apt-get install -y docker-ce-cli` / the static binary from
//! https://download.docker.com/linux/static/stable/ (Linux). No daemon is needed or used.


use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub fn require_tool(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` was not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin). \
         These tests drive the real Docker CLI against NetGet's Engine API, and that is the only \
         independent check that the documents NetGet renders decode in Docker's own Go types. \
         Skipping would leave the Docker server's maturity rating resting on nothing, so this is \
         a failure and not a skip. Install with `brew install docker` (macOS) or the \
         docker-ce-cli package / static binary (Linux); no daemon is needed."
    );
}

pub struct DockerOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run the CLI against NetGet only. See the module header for why each variable is removed.
pub async fn docker(
    bin: &str,
    config_dir: &std::path::Path,
    port: u16,
    args: &[&str],
) -> DockerOutput {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(bin)
            .arg("-H")
            .arg(format!("tcp://127.0.0.1:{port}"))
            .args(args)
            .env_remove("DOCKER_HOST")
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_TLS_VERIFY")
            .env_remove("DOCKER_CERT_PATH")
            .env("DOCKER_CONFIG", config_dir)
            .env("DOCKER_CLI_HINTS", "false")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("docker did not finish within 60s")
    .expect("run docker");
    let result = DockerOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    println!(
        "$ docker {}\n  exit ok = {}\n{}{}",
        args.join(" "),
        result.success,
        result.stdout,
        result.stderr
    );
    result
}

const WEB_ID: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";

fn web() -> Value {
    json!({
        "id": WEB_ID,
        "names": ["web-netget-fixture"],
        "image": "nginx:1.27-fixture",
        "command": "nginx -g 'daemon off;'",
        "state": "running",
        "status": "Up 42 minutes",
        "created": "2026-09-01T10:00:00Z",
        "ports": [{"private_port": 80, "public_port": 18080, "type": "tcp"}],
        "env": ["NETGET_FIXTURE=1"],
        "labels": {"netget.fixture": "web"}
    })
}

fn fixture_actions() -> Value {
    let mut inspect = web();
    inspect["type"] = json!("send_docker_container");
    json!([
        {"type": "send_docker_version", "version": "27.5.1-netget-fixture", "arch": "amd64"},
        {"type": "send_docker_info", "name": "netget-fixture-host", "containers_running": 1,
         "containers_stopped": 1, "images": 2, "operating_system": "NetGet Fixture OS",
         "ncpu": 3},
        {"type": "send_docker_containers", "containers": [
            web(),
            {"id": "deadbeef0000deadbeef0000deadbeef0000deadbeef0000deadbeef0000dead",
             "names": ["db-netget-fixture"], "image": "postgres:16-fixture",
             "command": "docker-entrypoint.sh postgres", "state": "exited", "exit_code": 0,
             "status": "Exited (0) 3 hours ago", "created": "2026-09-01T08:00:00Z"}
        ]},
        inspect,
        {"type": "send_docker_images", "images": [
            {"repo_tags": ["nginx:1.27-fixture"], "size": 187654321,
             "created": "2026-08-20T00:00:00Z"},
            {"repo_tags": ["postgres:16-fixture"], "size": 432109876,
             "created": "2026-08-21T00:00:00Z"}
        ]},
        {"type": "send_docker_networks", "networks": [{"name": "netget-fixture-net"}]},
        {"type": "send_docker_volumes", "volumes": [{"name": "netget-fixture-vol"}]}
    ])
}

pub async fn start_docker(event_handlers: Vec<Value>) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "docker".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create docker server");
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return (state, addr.port());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("docker server never bound a port");
}

/// Lines of a table after its header.
fn rows(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect()
}

#[tokio::test]
async fn the_docker_cli_prints_exactly_what_the_handler_said() -> TestResult {
    let bin = require_tool("docker");
    let config = tempfile::TempDir::new()?;
    let (_state, port) = start_docker(vec![json!({
        "event_pattern": "docker_api_request",
        "handler": {"type": "static", "actions": fixture_actions()}
    })])
    .await;
    let cfg = config.path();

    // version: negotiated down to our API version, Server section is ours.
    let v = docker(&bin, cfg, port, &["version"]).await;
    assert!(v.success, "docker version failed: {}", v.stderr);
    let server = v
        .stdout
        .split("Server:")
        .nth(1)
        .expect("docker version printed no Server section");
    assert!(server.contains("27.5.1-netget-fixture"), "{server}");
    assert!(server.contains("1.47 (minimum version 1.24)"), "{server}");
    // The client negotiated to at most what /_ping advertised: a newer CLI says "1.47
    // (downgraded from 1.5x)", an older one keeps its own lower maximum.
    let client = v.stdout.split("Server:").next().unwrap_or_default();
    let negotiated = client
        .lines()
        .find_map(|l| l.trim().strip_prefix("API version:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(netget::server::docker::api::parse_version)
        .unwrap_or_else(|| panic!("no client API version line:\n{client}"));
    assert!(
        negotiated <= (1, 47),
        "the CLI used API {negotiated:?}, above the 1.47 NetGet advertised:\n{client}"
    );

    // ps -a: exactly our two rows, with everything the CLI derives from our JSON.
    let ps = docker(&bin, cfg, port, &["ps", "-a"]).await;
    assert!(ps.success, "docker ps -a failed: {}", ps.stderr);
    let lines = rows(&ps.stdout);
    assert_eq!(
        lines.len(),
        2,
        "exactly the handler's two containers:\n{}",
        ps.stdout
    );
    let web_row = lines
        .iter()
        .find(|l| l.contains("web-netget-fixture"))
        .expect("web row");
    for cell in [
        "c0ffee00c0ff",
        "nginx:1.27-fixture",
        "\"nginx -g 'daemon",
        "Up 42 minutes",
        "0.0.0.0:18080->80/tcp",
    ] {
        assert!(web_row.contains(cell), "web row lacks {cell:?}: {web_row}");
    }
    assert!(
        !web_row.contains(WEB_ID),
        "the CLI should truncate the ID: {web_row}"
    );
    let db_row = lines
        .iter()
        .find(|l| l.contains("db-netget-fixture"))
        .expect("db row");
    assert!(db_row.contains("Exited (0) 3 hours ago") && db_row.contains("deadbeef0000"));

    // images: our two tags and nothing else.
    let images = docker(
        &bin,
        cfg,
        port,
        &[
            "images",
            "--format",
            "{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}",
        ],
    )
    .await;
    assert!(images.success, "docker images failed: {}", images.stderr);
    let image_lines: Vec<&str> = images.stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(image_lines.len(), 2, "{}", images.stdout);
    assert!(
        image_lines
            .iter()
            .any(|l| l.starts_with("nginx:1.27-fixture ") && l.contains("188MB")),
        "{}",
        images.stdout
    );
    assert!(
        image_lines
            .iter()
            .any(|l| l.starts_with("postgres:16-fixture ")),
        "{}",
        images.stdout
    );

    // inspect: the CLI prints the raw document, so parse it.
    let inspect = docker(&bin, cfg, port, &["inspect", "web-netget-fixture"]).await;
    assert!(inspect.success, "docker inspect failed: {}", inspect.stderr);
    let doc: Value = serde_json::from_str(&inspect.stdout)?;
    let c = &doc[0];
    assert_eq!(c["Id"], WEB_ID);
    assert_eq!(c["Name"], "/web-netget-fixture");
    assert_eq!(c["State"]["Status"], "running");
    assert_eq!(c["State"]["Running"], true);
    assert_eq!(c["Config"]["Image"], "nginx:1.27-fixture");
    assert_eq!(c["Config"]["Env"], json!(["NETGET_FIXTURE=1"]));
    assert_eq!(c["Config"]["Labels"]["netget.fixture"], "web");
    assert_eq!(
        c["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"],
        "18080"
    );
    assert_eq!(c["Created"], "2026-09-01T10:00:00.000000000Z");

    // A templated field goes through the CLI's own decode into its Go types.
    let fmt = docker(
        &bin,
        cfg,
        port,
        &[
            "inspect",
            "--format",
            "{{.State.Status}} {{.Config.Image}} {{.Name}}",
            "web-netget-fixture",
        ],
    )
    .await;
    assert_eq!(
        fmt.stdout.trim(),
        "running nginx:1.27-fixture /web-netget-fixture"
    );

    // networks and volumes.
    let nets = docker(
        &bin,
        cfg,
        port,
        &[
            "network",
            "ls",
            "--format",
            "{{.Name}} {{.Driver}} {{.Scope}}",
        ],
    )
    .await;
    assert!(nets.success, "docker network ls failed: {}", nets.stderr);
    assert_eq!(nets.stdout.trim(), "netget-fixture-net bridge local");
    let vols = docker(
        &bin,
        cfg,
        port,
        &["volume", "ls", "--format", "{{.Name}} {{.Driver}}"],
    )
    .await;
    assert!(vols.success, "docker volume ls failed: {}", vols.stderr);
    assert_eq!(vols.stdout.trim(), "netget-fixture-vol local");

    // info: the server section is ours.
    let info = docker(&bin, cfg, port, &["info", "--format", "{{.Name}}|{{.OperatingSystem}}|{{.Containers}}|{{.ContainersRunning}}|{{.Images}}|{{.NCPU}}|{{.ServerVersion}}"]).await;
    assert!(info.success, "docker info failed: {}", info.stderr);
    assert_eq!(
        info.stdout.trim(),
        "netget-fixture-host|NetGet Fixture OS|2|1|2|3|27.5.1"
    );

    // Mutating commands get Docker's own error shape, statically.
    let rm = docker(&bin, cfg, port, &["rm", "web-netget-fixture"]).await;
    assert!(!rm.success);
    assert!(
        rm.stderr.contains("Error response from daemon") && rm.stderr.contains("read-only"),
        "docker rm should be refused in Docker's error shape: {}",
        rm.stderr
    );
    Ok(())
}

/// The shipped script-mode example, run as written: it answers by resource and says 404 for a
/// container it does not know, which the CLI turns into its own "No such object".
#[tokio::test]
async fn the_documented_script_example_drives_the_cli() -> TestResult {
    use netget::llm::actions::protocol_trait::Protocol;
    let bin = require_tool("docker");
    let config = tempfile::TempDir::new()?;
    let handlers = netget::server::DockerProtocol::new()
        .get_startup_examples()
        .script_mode["event_handlers"]
        .as_array()
        .expect("script example has handlers")
        .clone();
    let (_state, port) = start_docker(handlers).await;
    let cfg = config.path();

    let ps = docker(&bin, cfg, port, &["ps"]).await;
    assert!(ps.success, "{}", ps.stderr);
    let lines = rows(&ps.stdout);
    assert_eq!(lines.len(), 1, "{}", ps.stdout);
    assert!(
        lines[0].contains("web") && lines[0].contains("0.0.0.0:8080->80/tcp"),
        "{}",
        lines[0]
    );

    let inspect = docker(
        &bin,
        cfg,
        port,
        &["inspect", "--format", "{{.Name}}", "web"],
    )
    .await;
    assert_eq!(inspect.stdout.trim(), "/web", "{}", inspect.stderr);

    let missing = docker(&bin, cfg, port, &["inspect", "nothing-here"]).await;
    assert!(!missing.success);
    assert!(
        missing
            .stderr
            .to_lowercase()
            .contains("no such object: nothing-here"),
        "{}",
        missing.stderr
    );
    Ok(())
}
