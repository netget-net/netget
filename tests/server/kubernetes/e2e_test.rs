//! End-to-end tests for the Kubernetes API server.
//!
//! The load-bearing tests here drive the **real `kubectl` binary** through a generated
//! kubeconfig. That is the whole point: a Kubernetes API server that has only ever been talked
//! to by our own code is not evidence of anything. `kubectl` performs full API discovery before
//! every command and fails opaquely if `/api`, `/apis` or `/api/v1` are wrong, so a passing
//! `kubectl get pods` proves the discovery documents, the resource routing, the `Table`
//! rendering and the `Status` error envelope all at once.
//!
//! The wire-level tests cover what kubectl cannot easily be made to exercise: the TLS listener,
//! `?watch=true`, and the exact JSON of the discovery documents.
//!
//! Everything binds to 127.0.0.1. No real cluster is contacted, and `KUBECONFIG` is passed
//! explicitly so an operator's own cluster can never be reached.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// kubectl harness
// ---------------------------------------------------------------------------

/// Fail unless a usable `kubectl` is on PATH, naming the client version it found.
///
/// **This must not skip.** The real `kubectl` binary *is* the evidence these tests exist to
/// produce — it is what makes this protocol's maturity rating honest, because a Kubernetes API
/// server that has only ever been talked to by our own code proves nothing. A
/// `println!("SKIP")` + `return Ok(())` is a silent pass on any machine without the binary, and
/// that is precisely how a maturity claim outlives the thing that justified it. Copied from
/// `tests/server/npm/e2e_test.rs`, which says the same in its own words.
fn require_kubectl() -> Result<String, Box<dyn std::error::Error>> {
    match Command::new("kubectl")
        .args(["version", "--client"])
        .output()
    {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`kubectl version --client` exited {}: this test's whole point is driving the real \
             kubectl binary against NetGet's apiserver",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "kubectl is not available ({e}): this test's whole point is driving the real kubectl \
             binary against NetGet's apiserver, and skipping it would leave the Kubernetes \
             server's maturity rating resting on nothing"
        )
        .into()),
    }
}

/// Write a kubeconfig pointing at the NetGet server and return its path.
///
/// For a plain-HTTP server this is all that is needed. Over TLS, NetGet serves a self-signed
/// certificate, so `insecure-skip-tls-verify` is set — the pragmatic path documented in
/// `src/server/kubernetes/CLAUDE.md`.
fn write_kubeconfig(dir: &Path, server_url: &str) -> PathBuf {
    let insecure = if server_url.starts_with("https://") {
        "\n    insecure-skip-tls-verify: true"
    } else {
        ""
    };
    let contents = format!(
        "apiVersion: v1\n\
         kind: Config\n\
         clusters:\n\
         - name: netget\n\
         \x20 cluster:\n\
         \x20   server: {server_url}{insecure}\n\
         contexts:\n\
         - name: netget\n\
         \x20 context:\n\
         \x20   cluster: netget\n\
         \x20   user: netget\n\
         \x20   namespace: default\n\
         current-context: netget\n\
         users:\n\
         - name: netget\n\
         \x20 user: {{}}\n"
    );
    let path = dir.join("kubeconfig.yaml");
    std::fs::write(&path, contents).expect("failed to write kubeconfig");
    path
}

struct KubectlOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run kubectl against the generated kubeconfig with a private discovery cache.
///
/// `--cache-dir` matters: kubectl caches discovery under `~/.kube/cache` keyed by host:port,
/// so without a private cache a previous test's cluster could be reused for this one.
///
/// **This must be `tokio::process`, not `std::process`.** `#[tokio::test]` runs a
/// current-thread runtime, so a blocking `Command::output()` parks the only worker and stops
/// the harness tasks that drain the netget child's stdout/stderr. The 64 KB pipes then fill,
/// netget blocks inside `debug!` while serving a request, and kubectl times out against a
/// server that is perfectly correct. That cost an hour; do not "simplify" this back.
async fn run_kubectl(kubeconfig: &Path, cache_dir: &Path, args: &[&str]) -> KubectlOutput {
    let output = TokioCommand::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .arg("--cache-dir")
        .arg(cache_dir)
        .arg("--request-timeout=30s")
        .args(args)
        .output()
        .await
        .expect("failed to execute kubectl");

    let result = KubectlOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    println!("$ kubectl {}", args.join(" "));
    println!("  exit ok = {}", result.success);
    if !result.stdout.is_empty() {
        println!("  stdout:\n{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        println!("  stderr:\n{}", result.stderr);
    }
    result
}

fn pod_items() -> Value {
    json!([
        {
            "metadata": {"name": "web-0", "namespace": "default",
                         "creationTimestamp": "2026-08-10T09:00:00Z"},
            "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
            "status": {"phase": "Running",
                       "containerStatuses": [{"name": "web", "ready": true, "restartCount": 0}]}
        },
        {
            "metadata": {"name": "web-1", "namespace": "default",
                         "creationTimestamp": "2026-08-10T09:05:00Z"},
            "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
            "status": {"phase": "Running",
                       "containerStatuses": [{"name": "web", "ready": true, "restartCount": 2}]}
        },
        {
            "metadata": {"name": "cache-0", "namespace": "default",
                         "creationTimestamp": "2026-08-10T08:00:00Z"},
            "spec": {"containers": [{"name": "redis", "image": "redis:7"}]},
            "status": {"phase": "CrashLoopBackOff",
                       "containerStatuses": [{"name": "redis", "ready": false, "restartCount": 7}]}
        }
    ])
}

fn node_items() -> Value {
    json!([
        {
            "metadata": {"name": "node-1", "creationTimestamp": "2026-07-01T00:00:00Z",
                         "labels": {"node-role.kubernetes.io/control-plane": ""}},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "nodeInfo": {"kubeletVersion": "v1.29.4"}
            }
        },
        {
            "metadata": {"name": "node-2", "creationTimestamp": "2026-07-01T00:00:00Z"},
            "status": {
                "conditions": [{"type": "Ready", "status": "False"}],
                "nodeInfo": {"kubeletVersion": "v1.29.4"}
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Test 1: real kubectl - version, get pods, get nodes
// ---------------------------------------------------------------------------

/// The headline test: a real `kubectl` lists an LLM-invented cluster.
///
/// LLM calls: 3 (startup, pods list, nodes list). `kubectl version` and every discovery
/// request are served deterministically and cost nothing.
#[tokio::test]
async fn test_kubectl_version_get_pods_and_get_nodes() -> E2EResult<()> {
    println!("\n=== E2E Test: real kubectl against NetGet ===");

    println!("kubectl client: {}", require_kubectl()?);

    let prompt =
        "Open a Kubernetes API server on port {AVAILABLE_PORT} with three pods and two nodes";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Kubernetes API server")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "kubernetes",
                "instruction": "Kubernetes API server for a small cluster",
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_list_request")
            .and_event_data_contains("resource", "pods")
            .respond_with_actions(json!([{
                "type": "k8s_list_response",
                "kind": "PodList",
                "apiVersion": "v1",
                "items": pod_items(),
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_list_request")
            .and_event_data_contains("resource", "nodes")
            .respond_with_actions(json!([{
                "type": "k8s_list_response",
                "kind": "NodeList",
                "apiVersion": "v1",
                "items": node_items(),
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
    println!("Kubernetes API server started on port {}", server.port);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let workdir = TempDir::new()?;
    let kubeconfig = write_kubeconfig(workdir.path(), &format!("http://127.0.0.1:{}", server.port));
    let cache_dir = workdir.path().join("cache");

    // --- kubectl version: exercises GET /version, no LLM call ---------------
    let version = run_kubectl(&kubeconfig, &cache_dir, &["version"]).await;
    assert!(
        version.success,
        "kubectl version failed: {}",
        version.stderr
    );
    assert!(
        version.stdout.contains("v1.29.4"),
        "kubectl version did not report the server version v1.29.4; got:\n{}",
        version.stdout
    );
    assert!(
        version.stdout.contains("Server Version"),
        "kubectl did not print a Server Version block, so it never reached /version:\n{}",
        version.stdout
    );

    // --- kubectl get pods: discovery + list + server-side Table -------------
    let pods = run_kubectl(&kubeconfig, &cache_dir, &["get", "pods"]).await;
    assert!(pods.success, "kubectl get pods failed: {}", pods.stderr);

    let header = pods
        .stdout
        .lines()
        .next()
        .expect("kubectl get pods produced no output");
    for column in ["NAME", "READY", "STATUS", "RESTARTS", "AGE"] {
        assert!(
            header.contains(column),
            "kubectl did not render the {column} column - the Table response was wrong.\n\
             header: {header}"
        );
    }

    let web0 = pods
        .stdout
        .lines()
        .find(|l| l.starts_with("web-0"))
        .expect("kubectl get pods did not list web-0");
    assert!(
        web0.contains("Running") && web0.contains("1/1"),
        "web-0 row did not carry the model's phase/readiness: {web0}"
    );

    let cache0 = pods
        .stdout
        .lines()
        .find(|l| l.starts_with("cache-0"))
        .expect("kubectl get pods did not list cache-0");
    assert!(
        cache0.contains("CrashLoopBackOff") && cache0.contains("0/1") && cache0.contains(" 7"),
        "cache-0 row lost its status/readiness/restart count: {cache0}"
    );

    // --- kubectl get nodes: a different kind, different columns -------------
    let nodes = run_kubectl(&kubeconfig, &cache_dir, &["get", "nodes"]).await;
    assert!(nodes.success, "kubectl get nodes failed: {}", nodes.stderr);

    let node_header = nodes
        .stdout
        .lines()
        .next()
        .expect("kubectl get nodes produced no output");
    for column in ["NAME", "STATUS", "ROLES", "AGE", "VERSION"] {
        assert!(
            node_header.contains(column),
            "kubectl did not render the {column} column for nodes.\nheader: {node_header}"
        );
    }
    let node1 = nodes
        .stdout
        .lines()
        .find(|l| l.starts_with("node-1"))
        .expect("kubectl get nodes did not list node-1");
    assert!(
        node1.contains("Ready") && node1.contains("control-plane") && node1.contains("v1.29.4"),
        "node-1 row lost its condition/role/kubelet version: {node1}"
    );
    let node2 = nodes
        .stdout
        .lines()
        .find(|l| l.starts_with("node-2"))
        .expect("kubectl get nodes did not list node-2");
    assert!(
        node2.contains("NotReady"),
        "node-2 was Ready=False but did not render as NotReady: {node2}"
    );

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("✓ real kubectl drove version, get pods and get nodes\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: real kubectl - single object as JSON, and a 404 Status
// ---------------------------------------------------------------------------

/// `kubectl get pod <name> -o json` proves the raw object envelope, and a missing pod proves
/// the `Status` error object is the one kubectl parses.
///
/// LLM calls: 3 (startup, the found pod, the missing pod).
#[tokio::test]
async fn test_kubectl_get_single_pod_and_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: kubectl get pod / NotFound Status ===");

    println!("kubectl client: {}", require_kubectl()?);

    let prompt =
        "Open a Kubernetes API server on port {AVAILABLE_PORT} serving one pod named web-0";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Kubernetes API server")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "kubernetes",
                "instruction": "Kubernetes API server with a single pod web-0",
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_get_request")
            .and_event_data_contains("name", "web-0")
            .respond_with_actions(json!([{
                "type": "k8s_object_response",
                "object": {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "metadata": {
                        "name": "web-0",
                        "namespace": "default",
                        "uid": "8b1f0c3e-0000-4000-8000-000000000001",
                        "creationTimestamp": "2026-08-10T09:00:00Z",
                        "labels": {"app": "web"}
                    },
                    "spec": {"nodeName": "node-1",
                             "containers": [{"name": "web", "image": "nginx:1.27"}]},
                    "status": {"phase": "Running", "podIP": "10.42.0.7"}
                }
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_get_request")
            .and_event_data_contains("name", "ghost")
            .respond_with_actions(json!([{
                "type": "k8s_status",
                "code": 404,
                "reason": "NotFound",
                "message": "pods \"ghost\" not found",
                "details": {"name": "ghost", "kind": "pods"}
            }]))
            .expect_calls(1)
            .and()
            // The third declared event. A declared event that is never emitted is worse than
            // no event at all, so this exists specifically to prove k8s_write_request fires.
            .on_event("k8s_write_request")
            .and_event_data_contains("method", "DELETE")
            .respond_with_actions(json!([{
                "type": "k8s_object_response",
                "object": {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "metadata": {
                        "name": "web-0",
                        "namespace": "default",
                        "deletionTimestamp": "2026-08-10T10:00:00Z"
                    },
                    "status": {"phase": "Running"}
                }
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
    tokio::time::sleep(Duration::from_millis(500)).await;

    let workdir = TempDir::new()?;
    let kubeconfig = write_kubeconfig(workdir.path(), &format!("http://127.0.0.1:{}", server.port));
    let cache_dir = workdir.path().join("cache");

    // --- the object, as JSON, straight off the wire ------------------------
    let got = run_kubectl(
        &kubeconfig,
        &cache_dir,
        &["get", "pod", "web-0", "-o", "json"],
    )
    .await;
    assert!(got.success, "kubectl get pod web-0 failed: {}", got.stderr);

    let object: Value = serde_json::from_str(&got.stdout).map_err(|e| {
        format!(
            "kubectl emitted output that is not JSON: {e}\n{}",
            got.stdout
        )
    })?;
    assert_eq!(
        object.get("kind").and_then(Value::as_str),
        Some("Pod"),
        "wrong kind in the object envelope"
    );
    assert_eq!(
        object.get("apiVersion").and_then(Value::as_str),
        Some("v1"),
        "wrong apiVersion in the object envelope"
    );
    assert_eq!(
        object.pointer("/metadata/name").and_then(Value::as_str),
        Some("web-0")
    );
    assert_eq!(
        object.pointer("/status/podIP").and_then(Value::as_str),
        Some("10.42.0.7"),
        "kubectl did not receive the status the model invented"
    );

    // --- a pod that does not exist -----------------------------------------
    let missing = run_kubectl(&kubeconfig, &cache_dir, &["get", "pod", "ghost"]).await;
    assert!(
        !missing.success,
        "kubectl should have failed for a nonexistent pod, but it succeeded:\n{}",
        missing.stdout
    );
    assert!(
        missing.stderr.contains("NotFound") || missing.stderr.contains("not found"),
        "kubectl did not decode the Status object as a NotFound error; stderr:\n{}",
        missing.stderr
    );
    assert!(
        missing.stderr.contains("ghost"),
        "the Status message did not reach the user: {}",
        missing.stderr
    );

    // --- a write, proving k8s_write_request is emitted and not just declared
    // `--wait=false` on purpose: kubectl's default post-delete wait polls
    // `?fieldSelector=metadata.name=web-0` until the object is gone, which would cost another
    // LLM round-trip per poll for no extra evidence about the write path.
    let deleted = run_kubectl(
        &kubeconfig,
        &cache_dir,
        &["delete", "pod", "web-0", "--wait=false"],
    )
    .await;
    assert!(
        deleted.success,
        "kubectl delete pod web-0 failed: {}",
        deleted.stderr
    );
    assert!(
        deleted.stdout.contains("web-0") && deleted.stdout.contains("deleted"),
        "kubectl did not accept the delete response: {}",
        deleted.stdout
    );

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("✓ kubectl decoded both the object and the Status error\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: wire-level discovery over TLS, plus watch and unknown resources
// ---------------------------------------------------------------------------

/// Wire-level assertions on the discovery documents, served over the TLS listener.
///
/// This covers what kubectl cannot conveniently prove: the exact JSON of each discovery
/// document, that `kubernetes_version` is actually read, that `?watch=true` is refused rather
/// than answered wrongly, and that TLS works at all.
///
/// LLM calls: 1 (startup). Every request here is served without touching the model.
#[tokio::test]
async fn test_discovery_over_tls_and_error_paths() -> E2EResult<()> {
    println!("\n=== E2E Test: discovery over TLS, watch, unknown resource ===");

    let prompt = "Open a Kubernetes API server with TLS on port {AVAILABLE_PORT}";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Kubernetes API server")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "kubernetes",
                "instruction": "TLS Kubernetes API server",
                "startup_params": {
                    "tls_enabled": true,
                    "kubernetes_version": "v1.31.2",
                    "common_name": "kubernetes",
                    "san_dns_names": ["kubernetes", "localhost"]
                }
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
    tokio::time::sleep(Duration::from_millis(500)).await;

    let base = format!("https://127.0.0.1:{}", server.port);
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()?;

    // --- GET /version, proving kubernetes_version is read ------------------
    let version: Value = client
        .get(format!("{base}/version"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        version.get("gitVersion").and_then(Value::as_str),
        Some("v1.31.2")
    );
    assert_eq!(version.get("major").and_then(Value::as_str), Some("1"));
    assert_eq!(
        version.get("minor").and_then(Value::as_str),
        Some("31"),
        "major/minor must be derived from kubernetes_version, never hardcoded"
    );

    // --- GET /api -----------------------------------------------------------
    let api: Value = client
        .get(format!("{base}/api"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(api.get("kind").and_then(Value::as_str), Some("APIVersions"));
    let versions = api
        .get("versions")
        .and_then(Value::as_array)
        .expect("no versions");
    assert!(versions.iter().any(|v| v == "v1"), "core v1 not advertised");
    assert!(
        api.pointer("/serverAddressByClientCIDRs/0/serverAddress")
            .and_then(Value::as_str)
            .map(|s| s.starts_with("https://"))
            .unwrap_or(false),
        "serverAddressByClientCIDRs must report the real https address"
    );

    // --- GET /apis ----------------------------------------------------------
    let apis: Value = client
        .get(format!("{base}/apis"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        apis.get("kind").and_then(Value::as_str),
        Some("APIGroupList")
    );
    let groups = apis
        .get("groups")
        .and_then(Value::as_array)
        .expect("no groups");
    let apps = groups
        .iter()
        .find(|g| g.get("name").and_then(Value::as_str) == Some("apps"))
        .expect("the apps group is not advertised");
    assert_eq!(
        apps.pointer("/preferredVersion/groupVersion")
            .and_then(Value::as_str),
        Some("apps/v1"),
        "every group needs a preferredVersion or kubectl's discovery cache rejects it"
    );

    // --- GET /api/v1 --------------------------------------------------------
    let core: Value = client
        .get(format!("{base}/api/v1"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        core.get("kind").and_then(Value::as_str),
        Some("APIResourceList")
    );
    assert_eq!(core.get("groupVersion").and_then(Value::as_str), Some("v1"));
    let pods = core
        .get("resources")
        .and_then(Value::as_array)
        .expect("no resources")
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("pods"))
        .expect("pods not advertised in core/v1");
    assert_eq!(pods.get("kind").and_then(Value::as_str), Some("Pod"));
    assert_eq!(pods.get("namespaced").and_then(Value::as_bool), Some(true));
    assert!(
        pods.get("shortNames")
            .and_then(Value::as_array)
            .map(|s| s.iter().any(|v| v == "po"))
            .unwrap_or(false),
        "the 'po' short name is what makes `kubectl get po` work"
    );

    // --- GET /apis/apps/v1 --------------------------------------------------
    let apps_v1: Value = client
        .get(format!("{base}/apis/apps/v1"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        apps_v1.get("groupVersion").and_then(Value::as_str),
        Some("apps/v1")
    );
    assert!(
        apps_v1
            .get("resources")
            .and_then(Value::as_array)
            .map(|r| r
                .iter()
                .any(|x| x.get("name").and_then(Value::as_str) == Some("deployments")))
            .unwrap_or(false),
        "deployments must be advertised at apps/v1"
    );

    // --- an unadvertised resource is a 404 Status, not an empty list --------
    let unknown = client
        .get(format!("{base}/api/v1/namespaces/default/frobnicators"))
        .send()
        .await?;
    assert_eq!(unknown.status().as_u16(), 404);
    let unknown_body: Value = unknown.json().await?;
    assert_eq!(
        unknown_body.get("kind").and_then(Value::as_str),
        Some("Status")
    );
    assert_eq!(
        unknown_body.get("apiVersion").and_then(Value::as_str),
        Some("v1")
    );
    assert_eq!(
        unknown_body.get("status").and_then(Value::as_str),
        Some("Failure")
    );
    assert_eq!(
        unknown_body.get("reason").and_then(Value::as_str),
        Some("NotFound")
    );
    assert_eq!(unknown_body.get("code").and_then(Value::as_u64), Some(404));

    // --- an unknown API group is also a Status ------------------------------
    let unknown_group = client
        .get(format!("{base}/apis/nope.example.com/v1"))
        .send()
        .await?;
    assert_eq!(unknown_group.status().as_u16(), 404);
    let unknown_group_body: Value = unknown_group.json().await?;
    assert_eq!(
        unknown_group_body.get("kind").and_then(Value::as_str),
        Some("Status")
    );

    // --- watch is refused explicitly, not answered with a one-shot list -----
    let watch = client
        .get(format!("{base}/api/v1/namespaces/default/pods?watch=true"))
        .send()
        .await?;
    assert_eq!(
        watch.status().as_u16(),
        501,
        "watch must be refused with a clear Status, not silently answered"
    );
    let watch_body: Value = watch.json().await?;
    assert_eq!(
        watch_body.get("kind").and_then(Value::as_str),
        Some("Status")
    );
    assert_eq!(
        watch_body.get("reason").and_then(Value::as_str),
        Some("NotImplemented")
    );

    // --- /healthz, which kubectl and probes both use ------------------------
    let healthz = client.get(format!("{base}/healthz")).send().await?;
    assert_eq!(healthz.status().as_u16(), 200);
    assert_eq!(healthz.text().await?.trim(), "ok");

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("✓ discovery, TLS, watch refusal and Status envelopes verified\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 4: custom resources and an explicit Table
// ---------------------------------------------------------------------------

/// A CRD advertised through the `resources` startup parameter, answered with an explicit
/// `k8s_table_response`. Proves the parameter is read and that a model can own the columns.
///
/// LLM calls: 2 (startup, the widgets list).
#[tokio::test]
async fn test_custom_resource_discovery_and_explicit_table() -> E2EResult<()> {
    println!("\n=== E2E Test: CRD discovery + explicit Table ===");

    let prompt = "Open a Kubernetes API server on port {AVAILABLE_PORT} advertising a Widget CRD";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Kubernetes API server")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "kubernetes",
                "instruction": "Kubernetes API server exposing widgets.example.com",
                "startup_params": {
                    "resources": [
                        {"group": "", "version": "v1", "name": "pods", "kind": "Pod",
                         "namespaced": true, "shortNames": ["po"]},
                        {"group": "example.com", "version": "v1", "name": "widgets",
                         "kind": "Widget", "namespaced": true, "shortNames": ["wd"]}
                    ]
                }
            }]))
            .expect_calls(1)
            .and()
            .on_event("k8s_list_request")
            .and_event_data_contains("resource", "widgets")
            .respond_with_actions(json!([{
                "type": "k8s_table_response",
                "columns": ["NAME", "COLOUR", "SPIN", "AGE"],
                "rows": [
                    {"name": "widget-a", "namespace": "default",
                     "cells": ["widget-a", "cerulean", "clockwise", "3d"]},
                    {"name": "widget-b", "namespace": "default",
                     "cells": ["widget-b", "vermilion", "counter", "9h"]}
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
    tokio::time::sleep(Duration::from_millis(500)).await;

    let base = format!("http://127.0.0.1:{}", server.port);
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .timeout(Duration::from_secs(15))
        .build()?;

    // The CRD's group must appear in /apis, or kubectl never asks for it.
    let apis: Value = client
        .get(format!("{base}/apis"))
        .send()
        .await?
        .json()
        .await?;
    assert!(
        apis.get("groups")
            .and_then(Value::as_array)
            .map(|g| g
                .iter()
                .any(|x| x.get("name").and_then(Value::as_str) == Some("example.com")))
            .unwrap_or(false),
        "the resources startup parameter did not reach API discovery: {apis}"
    );

    // Replacing the resource set is wholesale: apps/v1 is no longer advertised.
    let apps = client.get(format!("{base}/apis/apps/v1")).send().await?;
    assert_eq!(
        apps.status().as_u16(),
        404,
        "the built-in surface must be replaced, not merged, when 'resources' is supplied"
    );

    let widgets_discovery: Value = client
        .get(format!("{base}/apis/example.com/v1"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        widgets_discovery
            .get("groupVersion")
            .and_then(Value::as_str),
        Some("example.com/v1")
    );

    // Ask exactly the way kubectl does, and check the Table we get back.
    let table: Value = client
        .get(format!(
            "{base}/apis/example.com/v1/namespaces/default/widgets"
        ))
        .header(
            "Accept",
            "application/json;as=Table;v=1;g=meta.k8s.io,application/json",
        )
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(table.get("kind").and_then(Value::as_str), Some("Table"));
    assert_eq!(
        table.get("apiVersion").and_then(Value::as_str),
        Some("meta.k8s.io/v1")
    );
    let columns: Vec<&str> = table
        .get("columnDefinitions")
        .and_then(Value::as_array)
        .expect("no columnDefinitions")
        .iter()
        .filter_map(|c| c.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(columns, vec!["NAME", "COLOUR", "SPIN", "AGE"]);
    let rows = table
        .get("rows")
        .and_then(Value::as_array)
        .expect("no rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].pointer("/cells/1").and_then(Value::as_str),
        Some("cerulean")
    );
    assert_eq!(
        rows[0].pointer("/object/kind").and_then(Value::as_str),
        Some("PartialObjectMetadata"),
        "every Table row needs a PartialObjectMetadata object or kubectl cannot address it"
    );
    assert_eq!(
        rows[1]
            .pointer("/object/metadata/name")
            .and_then(Value::as_str),
        Some("widget-b")
    );

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    println!("✓ CRD discovery and explicit Table verified\n");
    Ok(())
}
